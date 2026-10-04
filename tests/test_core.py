import base64
import json
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest.mock import patch

from gate_us_lite.http import HTTPResponse
from gate_us_lite.models import Candidate, OpenVPNProfile
from gate_us_lite.ovpn import parse_ovpn
from gate_us_lite.probe import tcp_probe
from gate_us_lite.select import merge_candidates, evaluate, choose
from gate_us_lite.store import Store
from gate_us_lite import sources, intel as intel_mod
from gate_us_lite.mihomo import render
from gate_us_lite import cli

CA='''-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----'''
CONF=f'''client\ndev tun\nproto udp\nremote 1.2.3.4 1194\nauth-user-pass\ncipher AES-256-GCM\nauth SHA256\n<ca>\n{CA}\n</ca>\n'''
TCP_CONF=CONF.replace('proto udp','proto tcp').replace('1194','443')


class TestPackageMetadata(unittest.TestCase):
    def test_version_matches_pyproject(self):
        from gate_us_lite import __version__
        data = tomllib.loads(Path("pyproject.toml").read_text())
        self.assertEqual(__version__, data["project"]["version"])


class TestWorkflowContract(unittest.TestCase):
    def test_github_actions_contract(self):
        text = Path(".github/workflows/generate-mihomo.yml").read_text(encoding="utf-8")
        for required in (
            "permissions:\n  contents: write",
            "uses: actions/checkout@v7",
            "uses: actions/setup-python@v7",
            "uses: actions/cache@v6",
            "timeout-minutes: 12",
            "PUBLICVPNLIST_API_KEY",
            "ABUSEIPDB_API_KEY",
            "PROXYCHECK_API_KEY",
            "mihomo-linux-amd64-v1-${MIHOMO_VERSION}.gz",
            "d4304c546c3cddcb6fafd4b4fddb0ba1a95ffa36606fda56d75db2e59ad24114",
            "mihomo -t -f mihomo.yaml",
        ):
            self.assertIn(required, text)

    def test_ci_intel_budget_defaults(self):
        from gate_us_lite.config import DEFAULTS
        general = DEFAULTS["general"]
        self.assertLessEqual(general["intel_request_timeout_seconds"], 6)
        self.assertEqual(general["intel_request_retries"], 0)
        self.assertGreaterEqual(general["intel_workers"], 6)


class TestOVPN(unittest.TestCase):
    def test_safe_profile(self):
        p=parse_ovpn(CONF,username='vpn',password='vpn')
        self.assertEqual((p.server,p.port,p.proto),('1.2.3.4',1194,'udp'))
        self.assertEqual(p.username,'vpn')
        self.assertIn('BEGIN CERTIFICATE',p.ca)

    def test_reject_script_hook(self):
        with self.assertRaisesRegex(ValueError,'unsafe'):
            parse_ovpn(CONF+'\nscript-security 2\nup /tmp/a.sh\n')

    def test_proto_line_is_not_consumed_as_remote_proto(self):
        p=parse_ovpn(TCP_CONF,username='vpn',password='vpn')
        self.assertEqual(p.proto,'tcp')
        self.assertEqual(p.port,443)

    def test_crlf_remote_line(self):
        p=parse_ovpn(TCP_CONF.replace('\n','\r\n'),username='vpn',password='vpn')
        self.assertEqual((p.proto,p.port),('tcp',443))

    def test_tls_auth_is_preserved_for_mihomo(self):
        p=parse_ovpn(CONF+'\n<tls-auth>\nSTATICKEY\n</tls-auth>\nkey-direction 1\n',username='vpn',password='vpn')
        self.assertEqual(p.tls_auth,'STATICKEY')
        self.assertEqual(p.key_direction,'1')

    def test_keepalive_maps_to_ping_fields(self):
        p=parse_ovpn(CONF+'\nkeepalive 10 60\n',username='vpn',password='vpn')
        self.assertEqual((p.ping,p.ping_restart),(10,60))
        c=Candidate('vpngate','vpngate','x','US','', '1.2.3.4','1.2.3.4',p)
        y=render([c],[])
        self.assertIn('    ping: 10',y)
        self.assertIn('    ping-restart: 60',y)


class TestSources(unittest.TestCase):
    def test_vpngate_us_filter_and_uptime_ms(self):
        b64=base64.b64encode(CONF.encode()).decode()
        text='#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64\n'
        text+=f'vpn1,1.2.3.4,10,12,80000000,United States,US,7,3600000,1,1,2weeks,x,,{b64}\n'
        text+=f'vpn2,5.6.7.8,10,12,80000000,Japan,JP,7,3600000,1,1,2weeks,x,,{b64}\n'
        fake=HTTPResponse(text.encode(),200,{},sources.VPNGATE_URL)
        with patch.object(sources,'fetch',return_value=fake):
            out=sources.vpngate('US')
        self.assertEqual(len(out),1)
        self.assertEqual(out[0].uptime_seconds,3600)
        self.assertEqual(out[0].speed_mbps,80)

    def test_vpngate_base64_trailing_column_fallback(self):
        b64=base64.b64encode(CONF.encode()).decode()
        text='#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,LegacyConfig\n'
        text+=f'vpn1,1.2.3.4,10,12,80000000,United States,US,7,3600000,{b64}\n'
        with patch.object(sources,'fetch',return_value=HTTPResponse(text.encode(),200,{},sources.VPNGATE_URL)):
            out=sources.vpngate('US')
        self.assertEqual(len(out),1)
        self.assertEqual(out[0].profile.server,'1.2.3.4')

    def test_ipspeed_html_row(self):
        page='<table><tr><td>1</td><td>USA</td><td><a href="/download/8.8.8.8.ovpn">8.8.8.8.ovpn</a></td><td>2 day(s)</td><td>14 ms</td></tr></table>'
        def fake(url,**kwargs):
            body = page if url==sources.IPSPEED_URL else CONF.replace('1.2.3.4','8.8.8.8')
            return HTTPResponse(body.encode(),200,{},url)
        with patch.object(sources,'fetch',side_effect=fake):
            out=sources.ipspeed('US')
        self.assertEqual(len(out),1)
        self.assertEqual(out[0].uptime_seconds,172800)
        self.assertEqual(out[0].ping_ms,14)

    def test_vpnbook_dynamic_credentials_and_tcp443(self):
        page='Username <b>vpnbook</b> Password <span>abcd1234</span> us16.vpnbook.com'
        def fake(url,**kwargs):
            if url==sources.VPNBOOK_URL:
                return HTTPResponse(page.encode(),200,{},url)
            return HTTPResponse(CONF.encode(),200,{},url)
        with patch.object(sources,'fetch',side_effect=fake), patch.object(sources,'_ip',return_value='9.9.9.9'):
            out=sources.vpnbook('US')
        self.assertEqual(len(out),1)
        self.assertEqual(out[0].profile.port,443)
        self.assertEqual(out[0].profile.proto,'tcp')
        self.assertEqual(out[0].profile.password,'abcd1234')

    def test_scraper_readme_config_correlation(self):
        readme='| vpnx | 8.8.4.4 | 11 | 33.2 Mbps | United States | [Download](./configs/server_1_US.ovpn) |'
        def fake(url,**kwargs):
            if url==sources.SCRAPER_README:
                return HTTPResponse(readme.encode(),200,{},url)
            return HTTPResponse(CONF.replace('1.2.3.4','8.8.4.4').encode(),200,{},url)
        with patch.object(sources,'fetch',side_effect=fake):
            out=sources.vpngate_scraper('US')
        self.assertEqual(len(out),1)
        self.assertEqual(out[0].source_family,'vpngate')
        self.assertEqual(out[0].speed_mbps,33.2)

    def test_publicvpnlist_source_family(self):
        payload={'data':[{'id':9,'ip':'1.2.3.4','exit_ip':'1.2.3.4','country_code':'US','config_download_url':'https://x/config','source':'VPNGate','latency_ms':22,'speed_mbps':4.2,'uptime_percent_7d':95,'handshake_ms':44,'https_first_byte_ms':88}]}
        def fake(url,**kwargs):
            body=json.dumps(payload).encode() if 'api/v1/servers?' in url else CONF.encode()
            return HTTPResponse(body,200,{},url)
        with patch.object(sources,'fetch',side_effect=fake):
            out=sources.publicvpnlist('k','US')
        self.assertEqual(len(out),1)
        self.assertEqual(out[0].source_family,'vpngate')
        self.assertEqual(out[0].source_uptime_7d,95)
        self.assertEqual(out[0].handshake_ms,44)
        self.assertEqual(out[0].https_first_byte_ms,88)

    def test_publicvpnlist_lazy_materialization(self):
        rows=[]
        for i in range(1,7):
            rows.append({
                'id':i,'ip':f'1.2.3.{i}','exit_ip':f'1.2.3.{i}','config_download_url':f'https://x/{i}.ovpn',
                'source':'VPNGate','technical_quality_score':100-i,'uptime_percent_7d':99-i,
                'speed_mbps':100-i,'latency_ms':i,
            })
        payload={'data':rows}
        downloads=[]
        api_urls=[]
        def fake(url,**kwargs):
            if 'api/v1/servers?' in url:
                api_urls.append(url)
                return HTTPResponse(json.dumps(payload).encode(),200,{},url)
            downloads.append(url)
            return HTTPResponse(CONF.encode(),200,{},url)
        with patch.object(sources,'fetch',side_effect=fake):
            out=sources.publicvpnlist('k','US',materialize_limit=2)
        self.assertEqual(len(out),2)
        self.assertEqual(len(downloads),2)
        self.assertIn('fresh_within=86400',api_urls[0])


class TestProbe(unittest.TestCase):
    class Conn:
        def __enter__(self): return self
        def __exit__(self,*args): return False

    def test_tcp_probe(self):
        p=parse_ovpn(TCP_CONF,username='vpn',password='vpn')
        c=Candidate('x','x','x','US','', '1.2.3.4','1.2.3.4',p)
        with patch('gate_us_lite.probe.socket.create_connection',return_value=self.Conn()):
            ok,lat=tcp_probe(c,timeout=0.1)
        self.assertTrue(ok)
        self.assertIsNotNone(lat)


class TestSelection(unittest.TestCase):
    def mk(self,ip,asn,score=10,hosting=False,source='vpngate',proto='udp'):
        p=OpenVPNProfile(ip,443 if proto=='tcp' else 1194,proto,CA,username='vpn',password='vpn')
        c=Candidate(source,source,ip,'US','',ip,ip,p,provenance=[source])
        c.history={'seen_24h':3,'availability_24h':1.0,'availability_7d':1.0,'tcp_fail_streak':0}
        c.intel={'country_code':'US','asn_key':asn,'fixed_isp_heuristic':not hosting,'hosting':hosting}
        c.selection_score=score
        return c

    def test_merge_provenance_does_not_fake_independent_family(self):
        a=self.mk('1.1.1.1','AS1',source='vpngate')
        b=self.mk('1.1.1.1','AS1',source='publicvpnlist')
        b.source_family='vpngate'
        b.evidence_families=['vpngate']
        got=merge_candidates([a,b])
        self.assertEqual(len(got),1)
        self.assertGreaterEqual(len(got[0].provenance),2)
        self.assertEqual(got[0].evidence_families,['vpngate'])

    def test_merge_is_deterministic_across_completion_order(self):
        a=self.mk('1.1.1.1','AS1',source='vpngate')
        b=self.mk('1.1.1.1','AS1',source='publicvpnlist')
        b.source_family='vpngate'; b.evidence_families=['vpngate']; b.technical_score=95
        one=merge_candidates([a,b])[0]
        two=merge_candidates([b,a])[0]
        self.assertEqual(one.source,two.source)
        self.assertEqual(one.profile.server,two.profile.server)
        self.assertEqual(one.provenance,two.provenance)
        self.assertEqual(one.evidence_families,two.evidence_families)

    def test_multi_source_bonus_counts_families_not_mirrors(self):
        filters={'reject_country_mismatch':True,'reject_tor':True,'reject_residential_proxy':True}
        base=self.mk('1.1.1.1','AS1')
        base.evidence_families=['vpngate']
        mirror=self.mk('2.2.2.2','AS2')
        mirror.provenance=['vpngate','vpngate_scraper','publicvpnlist:vpngate']
        mirror.evidence_families=['vpngate']
        independent=self.mk('3.3.3.3','AS3')
        independent.evidence_families=['vpngate','vpnbook']
        for c in (base,mirror,independent):
            evaluate(c,filters)
        self.assertEqual(base.selection_score,mirror.selection_score)
        self.assertGreater(independent.selection_score,base.selection_score)

    def test_unknown_ip_intel_cannot_enter_preferred(self):
        c=self.mk('1.1.1.1','AS1',100)
        c.intel={'asn_key':'AS1','ipwho_status':'error','hosting_known':False}
        cfg={'general':{'preferred_limit':3,'fallback_limit':8},'filters':{'require_ipwho_for_preferred':True,'reject_hosting':True,'max_ping_ms':250,'min_speed_mbps':0,'min_preferred_availability_24h':0.25,'max_preferred_tcp_fail_streak':2}}
        pref,fb=choose([c],cfg,{})
        self.assertEqual(pref,[])
        self.assertEqual(fb,[c])

    def test_asn_diversity_and_sticky(self):
        cfg={'general':{'preferred_limit':3,'fallback_limit':8},'filters':{'reject_hosting':True,'max_ping_ms':250,'min_speed_mbps':0,'min_preferred_availability_24h':0.25,'max_preferred_tcp_fail_streak':2}}
        a=self.mk('1.1.1.1','AS1',100); b=self.mk('2.2.2.2','AS1',90); c=self.mk('3.3.3.3','AS2',80); d=self.mk('4.4.4.4','AS3',70)
        pref,_=choose([a,b,c,d],cfg,{'preferred':[c.dedupe_key]})
        self.assertEqual(pref[0].dedupe_key,c.dedupe_key)
        self.assertEqual(len({x.intel['asn_key'] for x in pref}),3)

    def test_hosting_only_fallback(self):
        cfg={'general':{'preferred_limit':3,'fallback_limit':8},'filters':{'reject_hosting':True,'max_ping_ms':250,'min_speed_mbps':0,'min_preferred_availability_24h':0.25,'max_preferred_tcp_fail_streak':2}}
        good=self.mk('1.1.1.1','AS1',50); host=self.mk('2.2.2.2','AS2',100,hosting=True)
        pref,fb=choose([good,host],cfg,{})
        self.assertEqual(pref,[good]); self.assertIn(host,fb)

    def test_two_tcp_failures_remove_only_preferred(self):
        cfg={'general':{'preferred_limit':3,'fallback_limit':8},'filters':{'reject_hosting':True,'max_ping_ms':250,'min_speed_mbps':0,'min_preferred_availability_24h':0.25,'max_preferred_tcp_fail_streak':2}}
        tcp=self.mk('1.1.1.1','AS1',100,proto='tcp')
        tcp.history['tcp_fail_streak']=2
        pref,fb=choose([tcp],cfg,{})
        self.assertEqual(pref,[])
        self.assertEqual(fb,[tcp])


class TestIntel(unittest.TestCase):
    def test_enrich_passes_bounded_retry_budget(self):
        with patch.object(intel_mod, "_ipwho", return_value={"country_code":"US","hosting":False}) as ipwho, \
             patch.object(intel_mod, "_proxycheck", return_value={}) as proxycheck, \
             patch.object(intel_mod, "_abuse", return_value={}) as abuse:
            intel_mod.enrich(
                "1.1.1.1", timeout=6, retries=0,
                proxycheck_key="proxy-key", abuseipdb_key="abuse-key"
            )
        ipwho.assert_called_once_with("1.1.1.1", 6, 0)
        proxycheck.assert_called_once_with("1.1.1.1", "proxy-key", 6, 0)
        abuse.assert_called_once_with("1.1.1.1", "abuse-key", 6, 0)

    def test_hosting_keyword_does_not_match_colorado(self):
        self.assertFalse(intel_mod._contains_keyword('Colorado Broadband LLC', intel_mod.HOSTING_WORDS))
        self.assertTrue(intel_mod._contains_keyword('Example Colo Hosting LLC', intel_mod.HOSTING_WORDS))

    def test_failed_ipwho_cache_expires_quickly(self):
        with tempfile.TemporaryDirectory() as td:
            st=Store(Path(td)/'s.db')
            payload={'intel_schema':2,'invalid_ip':False,'ipwho_status':'error','hosting_known':False}
            with patch('gate_us_lite.store.time.time', return_value=1000):
                st.put_intel('1.2.3.4',payload)
            with patch('gate_us_lite.store.time.time', return_value=1500):
                self.assertIsNotNone(st.get_intel('1.2.3.4',ttl=86400,error_ttl=900))
            with patch('gate_us_lite.store.time.time', return_value=2000):
                self.assertIsNone(st.get_intel('1.2.3.4',ttl=86400,error_ttl=900))
            st.close()


class TestStoreAndOutput(unittest.TestCase):
    def mk(self,ip='1.2.3.4'):
        p=OpenVPNProfile(ip,1194,'udp',CA,username='vpn',password='vpn')
        return Candidate('vpngate','vpngate','x','US','',ip,ip,p,provenance=['vpngate'])

    def test_history_and_cache_and_yaml(self):
        with tempfile.TemporaryDirectory() as td:
            st=Store(Path(td)/'s.db')
            c=self.mk()
            st.observe([c])
            h=st.history(c.dedupe_key)
            self.assertGreater(h['availability_24h'],0.9)
            st.cache_candidates('vpngate',[c])
            self.assertEqual(st.cached_candidates('vpngate')[0].dedupe_key,c.dedupe_key)
            st.close()
            y=render([c],[])
            self.assertIn('US-PREFERRED',y)
            self.assertIn('US-STABLE',y)
            self.assertIn('type: openvpn',y)
            self.assertIn('type: fallback',y)
            self.assertEqual(y.count('expected-status: 204'),2)
            self.assertNotIn('Generated by gate-us-lite at',y)

    def test_history_uses_only_valid_source_opportunities(self):
        with tempfile.TemporaryDirectory() as td:
            st=Store(Path(td)/'s.db')
            c=self.mk()
            with patch('gate_us_lite.store.time.time', return_value=1000):
                st.observe([c],{'vpngate':'ok'})
            with patch('gate_us_lite.store.time.time', return_value=2000):
                st.observe([],{'vpngate':'error'})
                h=st.history(c.dedupe_key)
            self.assertEqual(h['seen_24h'],1)
            self.assertEqual(h['opportunities_24h'],1)
            self.assertEqual(h['availability_24h'],1.0)
            with patch('gate_us_lite.store.time.time', return_value=3000):
                st.observe([],{'vpngate':'ok'})
                h=st.history(c.dedupe_key)
            st.close()
            self.assertEqual(h['opportunities_24h'],2)
            self.assertEqual(h['availability_24h'],0.5)

    def test_source_baseline_and_cache_schema(self):
        with tempfile.TemporaryDirectory() as td:
            st=Store(Path(td)/'s.db')
            c=self.mk()
            for i,count in enumerate([10,11,9,10],start=1):
                with patch('gate_us_lite.store.time.time', return_value=1000+i):
                    st.record_source_snapshot('vpngate',count,'ok')
            self.assertEqual(st.source_baseline('vpngate',12),10.0)
            with patch('gate_us_lite.store.time.time', return_value=2000):
                st.cache_candidates('vpngate',[c])
                self.assertEqual(len(st.cached_candidates('vpngate')),1)
            st.db.execute("UPDATE source_cache SET schema_version=1 WHERE source='vpngate'")
            st.db.commit()
            with patch('gate_us_lite.store.time.time', return_value=2000):
                self.assertEqual(st.cached_candidates('vpngate'),[])
            st.close()

    def test_low_watermark_detection(self):
        with tempfile.TemporaryDirectory() as td:
            st=Store(Path(td)/'s.db')
            for i in range(4):
                with patch('gate_us_lite.store.time.time', return_value=1000+i):
                    st.record_source_snapshot('vpngate',10,'ok')
            cfg={'general':{'source_baseline_window':12,'source_low_watermark_ratio':0.4,'source_low_watermark_min_baseline':4}}
            degraded,baseline=cli._is_degraded(st,'vpngate',2,cfg)
            self.assertTrue(degraded)
            self.assertEqual(baseline,10.0)
            st.close()

    def test_cached_fallback_does_not_fake_availability(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            cfg=root/'config.toml'
            cfg.write_text('[sources]\nvpngate=true\nipspeed=false\nvpnbook=false\npublicvpnlist=false\nvpngate_scraper=false\n',encoding='utf-8')
            c=self.mk()
            intel={'country_code':'US','asn_key':'AS1','fixed_isp_heuristic':True,'hosting':False,'intel_schema':2,'ipwho_status':'ok'}
            with patch.object(cli,'_fetch_one',return_value=[c]), patch.object(cli,'enrich',return_value=intel), patch('gate_us_lite.store.time.time',return_value=1000):
                self.assertEqual(cli.generate(str(cfg),str(root/'.state/state.sqlite3'),str(root/'mihomo.yaml')),0)
            with patch.object(cli,'_fetch_one',return_value=[]), patch('gate_us_lite.store.time.time',return_value=2000):
                self.assertEqual(cli.generate(str(cfg),str(root/'.state/state.sqlite3'),str(root/'mihomo.yaml')),0)
                st=Store(root/'.state/state.sqlite3')
                h=st.history(c.dedupe_key)
                st.close()
            self.assertEqual(h['seen_24h'],1)
            self.assertEqual(h['availability_24h'],1.0)
            self.assertEqual(h['opportunities_24h'],1)

    def test_generate_writes_only_yaml_output(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            cfg=root/'config.toml'
            cfg.write_text('[sources]\nvpngate=true\nipspeed=false\nvpnbook=false\npublicvpnlist=false\nvpngate_scraper=false\n',encoding='utf-8')
            c=self.mk()
            c.ping_ms=20; c.speed_mbps=50
            with patch.object(cli,'_fetch_one',return_value=[c]), patch.object(cli,'enrich',return_value={'country_code':'US','asn_key':'AS1','fixed_isp_heuristic':True,'hosting':False}):
                rc=cli.generate(str(cfg),str(root/'.state/state.sqlite3'),str(root/'mihomo.yaml'))
            self.assertEqual(rc,0)
            self.assertTrue((root/'mihomo.yaml').is_file())
            self.assertFalse((root/'report.json').exists())
            self.assertFalse((root/'summary.json').exists())


if __name__=='__main__':
    unittest.main()
