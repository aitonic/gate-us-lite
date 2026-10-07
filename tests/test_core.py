import base64
import json
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest.mock import patch

from gate_us_lite.config import DEFAULTS
from gate_us_lite.http import FetchError, HTTPResponse
from gate_us_lite.models import Candidate, OpenVPNProfile
from gate_us_lite.ovpn import parse_ovpn
from gate_us_lite.probe import tcp_probe
from gate_us_lite.select import merge_candidates, evaluate, choose
from gate_us_lite.store import Store
from gate_us_lite import sources
from gate_us_lite.mihomo import render

CA='''-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----'''
CONF=f'''client\ndev tun\nproto udp\nremote 1.2.3.4 1194\nauth-user-pass\ncipher AES-256-GCM\nauth SHA256\n<ca>\n{CA}\n</ca>\n'''
TCP_CONF=CONF.replace('proto udp','proto tcp').replace('1194','443')


class TestPackageMetadata(unittest.TestCase):
    def test_version_matches_pyproject(self):
        from gate_us_lite import __version__
        data = tomllib.loads(Path("pyproject.toml").read_text())
        self.assertEqual(__version__, data["project"]["version"])


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

    def test_publicvpnlist_key_is_only_sent_to_its_own_domain(self):
        own=['https://publicvpnlist.com/dl/1','https://dl.publicvpnlist.com/dl/2']
        foreign=['https://notpublicvpnlist.com/dl/3','https://publicvpnlist.com.evil.example/dl/4','https://cdn.example/dl/5']
        rows=[
            {'id':i,'ip':f'1.2.3.{i}','country_code':'US','source':'VPNGate','config_download_url':url}
            for i,url in enumerate(own+foreign,1)
        ]
        sent={}
        def fake(url,headers=None,**kwargs):
            if 'api/v1/servers?' in url:
                return HTTPResponse(json.dumps({'data':rows}).encode(),200,{},url)
            sent[url]=headers
            return HTTPResponse(CONF.encode(),200,{},url)
        with patch.object(sources,'fetch',side_effect=fake):
            sources.publicvpnlist('secret','US')
        for url in own:
            self.assertEqual(sent[url],{'Authorization':'Bearer secret','Accept':'application/json'})
        for url in foreign:
            self.assertIsNone(sent[url])

    def pvl_fetch(self,rows,download=None):
        def fake(url,**kwargs):
            if 'api/v1/servers?' in url:
                return HTTPResponse(json.dumps({'data':rows}).encode(),200,{},url)
            return download(url) if download else HTTPResponse(CONF.encode(),200,{},url)
        return patch.object(sources,'fetch',side_effect=fake)

    def test_publicvpnlist_empty_catalog_is_an_empty_result_not_an_error(self):
        with self.pvl_fetch([]):
            self.assertEqual(sources.publicvpnlist('k','US'),[])

    def test_publicvpnlist_records_without_download_links_are_reported(self):
        rows=[{'id':i,'ip':f'1.2.3.{i}','country_code':'US','config_download_url':None} for i in (1,2,3)]
        with self.pvl_fetch(rows),self.assertRaisesRegex(RuntimeError,r'^3 records, 0 with a download link, 0 usable profiles$'):
            sources.publicvpnlist('k','US')

    def test_publicvpnlist_unusable_profiles_are_reported_with_their_reasons(self):
        rows=[
            {'id':i,'ip':f'1.2.3.{i}','country_code':'US','config_download_url':f'https://publicvpnlist.com/dl/{i}'}
            for i in (1,2,3)
        ]
        def download(url):
            if url.endswith('3'):
                return HTTPResponse(b'<html>login required</html>',200,{},url)
            raise FetchError(url,'HTTPError 410')
        with self.pvl_fetch(rows,download),self.assertRaises(RuntimeError) as failed:
            sources.publicvpnlist('k','US')
        self.assertEqual(
            str(failed.exception),
            '3 records, 3 with a download link, 0 usable profiles (2x HTTPError 410; 1x missing embedded CA certificate)',
        )

    def test_scraper_fetch_failure_is_an_error_not_an_empty_result(self):
        with patch.object(sources,'fetch',side_effect=FetchError(sources.SCRAPER_README,'HTTPError 404')):
            with self.assertRaisesRegex(RuntimeError,'HTTPError 404'):
                sources.vpngate_scraper('US')

    def test_publicvpnlist_source_name_spelling(self):
        for name,family in (('VPN Gate','vpngate'),('IPSpeed','ipspeed'),('AutoOVPN','autoovpn')):
            self.assertEqual(sources._pvl_source_family({'source_name':name})[1],family)

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


FILTERS=DEFAULTS['filters']
SELECTION_CFG={'general':{'preferred_limit':3,'fallback_limit':8},'filters':FILTERS}


class TestSelection(unittest.TestCase):
    def mk(self,ip,asn,score=10,hosting=False,source='vpngate',proto='udp'):
        p=OpenVPNProfile(ip,443 if proto=='tcp' else 1194,proto,CA,username='vpn',password='vpn')
        c=Candidate(source,source,ip,'US','',ip,ip,p,provenance=[source])
        c.history={'seen_24h':3,'availability_24h':1.0,'availability_7d':1.0,'tcp_fail_streak':0}
        c.intel={'ipwho_status':'ok','proxycheck_status':'ok','hosting_known':True,'country_code':'US','asn_key':asn,'fixed_isp_heuristic':not hosting,'hosting':hosting}
        evaluate(c,FILTERS)
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
        independent.evidence_families=['vpngate','autoovpn']
        for c in (base,mirror,independent):
            evaluate(c,filters)
        self.assertEqual(base.selection_score,mirror.selection_score)
        self.assertGreater(independent.selection_score,base.selection_score)

    def test_unknown_intel_is_never_published(self):
        c=self.mk('1.1.1.1','AS1',100)
        c.intel={'asn_key':'AS1','ipwho_status':'error','hosting_known':False}
        evaluate(c,FILTERS)
        self.assertEqual(choose([c],SELECTION_CFG,{}),([],[]))

    def test_asn_diversity_and_sticky(self):
        a=self.mk('1.1.1.1','AS1',100); b=self.mk('2.2.2.2','AS1',90); c=self.mk('3.3.3.3','AS2',80); d=self.mk('4.4.4.4','AS3',70)
        pref,_=choose([a,b,c,d],SELECTION_CFG,{'preferred':[c.dedupe_key]})
        self.assertEqual(pref[0].dedupe_key,c.dedupe_key)
        self.assertEqual(len({x.intel['asn_key'] for x in pref}),3)

    def test_rejected_node_is_never_published(self):
        good=self.mk('1.1.1.1','AS1',50); tor=self.mk('2.2.2.2','AS2',100)
        tor.intel['tor']=True
        evaluate(tor,FILTERS); tor.selection_score=100
        self.assertEqual(tor.reject_reasons,['tor'])
        self.assertEqual(choose([good,tor],SELECTION_CFG,{}),([good],[]))

    def test_two_tcp_failures_remove_only_preferred(self):
        tcp=self.mk('1.1.1.1','AS1',100,proto='tcp')
        tcp.history['tcp_fail_streak']=2
        self.assertEqual(choose([tcp],SELECTION_CFG,{}),([],[tcp]))

    def test_slow_clean_node_stays_in_fallback(self):
        slow=self.mk('1.1.1.1','AS1',100)
        slow.ping_ms=900
        self.assertEqual(choose([slow],SELECTION_CFG,{}),([],[slow]))


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
            self.assertEqual(st.cached_candidates('vpngate',max_age=86400)[0].dedupe_key,c.dedupe_key)
            st.close()
            y=render([c],[])
            self.assertIn('US-PREFERRED',y)
            self.assertIn('US-STABLE',y)
            self.assertIn('type: openvpn',y)
            self.assertIn('type: fallback',y)
            self.assertEqual(y.count('expected-status: 204'),2)
            self.assertNotIn('Generated by gate-us-lite at',y)
            self.assertNotIn('score=',y)

    def test_yaml_does_not_depend_on_volatile_scores(self):
        a=self.mk(); b=self.mk()
        a.selection_score=10; b.selection_score=99
        self.assertEqual(render([a],[]),render([b],[]))

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
                self.assertEqual(len(st.cached_candidates('vpngate',max_age=86400)),1)
            st.db.execute("UPDATE source_cache SET schema_version=1 WHERE source='vpngate'")
            st.db.commit()
            with patch('gate_us_lite.store.time.time', return_value=2000):
                self.assertEqual(st.cached_candidates('vpngate',max_age=86400),[])
            st.close()

    def test_cached_candidates_expire_after_the_given_max_age(self):
        with tempfile.TemporaryDirectory() as td:
            st=Store(Path(td)/'s.db')
            with patch('gate_us_lite.store.time.time', return_value=1000):
                st.cache_candidates('vpngate',[self.mk()])
            with patch('gate_us_lite.store.time.time', return_value=1000+2*86400):
                self.assertEqual(st.cached_candidates('vpngate',max_age=86400),[])
                self.assertEqual(len(st.cached_candidates('vpngate',max_age=4*86400)),1)
            st.close()


if __name__=='__main__':
    unittest.main()
