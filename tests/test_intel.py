import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from gate_us_lite import intel as intel_mod
from gate_us_lite.config import DEFAULTS
from gate_us_lite.http import HTTPResponse
from gate_us_lite.models import Candidate, OpenVPNProfile
from gate_us_lite.select import evaluate
from gate_us_lite.store import Store

POLICY = DEFAULTS["filters"]
STRICT = {**POLICY, "reject_hosting": True, "reject_proxy": True, "max_proxycheck_risk": 25}
CLEAN = {"ipwho_status": "ok", "proxycheck_status": "ok", "country_code": "US", "hosting_known": True}


def response(payload: dict) -> HTTPResponse:
    return HTTPResponse(json.dumps(payload).encode(), 200, {}, "https://intel.test")


def proxycheck_payload(ip: str, *, detections=None, operator=None, network_type="Business") -> dict:
    base = {"tor": False, "compromised": False, "hosting": False, "anonymous": False, "risk": 0}
    return {"status": "ok", ip: {
        "network": {"type": network_type},
        "detections": {**base, **(detections or {})},
        "operator": operator,
    }}


# Reply captured from https://proxycheck.io/v3/147.135.15.16 on 2026-10-07 (a VPNBook server).
PROXYCHECK_V3_SAMPLE = {
    "status": "ok",
    "147.135.15.16": {
        "network": {
            "asn": "AS16276", "range": "147.135.15.0/24", "hostname": "us16.vpnbook.com",
            "provider": "OVH SAS", "organisation": "OVH US LLC", "type": "Hosting",
        },
        "location": {"country_code": "US", "region_name": "Kansas", "city_name": "Eastborough", "postal_code": None},
        "device_estimate": {"address": 1, "subnet": 28},
        "detections": {
            "proxy": False, "vpn": False, "compromised": False, "scraper": False, "tor": False,
            "hosting": True, "anonymous": False, "risk": 33, "confidence": 100,
            "first_seen": None, "last_seen": None, "times_seen": None,
        },
        "detection_history": None,
        "attack_history": None,
        "operator": None,
        "last_updated": "2026-10-06T21:04:43Z",
    },
    "query_time": 34,
}


def candidate(intel: dict) -> Candidate:
    profile = OpenVPNProfile("1.1.1.1", 1194, "udp", "CA", username="vpn", password="vpn")
    c = Candidate("vpngate", "vpngate", "x", "US", "", "1.1.1.1", "1.1.1.1", profile)
    c.intel = intel
    return c


class TestIntel(unittest.TestCase):
    def test_enrich_passes_bounded_retry_budget(self):
        with patch.object(intel_mod, "_ipwho", return_value={"country_code": "US"}) as ipwho, \
             patch.object(intel_mod, "_proxycheck", return_value={}) as proxycheck, \
             patch.object(intel_mod, "_abuse", return_value={}) as abuse:
            intel_mod.enrich(
                "1.1.1.1", timeout=6, retries=0,
                proxycheck_key="proxy-key", abuseipdb_key="abuse-key", proxycheck_lookback_days=30,
            )
        ipwho.assert_called_once_with("1.1.1.1", 6, 0)
        proxycheck.assert_called_once_with("1.1.1.1", "proxy-key", 6, 0, 30)
        abuse.assert_called_once_with("1.1.1.1", "abuse-key", 6, 0)

    def test_hosting_keyword_does_not_match_colorado(self):
        self.assertFalse(intel_mod._contains_keyword("Colorado Broadband LLC", intel_mod.HOSTING_WORDS))
        self.assertTrue(intel_mod._contains_keyword("Example Colo Hosting LLC", intel_mod.HOSTING_WORDS))

    def test_only_known_intel_is_cached_for_the_long_ttl(self):
        schema = {"intel_schema": intel_mod.INTEL_SCHEMA, "invalid_ip": False}
        cases = {
            "1.1.1.1": ({"ipwho_status": "error", "proxycheck_status": "ok"}, False),
            "2.2.2.2": ({"ipwho_status": "ok", "proxycheck_status": "error"}, False),
            "3.3.3.3": ({"ipwho_status": "ok", "proxycheck_status": "disabled"}, False),
            "4.4.4.4": ({"ipwho_status": "ok", "proxycheck_status": "ok"}, True),
        }
        with tempfile.TemporaryDirectory() as td:
            st = Store(Path(td) / "s.db")
            with patch("gate_us_lite.store.time.time", return_value=1000):
                for ip, (statuses, _) in cases.items():
                    st.put_intel(ip, {**schema, **statuses})
            for ip, (_, long_lived) in cases.items():
                with self.subTest(ip):
                    with patch("gate_us_lite.store.time.time", return_value=1500):
                        self.assertIsNotNone(st.get_intel(ip, ttl=86400, error_ttl=900))
                    with patch("gate_us_lite.store.time.time", return_value=2000):
                        self.assertEqual(st.get_intel(ip, ttl=86400, error_ttl=900) is not None, long_lived)
            st.close()

    def test_intel_cached_under_another_schema_is_never_reused(self):
        known = {"ipwho_status": "ok", "proxycheck_status": "ok"}
        with tempfile.TemporaryDirectory() as td:
            st = Store(Path(td) / "s.db")
            st.put_intel("1.1.1.1", {**known, "intel_schema": intel_mod.INTEL_SCHEMA - 1})
            st.put_intel("2.2.2.2", {**known, "intel_schema": intel_mod.INTEL_SCHEMA})
            self.assertIsNone(st.get_intel("1.1.1.1"))
            self.assertIsNotNone(st.get_intel("2.2.2.2"))
            st.close()

    def test_ipwho_free_tier_carries_no_security_verdicts(self):
        payload = {
            "success": True, "country_code": "US",
            "connection": {"asn": 15169, "org": "Google LLC", "isp": "Google LLC", "domain": "google.com"},
        }
        with patch.object(intel_mod, "fetch", return_value=response(payload)):
            got = intel_mod._ipwho("8.8.8.8", 6)
        self.assertEqual(set(got), {"country_code", "asn", "isp", "org", "domain"})

    def test_proxycheck_maps_residential_proxy_operator(self):
        operator = {"name": "IPRoyal", "services": ["web_scraping", "residential_proxies"]}
        payload = proxycheck_payload("1.1.1.1", detections={"anonymous": True, "risk": 100}, operator=operator)
        with patch.object(intel_mod, "fetch", return_value=response(payload)) as fetch:
            got = intel_mod._proxycheck("1.1.1.1", "key", 6)
        self.assertIn("/v3/1.1.1.1?key=key", fetch.call_args.args[0])
        self.assertEqual(got, {
            "tor": False, "compromised": False, "hosting": False, "proxycheck_proxy": True,
            "proxycheck_risk": 100.0, "residential_proxy": True,
        })

    def test_proxycheck_flags_tor_and_hosting(self):
        tor = proxycheck_payload("1.1.1.1", detections={"tor": True})
        hosting_net = proxycheck_payload("1.1.1.1", network_type="Hosting")
        hosting_detection = proxycheck_payload("1.1.1.1", detections={"hosting": True})
        with patch.object(intel_mod, "fetch", return_value=response(tor)):
            self.assertTrue(intel_mod._proxycheck("1.1.1.1", "key", 6)["tor"])
        for payload in (hosting_net, hosting_detection):
            with patch.object(intel_mod, "fetch", return_value=response(payload)):
                self.assertTrue(intel_mod._proxycheck("1.1.1.1", "key", 6)["hosting"])

    def test_proxycheck_flags_a_compromised_host(self):
        payload = proxycheck_payload("1.1.1.1", detections={"compromised": True})
        with patch.object(intel_mod, "fetch", return_value=response(payload)):
            self.assertTrue(intel_mod._proxycheck("1.1.1.1", "key", 6)["compromised"])

    def test_proxycheck_clean_address_without_operator(self):
        with patch.object(intel_mod, "fetch", return_value=response(proxycheck_payload("1.1.1.1"))):
            got = intel_mod._proxycheck("1.1.1.1", "key", 6)
        self.assertFalse(any(got[k] for k in ("tor", "compromised", "hosting", "proxycheck_proxy", "residential_proxy")))

    def test_proxycheck_denied_or_empty_result_is_an_error(self):
        denied = {"status": "denied", "message": "1,000 Free queries exhausted."}
        with patch.object(intel_mod, "fetch", return_value=response(denied)):
            with self.assertRaisesRegex(RuntimeError, "queries exhausted"):
                intel_mod._proxycheck("1.1.1.1", "key", 6)
        with patch.object(intel_mod, "fetch", return_value=response({"status": "ok"})):
            with self.assertRaisesRegex(RuntimeError, "no result"):
                intel_mod._proxycheck("1.1.1.1", "key", 6)

    def test_proxycheck_accepts_a_real_v3_reply(self):
        with patch.object(intel_mod, "fetch", return_value=response(PROXYCHECK_V3_SAMPLE)):
            got = intel_mod._proxycheck("147.135.15.16", "key", 6)
        self.assertEqual(got, {
            "tor": False, "compromised": False, "hosting": True, "proxycheck_proxy": False,
            "proxycheck_risk": 33.0, "residential_proxy": False,
        })

    def test_proxycheck_incomplete_verdict_is_an_error_not_a_clean_address(self):
        complete = proxycheck_payload("1.1.1.1")["1.1.1.1"]["detections"]
        broken = {
            "no detections": None,
            "null risk": {**complete, "risk": None},
            "missing risk": {key: value for key, value in complete.items() if key != "risk"},
            "null tor flag": {**complete, "tor": None},
            "missing anonymous flag": {key: value for key, value in complete.items() if key != "anonymous"},
            "null compromised flag": {**complete, "compromised": None},
            "missing compromised flag": {key: value for key, value in complete.items() if key != "compromised"},
            "hosting as text": {**complete, "hosting": "false"},
        }
        for name, detections in broken.items():
            payload = proxycheck_payload("1.1.1.1")
            payload["1.1.1.1"]["detections"] = detections
            with self.subTest(name), patch.object(intel_mod, "fetch", return_value=response(payload)):
                with self.assertRaisesRegex(RuntimeError, "complete verdict"):
                    intel_mod._proxycheck("1.1.1.1", "key", 6)

    def test_proxycheck_lookback_window_is_requested_only_when_configured(self):
        payload = response(proxycheck_payload("1.1.1.1"))
        with patch.object(intel_mod, "fetch", return_value=payload) as fetch:
            intel_mod._proxycheck("1.1.1.1", "key", 6, 0, 30)
            intel_mod._proxycheck("1.1.1.1", "key", 6)
        self.assertTrue(fetch.call_args_list[0].args[0].endswith("/v3/1.1.1.1?key=key&days=30"))
        self.assertTrue(fetch.call_args_list[1].args[0].endswith("/v3/1.1.1.1?key=key"))

    def test_abuseipdb_adds_an_independent_hosting_and_tor_opinion(self):
        def abuse(**fields):
            record = {"abuseConfidenceScore": 0, "totalReports": 0, "usageType": "Fixed Line ISP", "isTor": False}
            return response({"data": {**record, **fields}})

        ipwho = {"country_code": "US"}
        cases = {
            "data center usage": (abuse(usageType="Data Center/Web Hosting/Transit"), {"hosting": True, "tor": False}),
            "tor exit": (abuse(isTor=True), {"hosting": False, "tor": True}),
            "ordinary ISP": (abuse(), {"hosting": False, "tor": False}),
        }
        for name, (reply, expected) in cases.items():
            with self.subTest(name), patch.object(intel_mod, "_ipwho", return_value=ipwho), \
                 patch.object(intel_mod, "fetch", return_value=reply):
                got = intel_mod.enrich("1.1.1.1", abuseipdb_key="key")
            self.assertEqual({key: got[key] for key in expected}, expected)
            self.assertEqual(got["abuse_status"], "ok")

    def test_abuseipdb_silence_never_overrules_proxycheck(self):
        proxycheck = {"hosting": True, "tor": True}
        reply = response({"data": {"usageType": "Fixed Line ISP", "isTor": False}})
        with patch.object(intel_mod, "_ipwho", return_value={"country_code": "US"}), \
             patch.object(intel_mod, "_proxycheck", return_value=proxycheck), \
             patch.object(intel_mod, "fetch", return_value=reply):
            got = intel_mod.enrich("1.1.1.1", proxycheck_key="p", abuseipdb_key="a")
        self.assertTrue(got["hosting"] and got["tor"])

    def test_hosting_is_known_only_after_a_provider_verdict(self):
        ipwho = {"country_code": "US", "asn": 1, "isp": "Example Fiber", "org": "", "domain": ""}
        with patch.object(intel_mod, "_ipwho", return_value=ipwho):
            without_key = intel_mod.enrich("1.1.1.1")
        with patch.object(intel_mod, "_ipwho", return_value=ipwho), \
             patch.object(intel_mod, "_proxycheck", return_value={"hosting": False}):
            with_key = intel_mod.enrich("1.1.1.1", proxycheck_key="key")
        with patch.object(intel_mod, "_ipwho", return_value={**ipwho, "isp": "Example Hosting LLC"}):
            heuristic = intel_mod.enrich("1.1.1.1")
        self.assertEqual(without_key["ipwho_status"], "ok")
        self.assertFalse(without_key["hosting_known"])
        self.assertTrue(with_key["hosting_known"])
        self.assertTrue(heuristic["hosting_known"])
        self.assertTrue(heuristic["hosting_heuristic"])


class TestEvaluateIntel(unittest.TestCase):
    def score(self, intel: dict) -> float:
        return evaluate(candidate(intel), POLICY).selection_score

    def reasons(self, intel: dict, filters: dict = POLICY) -> list[str]:
        return evaluate(candidate({**CLEAN, **intel}), filters).reject_reasons

    def test_clean_bonus_requires_a_provider_verdict(self):
        clean = self.score({"hosting_known": True, "hosting": False})
        unknown = self.score({"hosting_known": False})
        hosting = self.score({"hosting_known": True, "hosting": True})
        self.assertEqual(clean - unknown, 14)
        self.assertEqual(unknown - hosting, 12)

    def test_keyword_heuristic_overrides_a_clean_verdict(self):
        clean = self.score({"hosting_known": True, "hosting": False})
        flagged = self.score({"hosting_known": True, "hosting": False, "hosting_heuristic": True})
        self.assertEqual(clean - flagged, 26)

    def test_clean_known_address_is_accepted(self):
        self.assertEqual(self.reasons({}), [])

    def test_default_policy_publishes_public_relays_but_not_dangerous_ones(self):
        relay = {"hosting": True, "hosting_heuristic": True, "proxycheck_proxy": True, "proxycheck_risk": 100.0}
        self.assertEqual(self.reasons(relay), [])
        dangerous = {
            "tor": {"tor": True},
            "compromised": {"compromised": True},
            "residential_proxy": {"residential_proxy": True},
            "severe_recent_abuse": {"abuse_confidence": 80},
            "country_mismatch": {"country_code": "DE"},
            "invalid_ip": {"invalid_ip": True},
        }
        for reason, intel in dangerous.items():
            with self.subTest(reason):
                self.assertIn(reason, self.reasons({**relay, **intel}))

    def test_every_risk_verdict_can_be_made_a_hard_reject(self):
        cases = {
            "hosting": {"hosting": True},
            "proxy": {"proxycheck_proxy": True},
            "high_risk": {"proxycheck_risk": 26},
        }
        for reason, intel in cases.items():
            with self.subTest(reason):
                self.assertEqual(self.reasons(intel, STRICT), [reason])

    def test_hosting_keyword_heuristic_follows_the_hosting_filter(self):
        self.assertEqual(self.reasons({"hosting_heuristic": True}), [])
        self.assertEqual(self.reasons({"hosting_heuristic": True}, STRICT), ["hosting"])

    def test_risk_at_the_threshold_is_accepted(self):
        self.assertEqual(self.reasons({"proxycheck_risk": 25.0}, STRICT), [])
        self.assertEqual(self.reasons({"proxycheck_risk": 40}, {**STRICT, "max_proxycheck_risk": 50}), [])

    def test_unverified_country_is_a_mismatch(self):
        self.assertIn("country_mismatch", self.reasons({"country_code": ""}))

    def test_unknown_intel_is_rejected_without_a_verdict_from_both_providers(self):
        for intel in ({"ipwho_status": "error"}, {"proxycheck_status": "error"}, {"proxycheck_status": "disabled"}):
            with self.subTest(intel):
                self.assertEqual(self.reasons(intel), ["intel_unknown"])
        self.assertEqual(self.reasons({"proxycheck_status": "disabled"}, {**POLICY, "require_known_intel": False}), [])

    def test_invalid_address_is_not_reported_as_unknown_intel(self):
        self.assertEqual(self.reasons({"invalid_ip": True, "ipwho_status": "invalid", "proxycheck_status": "skipped"}), ["invalid_ip"])


if __name__ == "__main__":
    unittest.main()
