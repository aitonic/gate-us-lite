import io
import json
import os
import tempfile
import unittest
from contextlib import contextmanager, redirect_stderr
from pathlib import Path
from unittest.mock import patch

from gate_us_lite import cli, pipeline, tunnel
from gate_us_lite import intel as intel_mod
from gate_us_lite.store import Store
from tests.helpers import candidate

CLEAN = {
    "intel_schema": intel_mod.INTEL_SCHEMA, "ipwho_status": "ok", "proxycheck_status": "ok",
    "country_code": "US", "asn_key": "AS1", "hosting_known": True, "hosting": False,
    "proxycheck_proxy": False, "proxycheck_risk": 0.0, "tor": False, "residential_proxy": False,
    "fixed_isp_heuristic": True,
}
VPNGATE_ONLY = "[sources]\nvpngate=true\npublicvpnlist=false\nvpngate_scraper=false\n"


def every_tunnel_alive(candidates, *_):
    return {c.dedupe_key: c.endpoint_ip for c in candidates}, {}


class PipelineCase(unittest.TestCase):
    config_text = VPNGATE_ONLY

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        (self.root / "config.toml").write_text(self.config_text)
        self.output = self.root / "mihomo.yaml"
        self.looked_up: list[str] = []
        self.lookup_args: list[dict] = []
        environment = patch.dict(os.environ, {"PROXYCHECK_API_KEY": "test-key"})
        environment.start()
        self.addCleanup(environment.stop)

    def run_cli(self, *stage) -> int:
        argv = [
            *stage,
            "--config", str(self.root / "config.toml"),
            "--state", str(self.root / ".state/state.sqlite3"),
            "--output", str(self.output),
            "--candidates", str(self.root / "handoff/candidates.json"),
            "--verdicts", str(self.root / "handoff/verdicts.json"),
        ]
        with self.assertRaises(SystemExit) as raised:
            cli.main(argv)
        return raised.exception.code

    @contextmanager
    def upstream(self, nodes, intel_by_ip=None, tunnels=every_tunnel_alive):
        """Replace every network boundary: sources, the tunnel probe and IP intelligence."""
        def enrich(ip, **kwargs):
            self.looked_up.append(ip)
            self.lookup_args.append(kwargs)
            return (intel_by_ip or {}).get(ip, CLEAN)

        with patch.object(pipeline, "_fetch_one", return_value=nodes), \
             patch.object(pipeline, "enrich", side_effect=enrich), \
             patch.object(pipeline, "probe_tunnels", side_effect=tunnels):
            yield

    def yaml_text(self) -> str:
        return self.output.read_text(encoding="utf-8")


class TestRun(PipelineCase):
    def test_only_live_tunnels_are_published_and_intel_checks_their_exit_address(self):
        live, dead = candidate("1.1.1.1"), candidate("2.2.2.2")
        verdict = ({live.dedupe_key: "9.9.9.9"}, {dead.dedupe_key: "handshake timeout"})
        with self.upstream([live, dead], tunnels=lambda *_: verdict):
            self.assertEqual(self.run_cli(), 0)
        self.assertEqual(self.looked_up, ["9.9.9.9"])
        self.assertIn('server: "1.1.1.1"', self.yaml_text())
        self.assertNotIn("2.2.2.2", self.yaml_text())

    def test_nothing_is_published_when_every_tunnel_is_dead(self):
        dead = candidate("2.2.2.2")
        with self.upstream([dead], tunnels=lambda *_: ({}, {dead.dedupe_key: "handshake timeout"})):
            self.assertEqual(self.run_cli(), 2)
        self.assertEqual(self.looked_up, [])
        self.assertFalse(self.output.exists())

    def test_unknown_intel_is_not_published(self):
        unknown = {**CLEAN, "proxycheck_status": "disabled"}
        with self.upstream([candidate("1.1.1.1")], {"1.1.1.1": unknown}):
            self.assertEqual(self.run_cli(), 2)
        self.assertFalse(self.output.exists())

    def test_risky_exit_addresses_are_dropped_and_clean_ones_kept(self):
        intel = {
            "2.2.2.2": {**CLEAN, "hosting": True},
            "3.3.3.3": {**CLEAN, "proxycheck_risk": 60.0},
            "4.4.4.4": {**CLEAN, "proxycheck_proxy": True},
        }
        nodes = [candidate(ip) for ip in ("1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4")]
        with self.upstream(nodes, intel):
            self.assertEqual(self.run_cli(), 0)
        self.assertEqual(self.yaml_text().count("type: openvpn"), 1)
        self.assertIn('server: "1.1.1.1"', self.yaml_text())

    def test_provider_failures_are_summarized_in_the_log(self):
        failed = {
            **CLEAN, "proxycheck_status": "error",
            "proxycheck_error": "fetch failed: https://proxycheck.io/v3/1.1.1.1: HTTPError 429",
        }
        with self.upstream([candidate("1.1.1.1")], {"1.1.1.1": failed}), redirect_stderr(io.StringIO()) as log:
            self.assertEqual(self.run_cli(), 2)
        self.assertIn("[intel] errors: 1x proxycheck: HTTPError 429", log.getvalue())

    def test_missing_proxycheck_key_is_a_configuration_error_before_any_work_is_done(self):
        probed = []

        def tunnels(pool, *_):
            probed.append(pool)
            return every_tunnel_alive(pool)

        self.output.write_text("previous", encoding="utf-8")
        with patch.dict(os.environ, {"PROXYCHECK_API_KEY": ""}), self.upstream([candidate("1.1.1.1")], tunnels=tunnels):
            self.assertEqual(self.run_cli(), cli.CONFIGURATION_EXIT)
        self.assertEqual((probed, self.looked_up), ([], []))
        self.assertEqual(self.yaml_text(), "previous")

    def test_finish_stage_alone_also_requires_the_proxycheck_key(self):
        handoff = self.root / "handoff"
        handoff.mkdir()
        live = candidate("1.1.1.1")
        (handoff / "candidates.json").write_text(json.dumps([cli.candidate_to_dict(live)]))
        (handoff / "verdicts.json").write_text(json.dumps({"alive": {live.dedupe_key: "9.9.9.9"}}))
        with patch.dict(os.environ, {"PROXYCHECK_API_KEY": ""}), self.upstream([]):
            self.assertEqual(self.run_cli("finish"), cli.CONFIGURATION_EXIT)
        self.assertEqual(self.looked_up, [])

    def test_previous_yaml_survives_a_run_without_acceptable_nodes(self):
        self.output.write_text("previous", encoding="utf-8")
        with self.upstream([candidate("1.1.1.1")], {"1.1.1.1": {**CLEAN, "tor": True}}):
            self.assertEqual(self.run_cli(), 2)
        self.assertEqual(self.yaml_text(), "previous")

    def test_missing_mihomo_binary_publishes_nothing(self):
        self.output.write_text("previous", encoding="utf-8")
        with self.upstream([candidate("1.1.1.1")]), \
             patch.object(pipeline, "probe_tunnels", tunnel.probe_tunnels), \
             patch.object(tunnel.shutil, "which", return_value=None):
            self.assertEqual(self.run_cli(), cli.PROBE_UNAVAILABLE_EXIT)
        self.assertEqual(self.looked_up, [])
        self.assertEqual(self.yaml_text(), "previous")

    def test_only_yaml_is_written_next_to_the_state(self):
        c = candidate("1.1.1.1")
        c.ping_ms, c.speed_mbps = 20, 50
        with self.upstream([c]):
            self.assertEqual(self.run_cli(), 0)
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), [".state", "config.toml", "mihomo.yaml"])

    def test_cached_fallback_does_not_fake_availability(self):
        c = candidate("1.1.1.1")
        with self.upstream([c]), patch("gate_us_lite.store.time.time", return_value=1000):
            self.assertEqual(self.run_cli(), 0)
        with self.upstream([]), patch("gate_us_lite.store.time.time", return_value=2000):
            self.assertEqual(self.run_cli(), 0)
            store = Store(self.root / ".state/state.sqlite3")
            history = store.history(c.dedupe_key)
            store.close()
        self.assertEqual(history["seen_24h"], 1)
        self.assertEqual(history["availability_24h"], 1.0)
        self.assertEqual(history["opportunities_24h"], 1)


class TestRelaxedIntelRequirement(PipelineCase):
    config_text = VPNGATE_ONLY + "[filters]\nrequire_known_intel=false\n"

    def test_no_proxycheck_key_is_acceptable_when_unknown_intel_is_allowed(self):
        with patch.dict(os.environ, {"PROXYCHECK_API_KEY": ""}), self.upstream([candidate("1.1.1.1")]):
            self.assertEqual(self.run_cli(), 0)


class TestLookbackWindow(PipelineCase):
    config_text = VPNGATE_ONLY + "[general]\nproxycheck_lookback_days=45\n"

    def test_intel_lookups_use_the_configured_window(self):
        with self.upstream([candidate("1.1.1.1")]):
            self.assertEqual(self.run_cli(), 0)
        self.assertEqual(self.lookup_args[0]["proxycheck_lookback_days"], 45)


class TestSourceCacheWindow(PipelineCase):
    day = 86400

    def run_at(self, moment: int, nodes) -> int:
        with self.upstream(nodes), patch("gate_us_lite.store.time.time", return_value=moment):
            return self.run_cli()

    def test_last_good_snapshot_covers_a_source_for_longer_than_one_run_interval(self):
        self.assertEqual(self.run_at(1000, [candidate("1.1.1.1")]), 0)
        self.assertEqual(self.run_at(1000 + 2 * self.day, []), 0)
        self.assertEqual(self.run_at(1000 + 5 * self.day, []), 2)


class TestSourceCacheWindowConfigured(PipelineCase):
    config_text = VPNGATE_ONLY + "[general]\nsource_cache_max_age_seconds=3600\n"

    def test_the_window_comes_from_the_configuration(self):
        with self.upstream([candidate("1.1.1.1")]), patch("gate_us_lite.store.time.time", return_value=1000):
            self.assertEqual(self.run_cli(), 0)
        with self.upstream([]), patch("gate_us_lite.store.time.time", return_value=1000 + 7200):
            self.assertEqual(self.run_cli(), 2)


class TestSourceHealth(unittest.TestCase):
    def test_low_watermark_detection(self):
        with tempfile.TemporaryDirectory() as td:
            store = Store(Path(td) / "s.db")
            for i in range(4):
                with patch("gate_us_lite.store.time.time", return_value=1000 + i):
                    store.record_source_snapshot("vpngate", 10, "ok")
            cfg = {"general": {"source_baseline_window": 12, "source_low_watermark_ratio": 0.4, "source_low_watermark_min_baseline": 4}}
            degraded, baseline = pipeline._is_degraded(store, "vpngate", 2, cfg)
            store.close()
        self.assertTrue(degraded)
        self.assertEqual(baseline, 10.0)


class TestStages(PipelineCase):
    def read(self, name: str):
        return json.loads((self.root / "handoff" / name).read_text(encoding="utf-8"))

    def test_stages_hand_work_over_through_files(self):
        live, dead = candidate("1.1.1.1"), candidate("2.2.2.2")
        verdict = ({live.dedupe_key: "9.9.9.9"}, {dead.dedupe_key: "timeout"})
        with self.upstream([live, dead], tunnels=lambda *_: verdict):
            self.assertEqual(self.run_cli("collect"), 0)
            self.assertEqual({item["endpoint_ip"] for item in self.read("candidates.json")}, {"1.1.1.1", "2.2.2.2"})
            self.assertEqual(self.run_cli("probe"), 0)
            self.assertEqual(self.read("verdicts.json"), {"alive": {live.dedupe_key: "9.9.9.9"}})
            self.assertEqual(self.looked_up, [])
            self.assertEqual(self.run_cli("finish"), 0)
        self.assertEqual(self.looked_up, ["9.9.9.9"])
        self.assertIn('server: "1.1.1.1"', self.yaml_text())

    def test_finish_keeps_only_plausible_verdicts(self):
        known, private, spoofed = candidate("1.1.1.1"), candidate("2.2.2.2"), candidate("3.3.3.3")
        handoff = self.root / "handoff"
        handoff.mkdir()
        (handoff / "candidates.json").write_text(json.dumps([cli.candidate_to_dict(c) for c in (known, private, spoofed)]))
        claimed = {
            known.dedupe_key: "9.9.9.9",
            private.dedupe_key: "10.0.0.2",
            spoofed.dedupe_key: ["9.9.9.9"],
            "6.6.6.6:1194/udp": "9.9.9.9",
        }
        (handoff / "verdicts.json").write_text(json.dumps({"alive": claimed}))
        with self.upstream([]):
            self.assertEqual(self.run_cli("finish"), 0)
        self.assertEqual(self.looked_up, ["9.9.9.9"])
        self.assertEqual(self.yaml_text().count("type: openvpn"), 1)

    def test_finish_without_verdicts_publishes_nothing(self):
        handoff = self.root / "handoff"
        handoff.mkdir()
        (handoff / "candidates.json").write_text(json.dumps([cli.candidate_to_dict(candidate("1.1.1.1"))]))
        self.output.write_text("previous", encoding="utf-8")
        with self.upstream([]):
            self.assertEqual(self.run_cli("finish"), cli.PROBE_UNAVAILABLE_EXIT)
        self.assertEqual(self.looked_up, [])
        self.assertEqual(self.yaml_text(), "previous")


class TestProbeLimit(PipelineCase):
    config_text = VPNGATE_ONLY + "[general]\ntunnel_probe_limit=2\n"

    def test_collect_hands_over_only_the_best_candidates(self):
        nodes = [candidate(f"1.1.1.{i}") for i in range(1, 5)]
        with self.upstream(nodes):
            self.assertEqual(self.run_cli("collect"), 0)
        pool = json.loads((self.root / "handoff/candidates.json").read_text(encoding="utf-8"))
        self.assertEqual(len(pool), 2)


if __name__ == "__main__":
    unittest.main()
