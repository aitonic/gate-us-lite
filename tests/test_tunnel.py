import os
import shutil
import subprocess
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import MagicMock, patch

from gate_us_lite import tunnel
from gate_us_lite.mihomo import render_probe_config
from gate_us_lite.tunnel import TunnelProbeUnavailable, probe_tunnels
from tests.helpers import candidate

CONTROL_IP = "8.8.8.8"
DIAL_ERROR_LINE = (
    'time="2026-10-07T08:15:50+08:00" level=warning msg="[TCP] dial probe-3 127.0.0.1:62371 --> '
    'www.cloudflare.com:443 error: make OpenVPN handshake: read hard reset response after 0 retransmits: '
    'context deadline exceeded"'
)
MIHOMO_BIN = shutil.which(os.environ.get("MIHOMO_BIN", "mihomo"))


def fake_mihomo(log_text: str = ""):
    captured = {}

    @contextmanager
    def run(binary, workdir, config, log_path, ready_port):
        captured["config"] = config.read_text(encoding="utf-8")
        log_path.write_text(log_text, encoding="utf-8")
        yield

    return run, captured


class TestProbeConfig(unittest.TestCase):
    def test_each_listener_is_pinned_to_one_proxy(self):
        text = render_probe_config([candidate("1.1.1.1"), candidate("2.2.2.2")], [41001, 41002], 41000)
        self.assertEqual(text.count("type: openvpn"), 2)
        for port, proxy in ((41000, "DIRECT"), (41001, "probe-0"), (41002, "probe-1")):
            self.assertIn(f'    port: {port}\n    proxy: "{proxy}"', text)
        self.assertEqual(text.count("listen: 127.0.0.1"), 3)
        self.assertNotIn("proxy-groups", text)

    @unittest.skipUnless(MIHOMO_BIN, "Mihomo binary not available")
    def test_pinned_mihomo_accepts_the_probe_config(self):
        with tempfile.TemporaryDirectory() as td:
            config = Path(td) / "config.yaml"
            config.write_text(render_probe_config([candidate("1.1.1.1"), candidate("2.2.2.2", 443, "tcp")], [41001, 41002], 41000))
            done = subprocess.run([MIHOMO_BIN, "-t", "-d", td, "-f", str(config)], capture_output=True, text=True, timeout=30)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)


class TestProbeTunnels(unittest.TestCase):
    def run_probe(self, traces, log_text="", count=4):
        """`traces` maps a candidate index to its trace result; the control listener always answers CONTROL_IP."""
        candidates = [candidate(f"1.1.1.{i + 1}") for i in range(count)]
        mihomo, captured = fake_mihomo(log_text)

        def trace(port, timeout):
            if port == self.ports[0]:
                return {"ip": CONTROL_IP}
            result = traces[self.ports.index(port) - 1]
            if isinstance(result, Exception):
                raise result
            return result

        def free_ports(n):
            self.ports = list(range(41000, 41000 + n))
            return self.ports

        with patch.object(tunnel.shutil, "which", return_value="/usr/bin/mihomo"), \
             patch.object(tunnel, "_free_ports", side_effect=free_ports), \
             patch.object(tunnel, "_mihomo", mihomo), \
             patch.object(tunnel, "_trace", side_effect=trace):
            return candidates, probe_tunnels(candidates, "mihomo", 5), captured

    def test_only_tunnels_with_a_distinct_public_exit_survive(self):
        traces = [
            {"ip": "9.9.9.9", "loc": "US"},
            {"ip": CONTROL_IP},
            RuntimeError("fetch failed: https://www.cloudflare.com/cdn-cgi/trace: URLError"),
            RuntimeError("closed"),
        ]
        candidates, (alive, failed), captured = self.run_probe(traces, DIAL_ERROR_LINE)
        self.assertEqual(alive, {candidates[0].dedupe_key: "9.9.9.9"})
        self.assertEqual(failed[candidates[1].dedupe_key], "traffic bypassed the tunnel")
        self.assertIn("URLError", failed[candidates[2].dedupe_key])
        self.assertIn("make OpenVPN handshake", failed[candidates[3].dedupe_key])
        self.assertEqual(captured["config"].count("type: openvpn"), 4)

    def test_failures_of_one_kind_do_not_differ_by_node_address(self):
        log_text = "\n".join(
            f'time="2026-10-07T08:15:50+08:00" level=warning msg="[TCP] dial probe-{i} 127.0.0.1:6237{i} --> '
            f'www.cloudflare.com:443 error: connect OpenVPN server: dial tcp 192.0.2.{i + 1}:995: i/o timeout"'
            for i in range(2)
        )
        _, (alive, failed), _ = self.run_probe([RuntimeError("closed")] * 2, log_text, count=2)
        self.assertEqual(alive, {})
        self.assertEqual(set(failed.values()), {"connect OpenVPN server: dial tcp <addr>: i/o timeout"})

    def test_private_or_missing_exit_address_is_a_failure(self):
        candidates, (alive, failed), _ = self.run_probe([{"ip": "10.0.0.2"}, {}], count=2)
        self.assertEqual(alive, {})
        self.assertEqual(len(failed), 2)

    def test_failed_control_request_makes_the_probe_unavailable(self):
        mihomo, _ = fake_mihomo()
        with patch.object(tunnel.shutil, "which", return_value="/usr/bin/mihomo"), \
             patch.object(tunnel, "_free_ports", return_value=[41000, 41001]), \
             patch.object(tunnel, "_mihomo", mihomo), \
             patch.object(tunnel, "_trace", side_effect=RuntimeError("no route")):
            with self.assertRaisesRegex(TunnelProbeUnavailable, "DIRECT control request failed: no route"):
                probe_tunnels([candidate("1.1.1.1")], "mihomo", 5)

    def test_missing_binary_makes_the_probe_unavailable(self):
        with patch.object(tunnel.shutil, "which", return_value=None):
            with self.assertRaisesRegex(TunnelProbeUnavailable, "MIHOMO_BIN"):
                probe_tunnels([candidate("1.1.1.1")], "mihomo", 5)

    def test_no_candidates_do_not_start_mihomo(self):
        with patch.object(tunnel, "_mihomo") as mihomo:
            self.assertEqual(probe_tunnels([], "mihomo", 5), ({}, {}))
        mihomo.assert_not_called()

    def test_free_ports_are_distinct_loopback_ports(self):
        ports = tunnel._free_ports(8)
        self.assertEqual(len(set(ports)), 8)


class TestMihomoProcess(unittest.TestCase):
    def test_child_gets_no_inherited_environment_and_is_always_stopped(self):
        proc = MagicMock()
        proc.poll.return_value = None
        with tempfile.TemporaryDirectory() as td, \
             patch.object(tunnel.subprocess, "Popen", return_value=proc) as popen, \
             patch.object(tunnel, "_wait_ready"):
            with self.assertRaises(KeyError):
                with tunnel._mihomo("/bin/mihomo", Path(td), Path(td) / "c.yaml", Path(td) / "m.log", 1):
                    raise KeyError("probe crashed")
        self.assertEqual(popen.call_args.kwargs["env"], {"HOME": td})
        proc.terminate.assert_called_once()

    def test_exit_during_startup_is_reported_with_the_log_tail(self):
        proc = MagicMock()
        proc.poll.return_value = 1
        proc.returncode = 1
        with tempfile.TemporaryDirectory() as td, patch.object(tunnel.subprocess, "Popen", return_value=proc):
            log_path = Path(td) / "m.log"
            with self.assertRaisesRegex(TunnelProbeUnavailable, "exited with status 1"):
                with tunnel._mihomo("/bin/mihomo", Path(td), Path(td) / "c.yaml", log_path, 1):
                    pass
        proc.terminate.assert_called_once()


if __name__ == "__main__":
    unittest.main()
