from __future__ import annotations

import concurrent.futures
import contextlib
import re
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path

from .http import fetch
from .intel import is_public_ip
from .mihomo import render_probe_config
from .models import Candidate

TRACE_URL = "https://www.cloudflare.com/cdn-cgi/trace"
READY_TIMEOUT_SECONDS = 10.0
DIAL_ERROR = re.compile(r'dial (probe-\d+) \S+ --> \S+ error: (.+?)"?$', re.M)


class TunnelProbeUnavailable(RuntimeError):
    """The probe harness cannot deliver trustworthy verdicts, so nothing may be published."""


def probe_tunnels(candidates: list[Candidate], mihomo_bin: str, timeout: float) -> tuple[dict[str, str], dict[str, str]]:
    """Dial every candidate through its own OpenVPN tunnel in a local Mihomo process.

    Each candidate is bound to a dedicated loopback listener and must fetch the Cloudflare
    trace through it. A DIRECT listener provides the runner's own address as a control.
    Returns (alive, failed): dedupe_key -> observed exit IP, dedupe_key -> failure reason.
    """
    if not candidates:
        return {}, {}
    binary = shutil.which(mihomo_bin)
    if not binary:
        raise TunnelProbeUnavailable(f"Mihomo binary {mihomo_bin!r} not found; set MIHOMO_BIN")
    control_port, *ports = _free_ports(len(candidates) + 1)
    with tempfile.TemporaryDirectory(prefix="gate-us-lite-") as workdir:
        root = Path(workdir)
        config, log_path = root / "config.yaml", root / "mihomo.log"
        config.write_text(render_probe_config(candidates, ports, control_port), encoding="utf-8")
        with _mihomo(binary, root, config, log_path, control_port):
            control_ip = _control_ip(control_port, timeout)
            with concurrent.futures.ThreadPoolExecutor(max_workers=len(candidates)) as pool:
                outcomes = list(pool.map(lambda port: _probe_port(port, control_ip, timeout), ports))
        dial_errors = dict(DIAL_ERROR.findall(log_path.read_text(encoding="utf-8", errors="replace")))

    alive: dict[str, str] = {}
    failed: dict[str, str] = {}
    for index, (c, (exit_ip, error)) in enumerate(zip(candidates, outcomes)):
        if exit_ip:
            alive[c.dedupe_key] = exit_ip
        else:
            failed[c.dedupe_key] = dial_errors.get(f"probe-{index}") or error
    return alive, failed


def _free_ports(count: int) -> list[int]:
    sockets = [socket.socket() for _ in range(count)]
    try:
        for s in sockets:
            s.bind(("127.0.0.1", 0))
        return [s.getsockname()[1] for s in sockets]
    finally:
        for s in sockets:
            s.close()


@contextlib.contextmanager
def _mihomo(binary: str, workdir: Path, config: Path, log_path: Path, ready_port: int):
    # The child dials untrusted servers, so it gets no inherited environment (API keys, tokens).
    with log_path.open("wb") as log:
        proc = subprocess.Popen(
            [binary, "-d", str(workdir), "-f", str(config)],
            stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, env={"HOME": str(workdir)},
        )
        try:
            _wait_ready(proc, ready_port, log_path)
            yield
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


def _wait_ready(proc: subprocess.Popen, port: int, log_path: Path) -> None:
    deadline = time.monotonic() + READY_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise TunnelProbeUnavailable(f"mihomo exited with status {proc.returncode}: {_log_tail(log_path)}")
        with contextlib.suppress(OSError):
            socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
            return
        time.sleep(0.1)
    raise TunnelProbeUnavailable(f"mihomo listener not ready after {READY_TIMEOUT_SECONDS:.0f}s: {_log_tail(log_path)}")


def _log_tail(log_path: Path, lines: int = 5) -> str:
    return " | ".join(log_path.read_text(encoding="utf-8", errors="replace").splitlines()[-lines:])


def _trace(port: int, timeout: float) -> dict[str, str]:
    body = fetch(TRACE_URL, proxy=f"http://127.0.0.1:{port}", timeout=timeout, retries=0, max_bytes=16_384).text()
    return dict(line.split("=", 1) for line in body.splitlines() if "=" in line)


def _exit_ip(port: int, timeout: float) -> str:
    ip = _trace(port, timeout).get("ip", "")
    if not is_public_ip(ip):
        raise ValueError(f"trace returned no public ip: {ip!r}")
    return ip


def _control_ip(port: int, timeout: float) -> str:
    try:
        return _exit_ip(port, timeout)
    except Exception as exc:
        raise TunnelProbeUnavailable(f"DIRECT control request failed: {exc}") from exc


def _probe_port(port: int, control_ip: str, timeout: float) -> tuple[str, str]:
    try:
        exit_ip = _exit_ip(port, timeout)
    except Exception as exc:
        return "", str(exc) or type(exc).__name__
    if exit_ip == control_ip:
        return "", "traffic bypassed the tunnel"
    return exit_ip, ""
