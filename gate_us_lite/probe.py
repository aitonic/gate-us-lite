from __future__ import annotations

import socket
import time
from .models import Candidate


def tcp_probe(candidate: Candidate, timeout: float = 2.0) -> tuple[bool, float | None]:
    """Cheap endpoint reachability signal; not an OpenVPN handshake.

    The result is intentionally a soft signal because GitHub Actions networking can
    differ from the eventual Mihomo client network.
    """
    if candidate.profile.proto != "tcp":
        return False, None
    host = candidate.endpoint_ip or candidate.profile.server
    started = time.monotonic()
    try:
        with socket.create_connection((host, candidate.profile.port), timeout=timeout):
            return True, round((time.monotonic() - started) * 1000.0, 2)
    except OSError:
        return False, None
