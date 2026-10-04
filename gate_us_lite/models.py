from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class OpenVPNProfile:
    server: str
    port: int
    proto: str
    ca: str
    cert: str = ""
    key: str = ""
    username: str = ""
    password: str = ""
    cipher: str = ""
    auth: str = ""
    data_ciphers: list[str] = field(default_factory=list)
    comp_lzo: str = ""
    tls_auth: str = ""
    key_direction: str = ""
    tls_crypt: str = ""
    tls_crypt_v2: str = ""
    ping: int = 0
    ping_restart: int = 0


@dataclass(slots=True)
class Candidate:
    source: str
    source_family: str
    source_id: str
    country_code: str
    hostname: str
    endpoint_ip: str
    exit_ip: str
    profile: OpenVPNProfile
    ping_ms: float | None = None
    speed_mbps: float | None = None
    uptime_seconds: int | None = None
    sessions: int | None = None
    source_uptime_7d: float | None = None
    last_checked_at: str = ""
    technical_score: float | None = None
    handshake_ms: float | None = None
    https_first_byte_ms: float | None = None
    provenance: list[str] = field(default_factory=list)
    evidence_families: list[str] = field(default_factory=list)
    intel: dict[str, Any] = field(default_factory=dict)
    history: dict[str, float] = field(default_factory=dict)
    tcp_reachable: bool | None = None
    tcp_probe_ms: float | None = None
    selection_score: float = 0.0
    reject_reasons: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.provenance:
            self.provenance = [self.source]
        else:
            self.provenance = sorted(set(self.provenance))
        if not self.evidence_families:
            self.evidence_families = [self.source_family]
        else:
            self.evidence_families = sorted(set(self.evidence_families + [self.source_family]))

    @property
    def dedupe_key(self) -> str:
        return f"{self.endpoint_ip}:{self.profile.port}/{self.profile.proto}"

    @property
    def ip_for_intel(self) -> str:
        return self.exit_ip or self.endpoint_ip


def candidate_to_dict(c: Candidate) -> dict:
    from dataclasses import asdict
    return asdict(c)


def candidate_from_dict(d: dict) -> Candidate:
    d = dict(d)
    profile_data = dict(d.pop("profile"))
    profile_data.setdefault("ping", 0)
    profile_data.setdefault("ping_restart", 0)
    profile = OpenVPNProfile(**profile_data)
    d.setdefault("handshake_ms", None)
    d.setdefault("https_first_byte_ms", None)
    d.setdefault("evidence_families", [d.get("source_family", "")])
    return Candidate(profile=profile, **d)
