from __future__ import annotations

import os
import tomllib
from pathlib import Path

DEFAULTS = {
    "general": {
        "country": "US",
        "preferred_limit": 3,
        "fallback_limit": 8,
        "timeout_seconds": 20,
        "max_candidates_for_intel": 30,
        "publicvpnlist_materialize_limit": 40,
        "publicvpnlist_fresh_within_seconds": 86400,
        "secondary_source_materialize_limit": 40,
        "profile_fetch_timeout_seconds": 8,
        "intel_cache_ttl_seconds": 86400,
        "intel_error_cache_ttl_seconds": 900,
        "intel_request_timeout_seconds": 6,
        "intel_request_retries": 0,
        "intel_workers": 6,
        "proxycheck_lookback_days": 30,
        "tcp_probe_limit": 40,
        "tcp_probe_timeout_seconds": 2.0,
        "tunnel_probe_limit": 60,
        "tunnel_probe_timeout_seconds": 15,
        "source_cache_max_age_seconds": 345600,
        "source_baseline_window": 12,
        "source_low_watermark_ratio": 0.40,
        "source_low_watermark_min_baseline": 4,
    },
    "filters": {
        "max_ping_ms": 250,
        "min_speed_mbps": 0.5,
        "reject_hosting": False,
        "reject_tor": True,
        "reject_compromised": True,
        "reject_proxy": False,
        "reject_residential_proxy": True,
        "reject_country_mismatch": True,
        "require_known_intel": True,
        "max_proxycheck_risk": 100,
        "min_preferred_availability_24h": 0.25,
        "max_preferred_tcp_fail_streak": 2,
    },
    "sources": {
        "vpngate": True,
        "publicvpnlist": True,
        "vpngate_scraper": True,
    },
}


class ConfigurationError(Exception):
    """The configuration or environment cannot produce a trustworthy publication."""


def _deep_merge(dst: dict, src: dict) -> dict:
    for k, v in src.items():
        if isinstance(v, dict) and isinstance(dst.get(k), dict):
            _deep_merge(dst[k], v)
        else:
            dst[k] = v
    return dst


def load_config(path: str | Path) -> dict:
    import copy
    cfg = copy.deepcopy(DEFAULTS)
    p = Path(path)
    if p.exists():
        with p.open("rb") as f:
            _deep_merge(cfg, tomllib.load(f))
    cfg["keys"] = {
        "publicvpnlist": os.getenv("PUBLICVPNLIST_API_KEY", ""),
        "abuseipdb": os.getenv("ABUSEIPDB_API_KEY", ""),
        "proxycheck": os.getenv("PROXYCHECK_API_KEY", ""),
    }
    cfg["mihomo_bin"] = os.getenv("MIHOMO_BIN", "mihomo")
    return cfg
