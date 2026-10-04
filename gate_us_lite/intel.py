from __future__ import annotations

import ipaddress
import re
import urllib.parse
from .http import fetch

INTEL_SCHEMA = 2

HOSTING_WORDS = {
    "amazon", "aws", "google cloud", "microsoft", "azure", "digitalocean", "vultr", "linode",
    "akamai", "ovh", "hetzner", "cloudflare", "choopa", "leaseweb", "datacenter", "data center",
    "hosting", "colo", "oracle cloud",
}
RESIDENTIAL_WORDS = {
    "fiber", "fibre", "cable", "broadband", "telecom", "communications", "comcast", "spectrum",
    "charter", "frontier", "cox", "sonic", "allo", "centurylink", "lumen", "verizon", "at&t",
}


def is_public_ip(ip: str) -> bool:
    try:
        obj = ipaddress.ip_address(ip)
        return obj.is_global
    except ValueError:
        return False


def _ipwho(ip: str, timeout: int, retries: int = 0) -> dict:
    p = fetch(
        f"https://ipwho.is/{urllib.parse.quote(ip)}",
        timeout=timeout, retries=retries, max_bytes=500_000,
    ).json()
    if not p.get("success", True):
        raise RuntimeError(p.get("message") or "ipwho.is failed")
    conn = p.get("connection") or {}
    sec = p.get("security") or {}
    return {
        "country_code": (p.get("country_code") or "").upper(),
        "asn": conn.get("asn") or "",
        "isp": conn.get("isp") or "",
        "org": conn.get("org") or "",
        "domain": conn.get("domain") or "",
        "proxy": bool(sec.get("proxy")),
        "vpn": bool(sec.get("vpn")),
        "tor": bool(sec.get("tor")),
        "hosting": bool(sec.get("hosting")),
    }


def _proxycheck(ip: str, key: str, timeout: int, retries: int = 0) -> dict:
    q = urllib.parse.urlencode({"key": key, "vpn": "1", "risk": "1", "asn": "1"})
    p = fetch(
        f"https://proxycheck.io/v2/{urllib.parse.quote(ip)}?{q}",
        timeout=timeout, retries=retries,
        max_bytes=500_000,
    ).json()
    r = p.get(ip) or {}
    typ = (r.get("type") or "").lower()
    return {
        "proxycheck_proxy": str(r.get("proxy", "")).lower() == "yes",
        "proxycheck_type": typ,
        "proxycheck_risk": _num(r.get("risk")),
        "residential_proxy": "residential" in typ and "proxy" in typ,
    }


def _abuse(ip: str, key: str, timeout: int, retries: int = 0) -> dict:
    url = "https://api.abuseipdb.com/api/v2/check?" + urllib.parse.urlencode(
        {"ipAddress": ip, "maxAgeInDays": 30, "verbose": ""}
    )
    p = fetch(
        url,
        headers={"Key": key, "Accept": "application/json"},
        timeout=timeout, retries=retries,
        max_bytes=500_000,
    ).json().get("data") or {}
    return {
        "abuse_confidence": _num(p.get("abuseConfidenceScore")),
        "abuse_reports_30d": int(p.get("totalReports") or 0),
        "abuse_last_reported": p.get("lastReportedAt") or "",
    }


def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _contains_keyword(text: str, words: set[str]) -> bool:
    """Match provider keywords as tokens/phrases, not arbitrary substrings.

    In particular, `colo` must not match `Colorado`.
    """
    text = text.lower()
    for word in words:
        pat = rf"(?<![a-z0-9]){re.escape(word.lower())}(?![a-z0-9])"
        if re.search(pat, text):
            return True
    return False


def enrich(
    ip: str, *, timeout: int = 10, retries: int = 0,
    proxycheck_key: str = "", abuseipdb_key: str = ""
) -> dict:
    if not is_public_ip(ip):
        return {
            "intel_schema": INTEL_SCHEMA,
            "invalid_ip": True,
            "ipwho_status": "invalid",
            "proxycheck_status": "disabled" if not proxycheck_key else "skipped",
            "abuse_status": "disabled" if not abuseipdb_key else "skipped",
            "hosting_known": False,
        }

    out = {
        "intel_schema": INTEL_SCHEMA,
        "invalid_ip": False,
        "ipwho_status": "unknown",
        "proxycheck_status": "disabled" if not proxycheck_key else "unknown",
        "abuse_status": "disabled" if not abuseipdb_key else "unknown",
    }

    try:
        out.update(_ipwho(ip, timeout, retries))
        out["ipwho_status"] = "ok"
    except Exception as exc:
        out["ipwho_status"] = "error"
        out["ipwho_error"] = str(exc)

    if proxycheck_key:
        try:
            out.update(_proxycheck(ip, proxycheck_key, timeout, retries))
            out["proxycheck_status"] = "ok"
        except Exception as exc:
            out["proxycheck_status"] = "error"
            out["proxycheck_error"] = str(exc)

    if abuseipdb_key:
        try:
            out.update(_abuse(ip, abuseipdb_key, timeout, retries))
            out["abuse_status"] = "ok"
        except Exception as exc:
            out["abuse_status"] = "error"
            out["abuse_error"] = str(exc)

    text = " ".join(str(out.get(k) or "") for k in ("isp", "org", "domain")).lower()
    if text and _contains_keyword(text, HOSTING_WORDS):
        out["hosting_heuristic"] = True
    if text and _contains_keyword(text, RESIDENTIAL_WORDS):
        out["fixed_isp_heuristic"] = True

    # `hosting=False` is meaningful only when the provider actually answered. If
    # ipwho failed and no positive heuristic exists, hosting status stays unknown.
    out["hosting_known"] = out.get("ipwho_status") == "ok" or bool(out.get("hosting_heuristic"))

    asn = str(out.get("asn") or "")
    out["asn_key"] = asn or text[:80] or ip
    return out
