from __future__ import annotations

import ipaddress
import re
import urllib.parse
from .http import fetch

INTEL_SCHEMA = 4

ABUSE_HOSTING_USAGE = "Data Center/Web Hosting/Transit"
PROXYCHECK_FLAGS = ("tor", "hosting", "anonymous")

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


def intel_known(intel: dict) -> bool:
    """True when both providers behind the selection verdicts answered for the address."""
    return intel.get("ipwho_status") == "ok" and intel.get("proxycheck_status") == "ok"


def _ipwho(ip: str, timeout: int, retries: int = 0) -> dict:
    p = fetch(
        f"https://ipwho.is/{urllib.parse.quote(ip)}",
        timeout=timeout, retries=retries, max_bytes=500_000,
    ).json()
    if not p.get("success", True):
        raise RuntimeError(p.get("message") or "ipwho.is failed")
    conn = p.get("connection") or {}
    return {
        "country_code": (p.get("country_code") or "").upper(),
        "asn": conn.get("asn") or "",
        "isp": conn.get("isp") or "",
        "org": conn.get("org") or "",
        "domain": conn.get("domain") or "",
    }


def _proxycheck(ip: str, key: str, timeout: int, retries: int = 0, lookback_days: int = 0) -> dict:
    """`lookback_days` widens how long ProxyCheck remembers a detection; 0 keeps its default window."""
    params = {"key": key, **({"days": lookback_days} if lookback_days else {})}
    p = fetch(
        f"https://proxycheck.io/v3/{urllib.parse.quote(ip)}?{urllib.parse.urlencode(params)}",
        timeout=timeout, retries=retries,
        max_bytes=500_000,
    ).json()
    if p.get("status") not in ("ok", "warning"):
        raise RuntimeError(p.get("message") or f"proxycheck status {p.get('status')}")
    record = p.get(ip)
    if not isinstance(record, dict):
        raise RuntimeError("proxycheck returned no result for the address")
    # A missing or null detection is "no data", never "clean": an incomplete verdict is an error.
    detections = record.get("detections")
    detections = detections if isinstance(detections, dict) else {}
    risk = _num(detections.get("risk"))
    if risk is None or not all(isinstance(detections.get(flag), bool) for flag in PROXYCHECK_FLAGS):
        raise RuntimeError("proxycheck result lacks a complete verdict")
    services = (record.get("operator") or {}).get("services") or []
    return {
        "tor": detections["tor"],
        "hosting": detections["hosting"] or (record.get("network") or {}).get("type") == "Hosting",
        "proxycheck_proxy": detections["anonymous"],
        "proxycheck_risk": risk,
        "residential_proxy": "residential_proxies" in services,
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
        "abuse_usage_type": p.get("usageType") or "",
        "abuse_tor": bool(p.get("isTor")),
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
    proxycheck_key: str = "", abuseipdb_key: str = "", proxycheck_lookback_days: int = 0
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
            out.update(_proxycheck(ip, proxycheck_key, timeout, retries, proxycheck_lookback_days))
            out["proxycheck_status"] = "ok"
        except Exception as exc:
            out["proxycheck_status"] = "error"
            out["proxycheck_error"] = str(exc)

    if abuseipdb_key:
        try:
            out.update(_abuse(ip, abuseipdb_key, timeout, retries))
            out["abuse_status"] = "ok"
            # A hosting or Tor verdict from either provider stands; the other one's silence never overrules it.
            out["hosting"] = bool(out.get("hosting")) or out.get("abuse_usage_type") == ABUSE_HOSTING_USAGE
            out["tor"] = bool(out.get("tor")) or bool(out.get("abuse_tor"))
        except Exception as exc:
            out["abuse_status"] = "error"
            out["abuse_error"] = str(exc)

    text = " ".join(str(out.get(k) or "") for k in ("isp", "org", "domain")).lower()
    if text and _contains_keyword(text, HOSTING_WORDS):
        out["hosting_heuristic"] = True
    if text and _contains_keyword(text, RESIDENTIAL_WORDS):
        out["fixed_isp_heuristic"] = True

    # `hosting=False` is meaningful only when ProxyCheck evaluated the address.
    # ipwho's free tier carries no hosting verdict, so without ProxyCheck the status
    # stays unknown unless the keyword heuristic matched.
    out["hosting_known"] = out["proxycheck_status"] == "ok" or bool(out.get("hosting_heuristic"))

    asn = str(out.get("asn") or "")
    out["asn_key"] = asn or text[:80] or ip
    return out
