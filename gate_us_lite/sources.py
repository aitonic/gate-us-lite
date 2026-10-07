from __future__ import annotations

import base64
import csv
import math
import re
import socket
import urllib.parse

from .http import FetchError, fetch
from .log import tally
from .models import Candidate
from .ovpn import parse_ovpn

VPNGATE_URL = "https://www.vpngate.net/api/iphone/"
SCRAPER_README = "https://raw.githubusercontent.com/fdciabdul/Vpngate-Scraper-API/main/README.md"
SCRAPER_BASE = "https://raw.githubusercontent.com/fdciabdul/Vpngate-Scraper-API/main/"
PVL_API = "https://publicvpnlist.com/api/v1/servers"
PVL_HOST = urllib.parse.urlsplit(PVL_API).hostname


def _ip(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except OSError:
        return host


def _int(v, default=None):
    try:
        return int(v)
    except (ValueError, TypeError):
        return default


def _float(v, default=None):
    try:
        return float(v)
    except (ValueError, TypeError):
        return default


def _decode_ovpn_b64(value: str) -> str:
    """Decode a VPNGate profile candidate and reject obvious non-OVPN payloads."""
    raw = re.sub(r"\s+", "", value or "")
    if len(raw) < 64:
        raise ValueError("base64 payload too short")
    raw += "=" * ((4 - len(raw) % 4) % 4)
    data = base64.b64decode(raw, validate=True)
    text = data.decode("utf-8", errors="replace")
    low = text.lower()
    if "<ca>" not in low or not re.search(r"(?mi)^\s*remote\s+\S+\s+\d+", text):
        raise ValueError("decoded payload does not look like OpenVPN")
    if not (re.search(r"(?mi)^\s*client\b", text) or re.search(r"(?mi)^\s*dev\s+", text)):
        raise ValueError("decoded payload lacks OpenVPN client markers")
    return text


def _vpngate_profile_text(header: list[str], row: list[str]) -> str:
    """Prefer the named field, then tolerate a VPNGate CSV column-layout change.

    CFNext has historically needed this kind of fallback when VPNGate changed its
    CSV layout. Only the final three columns are considered, and the decoded value
    still has to look like an OpenVPN client profile before our safe parser sees it.
    """
    named = ""
    try:
        idx = header.index("OpenVPN_ConfigData_Base64")
        if idx < len(row):
            named = row[idx]
    except ValueError:
        pass
    if named:
        try:
            return _decode_ovpn_b64(named)
        except Exception:
            pass
    for value in reversed(row[-3:]):
        if not value or value == named:
            continue
        try:
            return _decode_ovpn_b64(value)
        except Exception:
            continue
    raise ValueError("OpenVPN_ConfigData_Base64 not found")


def vpngate(country: str = "US", timeout: int = 20) -> list[Candidate]:
    text = fetch(VPNGATE_URL, timeout=timeout, retries=1).text()
    lines = text.splitlines()
    header_i = next(i for i, line in enumerate(lines) if "HostName" in line and "," in line)
    reader = csv.reader(lines[header_i:])
    header = [x.strip() for x in next(reader)]
    if header:
        header[0] = header[0].lstrip("#")
    out: list[Candidate] = []
    for row in reader:
        if not row or (row[0].strip().startswith("#") if row else False):
            continue
        r = {header[i]: row[i] for i in range(min(len(header), len(row)))}
        if (r.get("CountryShort") or "").upper() != country:
            continue
        try:
            text_conf = _vpngate_profile_text(header, row)
            p = parse_ovpn(text_conf, fallback_server=r.get("IP") or "", username="vpn", password="vpn")
        except Exception:
            continue
        out.append(Candidate(
            source="vpngate",
            source_family="vpngate",
            source_id=r.get("HostName") or r.get("IP") or p.server,
            country_code=country,
            hostname=r.get("HostName") or "",
            endpoint_ip=r.get("IP") or _ip(p.server),
            exit_ip=r.get("IP") or "",
            profile=p,
            ping_ms=_float(r.get("Ping")),
            speed_mbps=(_float(r.get("Speed"), 0) or 0) / 1_000_000,
            uptime_seconds=(_int(r.get("Uptime"), 0) or 0) // 1000,
            sessions=_int(r.get("NumVpnSessions")),
            provenance=["vpngate"],
        ))
    return out


def _pvl_source_family(r: dict) -> tuple[str, str]:
    raw = r.get("source") or r.get("source_name") or "publicvpnlist"
    if isinstance(raw, dict):
        raw = raw.get("name") or raw.get("slug") or raw.get("id") or "publicvpnlist"
    src = str(raw).lower()
    compact = re.sub(r"[^a-z0-9]", "", src)
    if "vpngate" in compact:
        family = "vpngate"
    elif "ipspeed" in compact:
        family = "ipspeed"
    else:
        family = src or "publicvpnlist"
    return src, family


def _is_publicvpnlist(url: str) -> bool:
    host = urllib.parse.urlsplit(url).hostname or ""
    return host == PVL_HOST or host.endswith("." + PVL_HOST)


def _failure_reason(exc: Exception) -> str:
    return exc.reason if isinstance(exc, FetchError) else str(exc) or type(exc).__name__


def _pvl_meta_rank(r: dict) -> float:
    tech = _float(r.get("technical_quality_score") or r.get("score"), 0) or 0
    uptime = _float(r.get("uptime_percent_7d"), 0) or 0
    speed = _float(r.get("speed_mbps") or r.get("checker_measured_throughput_mbps"), 0) or 0
    latency = _float(r.get("latency_ms") or r.get("checker_measured_tunnel_rtt_ms"), 999) or 999
    return tech * 0.45 + uptime * 0.35 + min(20.0, math.log1p(max(0.0, speed)) * 5) - min(20.0, latency / 20.0)


def publicvpnlist(
    api_key: str,
    country: str = "US",
    timeout: int = 20,
    limit: int = 200,
    materialize_limit: int = 40,
    fresh_within_seconds: int = 86400,
    profile_timeout: int = 8,
) -> list[Candidate]:
    if not api_key:
        return []
    q = urllib.parse.urlencode({
        "protocol": "openvpn",
        "status": "online",
        "country": country,
        "sort": "score",
        "order": "desc",
        "per_page": min(200, limit),
        "fresh_within": max(1, min(259200, int(fresh_within_seconds))),
    })
    headers = {"Authorization": f"Bearer {api_key}", "Accept": "application/json"}
    payload = fetch(PVL_API + "?" + q, headers=headers, timeout=timeout, retries=1, max_bytes=4_000_000).json()

    records = payload.get("data", [])
    rows = [r for r in records if r.get("config_download_url")]
    rows.sort(key=_pvl_meta_rank, reverse=True)
    selected: list[tuple[dict, str, str]] = []
    seen_meta: set[tuple[str, str]] = set()
    for r in rows:
        src, family = _pvl_source_family(r)
        endpoint_hint = str(r.get("ip") or r.get("hostname") or r.get("id") or "")
        key = (family, endpoint_hint)
        if key in seen_meta:
            continue
        seen_meta.add(key)
        selected.append((r, src, family))
        if len(selected) >= max(1, int(materialize_limit)):
            break

    out: list[Candidate] = []
    failures: list[str] = []
    for r, src, family in selected:
        cfg_url = r.get("config_download_url")
        user = "vpn" if family in {"vpngate", "ipspeed"} else ""
        password = "vpn" if user else ""
        try:
            # Download links come from the API response; the key is only ever sent to PublicVPNList itself.
            conf = fetch(
                cfg_url, headers=headers if _is_publicvpnlist(cfg_url) else None,
                timeout=min(timeout, profile_timeout), retries=0, max_bytes=1_000_000,
            ).text()
            p = parse_ovpn(conf, fallback_server=r.get("ip") or "", username=user, password=password)
        except Exception as exc:
            failures.append(_failure_reason(exc))
            continue
        if not (p.cert and p.key) and not p.username:
            failures.append("profile without credentials")
            continue
        out.append(Candidate(
            source="publicvpnlist",
            source_family=family or "publicvpnlist",
            source_id=str(r.get("id") or p.server),
            country_code=country,
            hostname=r.get("hostname") or p.server,
            endpoint_ip=r.get("ip") or _ip(p.server),
            exit_ip=r.get("exit_ip") or "",
            profile=p,
            ping_ms=_float(r.get("latency_ms") or r.get("checker_measured_tunnel_rtt_ms")),
            speed_mbps=_float(r.get("speed_mbps") or r.get("checker_measured_throughput_mbps")),
            sessions=_int(r.get("sessions")),
            source_uptime_7d=_float(r.get("uptime_percent_7d")),
            last_checked_at=r.get("last_checked_at") or "",
            technical_score=_float(r.get("technical_quality_score")),
            handshake_ms=_float(r.get("handshake_ms")),
            https_first_byte_ms=_float(r.get("https_first_byte_ms")),
            provenance=[f"publicvpnlist:{src}"],
        ))
    if records and not out:
        reasons = tally(failures)
        raise RuntimeError(
            f"{len(records)} records, {len(rows)} with a download link, 0 usable profiles"
            + (f" ({reasons})" if reasons else "")
        )
    return out


def vpngate_scraper(
    country: str = "US",
    timeout: int = 20,
    materialize_limit: int = 40,
    profile_timeout: int = 8,
) -> list[Candidate]:
    readme = fetch(SCRAPER_README, timeout=timeout, retries=1, max_bytes=2_000_000).text()
    out: list[Candidate] = []
    row_re = re.compile(r"^\|\s*([^|]+)\|\s*((?:\d{1,3}\.){3}\d{1,3})\s*\|\s*([^|]+)\|\s*([0-9.]+)\s*Mbps\s*\|\s*([^|]+)\|\s*\[[^\]]+\]\(([^)]+\.ovpn)\)\s*\|", re.M)
    considered = 0
    for m in row_re.finditer(readme):
        hostname, ip, ping_s, speed_s, country_name, path = [x.strip() for x in m.groups()]
        if country == "US" and country_name.lower() not in {"united states", "usa", "us"}:
            continue
        if considered >= max(1, int(materialize_limit)):
            break
        considered += 1
        url = urllib.parse.urljoin(SCRAPER_BASE, path.replace("./", ""))
        try:
            conf = fetch(url, timeout=min(timeout, profile_timeout), retries=0, max_bytes=1_000_000).text()
            p = parse_ovpn(conf, fallback_server=ip, username="vpn", password="vpn")
        except Exception:
            continue
        out.append(Candidate(
            source="vpngate_scraper",
            source_family="vpngate",
            source_id=hostname,
            country_code=country,
            hostname=hostname,
            endpoint_ip=ip,
            exit_ip=ip,
            profile=p,
            ping_ms=_float(ping_s),
            speed_mbps=_float(speed_s),
            provenance=["vpngate_scraper"],
        ))
    return out
