from __future__ import annotations

import math
from datetime import datetime, timezone
from .models import Candidate

# Profile authority is explicit so merge output does not depend on thread completion order.
SOURCE_PROFILE_PRIORITY = {
    "publicvpnlist": 50,
    "vpngate": 40,
    "vpnbook": 35,
    "ipspeed": 30,
    "vpngate_scraper": 20,
}


def _profile_completeness(c: Candidate) -> int:
    p = c.profile
    return sum(bool(x) for x in (p.ca, p.cert and p.key, p.username, p.tls_auth, p.tls_crypt, p.tls_crypt_v2))


def _canonical_key(c: Candidate) -> tuple:
    return (
        SOURCE_PROFILE_PRIORITY.get(c.source, 0),
        _profile_completeness(c),
        c.technical_score if c.technical_score is not None else -1.0,
        c.last_checked_at or "",
        c.source,
        c.source_id,
    )


def merge_candidates(items: list[Candidate]) -> list[Candidate]:
    grouped: dict[str, list[Candidate]] = {}
    for c in items:
        grouped.setdefault(c.dedupe_key, []).append(c)

    merged: list[Candidate] = []
    for key in sorted(grouped):
        group = grouped[key]
        canonical = max(group, key=_canonical_key)
        ranked = sorted(group, key=_canonical_key, reverse=True)

        canonical.provenance = sorted({p for c in group for p in (c.provenance + [c.source]) if p})
        canonical.evidence_families = sorted({f for c in group for f in (c.evidence_families + [c.source_family]) if f})

        exit_candidate = next((c for c in ranked if c.exit_ip), None)
        if exit_candidate:
            canonical.exit_ip = exit_candidate.exit_ip

        for attr in ("speed_mbps", "source_uptime_7d", "technical_score", "handshake_ms", "https_first_byte_ms"):
            values = [getattr(c, attr) for c in group if getattr(c, attr) is not None]
            if not values:
                continue
            if attr in {"handshake_ms", "https_first_byte_ms"}:
                setattr(canonical, attr, min(values))
            else:
                setattr(canonical, attr, max(values))

        pings = [c.ping_ms for c in group if c.ping_ms is not None]
        if pings:
            canonical.ping_ms = min(pings)
        uptimes = [c.uptime_seconds for c in group if c.uptime_seconds is not None]
        if uptimes:
            canonical.uptime_seconds = max(uptimes)
        sessions = [c.sessions for c in group if c.sessions is not None]
        if sessions:
            canonical.sessions = max(sessions)
        checked = [c.last_checked_at for c in group if c.last_checked_at]
        if checked:
            canonical.last_checked_at = max(checked)

        reachability = [c.tcp_reachable for c in group if c.tcp_reachable is not None]
        if any(v is True for v in reachability):
            canonical.tcp_reachable = True
            lats = [c.tcp_probe_ms for c in group if c.tcp_reachable is True and c.tcp_probe_ms is not None]
            canonical.tcp_probe_ms = min(lats) if lats else None
        elif reachability:
            canonical.tcp_reachable = False
            canonical.tcp_probe_ms = None

        merged.append(canonical)
    return merged


def _checked_age_seconds(value: str) -> float | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return max(0.0, (datetime.now(timezone.utc) - dt.astimezone(timezone.utc)).total_seconds())
    except (TypeError, ValueError):
        return None


def rough_rank(c: Candidate) -> float:
    score = 0.0
    families = set(c.evidence_families or [c.source_family])
    if families.intersection({"vpnbook", "ipspeed"}):
        score += 6
    if c.technical_score is not None:
        score += min(12, max(0.0, c.technical_score) * 0.12)
    if c.source_uptime_7d is not None:
        score += min(20, c.source_uptime_7d / 5)
    if c.uptime_seconds:
        score += min(12, math.log1p(c.uptime_seconds / 3600) * 2)
    if c.speed_mbps is not None:
        score += min(15, math.log1p(max(0, c.speed_mbps)) * 4)
    if c.ping_ms is not None:
        score += max(0, 12 - min(12, c.ping_ms / 20))
    if c.handshake_ms is not None:
        score += max(0, 4 - min(4, c.handshake_ms / 250))
    if c.https_first_byte_ms is not None:
        score += max(0, 3 - min(3, c.https_first_byte_ms / 350))

    age = _checked_age_seconds(c.last_checked_at)
    if age is not None:
        if age <= 3600:
            score += 5
        elif age <= 21600:
            score += 3
        elif age <= 86400:
            score += 1
        elif age > 259200:
            score -= 4

    if c.tcp_reachable is True:
        score += 5
        if c.tcp_probe_ms is not None:
            score += max(0, 3 - min(3, c.tcp_probe_ms / 100))
    elif c.tcp_reachable is False and c.profile.proto == "tcp":
        score -= 7
    return score


def _ipwho_known(i: dict) -> bool:
    status = i.get("ipwho_status")
    if status is not None:
        return status == "ok"
    # Compatibility for test fixtures and any pre-v0.4 in-memory payload.
    return bool(i.get("country_code") or i.get("asn") or i.get("isp") or i.get("org"))


def _hosting_known(i: dict) -> bool:
    if "hosting_known" in i:
        return bool(i.get("hosting_known"))
    return _ipwho_known(i) or bool(i.get("hosting_heuristic"))


def evaluate(c: Candidate, filters: dict) -> Candidate:
    i = c.intel
    h = c.history
    reasons: list[str] = []
    if i.get("invalid_ip"):
        reasons.append("invalid_ip")
    if filters.get("reject_country_mismatch", True) and i.get("country_code") and i.get("country_code") != c.country_code:
        reasons.append("country_mismatch")
    if filters.get("reject_tor", True) and i.get("tor"):
        reasons.append("tor")
    if filters.get("reject_residential_proxy", True) and i.get("residential_proxy"):
        reasons.append("residential_proxy")
    abuse = i.get("abuse_confidence")
    if abuse is not None and abuse >= 80:
        reasons.append("severe_recent_abuse")
    c.reject_reasons = reasons

    score = rough_rank(c)
    a24 = h.get("availability_24h", 0.0)
    a7 = h.get("availability_7d", 0.0)
    score += 25 * a24 + 20 * a7
    if i.get("fixed_isp_heuristic"):
        score += 15

    hosting_known = _hosting_known(i)
    if hosting_known and not i.get("hosting") and not i.get("hosting_heuristic"):
        score += 8
    elif i.get("hosting") or i.get("hosting_heuristic"):
        score -= 18
    else:
        # Unknown is not equivalent to clean. Keep it usable as fallback, but do not
        # grant the clean residential/fixed-ISP bonus.
        score -= 6

    if i.get("proxycheck_proxy"):
        score -= 10
    risk = i.get("proxycheck_risk")
    if risk is not None:
        score -= min(15, risk * 0.15)
    if abuse is not None:
        score -= min(20, abuse * 0.2)

    # Independent evidence is counted by source family, not provenance/mirror count.
    family_count = len(set(c.evidence_families or [c.source_family]))
    if family_count > 1:
        score += min(5, family_count - 1)

    fail_streak = int(h.get("tcp_fail_streak", 0) or 0)
    if fail_streak:
        score -= min(12, fail_streak * 4)
    c.selection_score = round(score, 3)
    return c


def _preferred_ok(c: Candidate, filters: dict) -> bool:
    if c.reject_reasons:
        return False
    i = c.intel
    if filters.get("require_ipwho_for_preferred", True) and not _ipwho_known(i):
        return False
    if filters.get("reject_hosting", True) and (i.get("hosting") or i.get("hosting_heuristic")):
        return False
    if filters.get("reject_proxy", False) and i.get("proxycheck_proxy"):
        return False
    if c.ping_ms is not None and c.ping_ms > float(filters.get("max_ping_ms", 250)):
        return False
    if c.speed_mbps is not None and c.speed_mbps < float(filters.get("min_speed_mbps", 0.5)):
        return False
    if c.history.get("seen_24h", 0) >= 2 and c.history.get("availability_24h", 0) < float(filters.get("min_preferred_availability_24h", 0.25)):
        return False
    if c.profile.proto == "tcp" and int(c.history.get("tcp_fail_streak", 0) or 0) >= int(filters.get("max_preferred_tcp_fail_streak", 2)):
        return False
    return True


def choose(candidates: list[Candidate], cfg: dict, previous: dict | None = None) -> tuple[list[Candidate], list[Candidate]]:
    general = cfg["general"]
    filters = cfg["filters"]
    ranked = sorted(candidates, key=lambda c: (c.selection_score, c.dedupe_key), reverse=True)
    eligible = [c for c in ranked if _preferred_ok(c, filters)]
    p_limit = int(general.get("preferred_limit", 3))
    f_limit = int(general.get("fallback_limit", 8))
    preferred: list[Candidate] = []
    used_asn: set[str] = set()
    prev_primary = (previous or {}).get("preferred", [None])[0] if (previous or {}).get("preferred") else None
    if prev_primary:
        sticky = next((c for c in eligible if c.dedupe_key == prev_primary), None)
        if sticky:
            preferred.append(sticky)
            used_asn.add(sticky.intel.get("asn_key") or sticky.ip_for_intel)
    for c in eligible:
        if c in preferred:
            continue
        asn = c.intel.get("asn_key") or c.ip_for_intel
        if asn in used_asn:
            continue
        preferred.append(c)
        used_asn.add(asn)
        if len(preferred) >= p_limit:
            break
    for c in eligible:
        if len(preferred) >= p_limit:
            break
        if c not in preferred:
            preferred.append(c)

    selected_keys = {c.dedupe_key for c in preferred}
    fallback: list[Candidate] = []
    for c in ranked:
        if c.dedupe_key in selected_keys or c.reject_reasons:
            continue
        fallback.append(c)
        if len(fallback) >= f_limit:
            break
    return preferred, fallback
