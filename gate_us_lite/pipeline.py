from __future__ import annotations

import concurrent.futures
import os
from collections import Counter
from pathlib import Path

from .config import ConfigurationError
from .intel import enrich
from .log import log, tally
from .mihomo import render
from .models import Candidate
from .probe import tcp_probe
from .select import choose, evaluate, merge_candidates, rough_rank
from .sources import publicvpnlist, vpngate, vpngate_scraper
from .store import Store
from .tunnel import probe_tunnels

SOURCE_NAMES = ("vpngate", "publicvpnlist", "vpngate_scraper")
INTEL_PROVIDERS = ("ipwho", "proxycheck", "abuse")


def _fetch_one(name: str, cfg: dict):
    general = cfg["general"]
    country = general["country"].upper()
    timeout = int(general["timeout_seconds"])
    profile_timeout = int(general.get("profile_fetch_timeout_seconds", 8))
    secondary_limit = int(general.get("secondary_source_materialize_limit", 40))

    if name == "vpngate":
        return vpngate(country, timeout)
    if name == "publicvpnlist":
        return publicvpnlist(
            cfg["keys"].get("publicvpnlist", ""),
            country,
            timeout,
            materialize_limit=int(general.get("publicvpnlist_materialize_limit", 40)),
            fresh_within_seconds=int(general.get("publicvpnlist_fresh_within_seconds", 86400)),
            profile_timeout=profile_timeout,
        )
    if name == "vpngate_scraper":
        return vpngate_scraper(
            country,
            timeout,
            materialize_limit=secondary_limit,
            profile_timeout=profile_timeout,
        )
    return []


def _is_degraded(store: Store, source: str, count: int, cfg: dict) -> tuple[bool, float | None]:
    general = cfg["general"]
    baseline = store.source_baseline(source, int(general.get("source_baseline_window", 12)))
    minimum = float(general.get("source_low_watermark_min_baseline", 4))
    ratio = float(general.get("source_low_watermark_ratio", 0.40))
    degraded = bool(count > 0 and baseline is not None and baseline >= minimum and count < baseline * ratio)
    return degraded, baseline


def _apply_tcp_probes(candidates: list, store: Store, cfg: dict) -> None:
    limit = int(cfg["general"].get("tcp_probe_limit", 40))
    timeout = float(cfg["general"].get("tcp_probe_timeout_seconds", 2.0))
    pool = [c for c in candidates[:limit] if c.profile.proto == "tcp"]
    if not pool:
        return

    def one(c):
        reachable, latency = tcp_probe(c, timeout=timeout)
        return c, reachable, latency

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(6, len(pool))) as ex:
        futures = [ex.submit(one, c) for c in pool]
        for fut in concurrent.futures.as_completed(futures):
            c, reachable, latency = fut.result()
            c.tcp_reachable = reachable
            c.tcp_probe_ms = latency
    store.record_probes(pool)
    for c in pool:
        c.history.update(store.probe_history(c.dedupe_key))


def _gather_sources(cfg: dict, store: Store) -> tuple[dict[str, dict], list[Candidate], list[Candidate]]:
    """Fetch every enabled source independently; returns (health, fresh candidates, generation candidates)."""
    source_health: dict[str, dict] = {}
    observable_fresh: list[Candidate] = []
    generation_gathered: list[Candidate] = []
    enabled = [s for s in SOURCE_NAMES if cfg["sources"].get(s, False)]
    cache_max_age = int(cfg["general"]["source_cache_max_age_seconds"])
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(5, len(enabled) or 1)) as ex:
        futs = {ex.submit(_fetch_one, s, cfg): s for s in enabled}
        for fut in concurrent.futures.as_completed(futs):
            name = futs[fut]
            try:
                nodes = fut.result()
                if name == "publicvpnlist" and not cfg["keys"].get("publicvpnlist"):
                    source_health[name] = {"status": "skipped", "count": 0, "cached": 0}
                    log("[source] publicvpnlist: skipped (PUBLICVPNLIST_API_KEY not set)")
                    continue

                if nodes:
                    degraded, baseline = _is_degraded(store, name, len(nodes), cfg)
                    if degraded:
                        cached = store.cached_candidates(name, max_age=cache_max_age)
                        store.record_source(name, False, f"degraded snapshot: {len(nodes)} vs baseline {baseline:.1f}")
                        store.record_source_snapshot(name, len(nodes), "degraded")
                        generation_gathered.extend(nodes)
                        generation_gathered.extend(cached)
                        source_health[name] = {
                            "status": "degraded",
                            "count": len(nodes),
                            "cached": len(cached),
                            "baseline": baseline,
                        }
                        log(f"[source] {name}: degraded {len(nodes)} vs baseline={baseline:.1f}; last-good={len(cached)}")
                    else:
                        store.cache_candidates(name, nodes)
                        store.record_source(name, True, f"{len(nodes)} candidates")
                        store.record_source_snapshot(name, len(nodes), "ok")
                        observable_fresh.extend(nodes)
                        generation_gathered.extend(nodes)
                        source_health[name] = {"status": "ok", "count": len(nodes), "cached": 0}
                        log(f"[source] {name}: {len(nodes)} candidates")
                else:
                    cached = store.cached_candidates(name, max_age=cache_max_age)
                    store.record_source(name, False, "empty result")
                    store.record_source_snapshot(name, 0, "empty")
                    source_health[name] = {
                        "status": "empty",
                        "count": 0,
                        "cached": len(cached),
                    }
                    generation_gathered.extend(cached)
                    log(f"[source] {name}: empty; last-good={len(cached)}")
            except Exception as exc:
                cached = store.cached_candidates(name, max_age=cache_max_age)
                store.record_source(name, False, str(exc))
                store.record_source_snapshot(name, 0, "error")
                source_health[name] = {
                    "status": "error",
                    "count": 0,
                    "cached": len(cached),
                    "error": str(exc),
                }
                generation_gathered.extend(cached)
                log(f"[warn] {name}: {exc}; last-good={len(cached)}")
    return source_health, observable_fresh, generation_gathered


def collect(cfg: dict, store: Store) -> list[Candidate]:
    """Fetch, merge and pre-rank candidates; returns the best `tunnel_probe_limit` for tunnel probing."""
    source_health, observable_fresh, generation_gathered = _gather_sources(cfg, store)
    # Availability evidence is source-aware. Only raw candidates from an `ok`
    # adapter are observed; degraded/error/empty/cache-only sources do not enlarge
    # the denominator and cached nodes never become fake live observations.
    store.observe(
        observable_fresh,
        {name: data.get("status", "error") for name, data in source_health.items()},
    )
    fresh_merged = merge_candidates(observable_fresh)
    merged = merge_candidates(generation_gathered)
    for c in merged:
        c.history = store.history(c.dedupe_key)

    filters = cfg["filters"]
    prelim = []
    for c in merged:
        if c.ping_ms is not None and c.ping_ms > max(float(filters.get("max_ping_ms", 250)) * 2, 500):
            continue
        if c.speed_mbps is not None and c.speed_mbps < 0.05:
            continue
        prelim.append(c)
    prelim.sort(key=lambda c: (rough_rank(c), c.dedupe_key), reverse=True)

    # TCP connect is only a soft GitHub-runner signal. It happens before expensive
    # IP intelligence so repeatedly dead TCP endpoints are naturally deprioritized.
    _apply_tcp_probes(prelim, store, cfg)
    prelim.sort(key=lambda c: (rough_rank(c), c.dedupe_key), reverse=True)
    status = ", ".join(
        f"{k}={v.get('status')}:{v.get('count', 0)}+cache{v.get('cached', 0)}"
        for k, v in sorted(source_health.items())
    )
    log(f"[collect] sources: {status}; fresh={len(fresh_merged)} candidates={len(prelim)}")
    return prelim[: int(cfg["general"]["tunnel_probe_limit"])]


def probe_pool(pool: list[Candidate], cfg: dict) -> dict[str, str]:
    """dedupe_key -> observed exit IP for every candidate that carries traffic through a real tunnel."""
    alive, failed = probe_tunnels(pool, cfg["mihomo_bin"], float(cfg["general"]["tunnel_probe_timeout_seconds"]))
    reasons = tally(failed.values())
    log(f"[tunnel] probed={len(pool)} alive={len(alive)} failed={len(failed)}" + (f" ({reasons})" if reasons else ""))
    return alive


def _apply_verdicts(pool: list[Candidate], alive: dict[str, str]) -> list[Candidate]:
    survivors = [c for c in pool if c.dedupe_key in alive]
    for c in survivors:
        c.exit_ip = alive[c.dedupe_key]
    return survivors


def _log_intel_summary(candidates: list) -> None:
    if not candidates:
        return
    providers = Counter(f"{p}={c.intel.get(f'{p}_status', 'none')}" for c in candidates for p in INTEL_PROVIDERS)
    log("[intel] " + " ".join(f"{name}:{n}" for name, n in sorted(providers.items())))
    errors = tally(
        f"{p}: {str(c.intel[f'{p}_error']).rsplit(': ', 1)[-1]}"
        for c in candidates for p in INTEL_PROVIDERS if c.intel.get(f"{p}_error")
    )
    if errors:
        log("[intel] errors: " + errors)
    rejected = Counter(reason for c in candidates for reason in c.reject_reasons)
    if rejected:
        log("[select] rejected: " + " ".join(f"{reason}={n}" for reason, n in sorted(rejected.items())))


def _enrich(candidates: list[Candidate], cfg: dict, store: Store) -> None:
    filters = cfg["filters"]
    intel_ttl = int(cfg["general"].get("intel_cache_ttl_seconds", 86400))
    intel_error_ttl = int(cfg["general"].get("intel_error_cache_ttl_seconds", 900))
    uncached = []
    for c in candidates:
        cached = store.get_intel(c.ip_for_intel, ttl=intel_ttl, error_ttl=intel_error_ttl)
        if cached is not None:
            c.intel = cached
            evaluate(c, filters)
        else:
            uncached.append(c)

    def fetch_intel(c):
        general = cfg["general"]
        data = enrich(
            c.ip_for_intel,
            timeout=max(1, min(12, int(general.get("intel_request_timeout_seconds", 6)))),
            retries=max(0, min(1, int(general.get("intel_request_retries", 0)))),
            proxycheck_key=cfg["keys"].get("proxycheck", ""),
            abuseipdb_key=cfg["keys"].get("abuseipdb", ""),
            proxycheck_lookback_days=int(general.get("proxycheck_lookback_days", 30)),
        )
        return c, data

    intel_workers = max(1, min(12, int(cfg["general"].get("intel_workers", 6))))
    with concurrent.futures.ThreadPoolExecutor(max_workers=intel_workers) as ex:
        futures = [ex.submit(fetch_intel, c) for c in uncached]
        for c, data in (f.result() for f in concurrent.futures.as_completed(futures)):
            store.put_intel(c.ip_for_intel, data)
            c.intel = data
            evaluate(c, filters)


def _require_verdict_providers(cfg: dict) -> None:
    if cfg["filters"].get("require_known_intel", True) and not cfg["keys"].get("proxycheck"):
        raise ConfigurationError(
            "PROXYCHECK_API_KEY is not set, but filters.require_known_intel needs a ProxyCheck verdict "
            "for every exit address; set the key or relax the filter deliberately"
        )


def finish(cfg: dict, store: Store, pool: list[Candidate], alive: dict[str, str], output_path: str) -> int:
    """Enrich, select and render the pool candidates whose tunnel verdict is alive."""
    _require_verdict_providers(cfg)
    candidates = _apply_verdicts(pool, alive)[: int(cfg["general"].get("max_candidates_for_intel", 30))]
    _enrich(candidates, cfg, store)
    _log_intel_summary(candidates)
    previous = store.get_selection()
    preferred, fallback = choose(candidates, cfg, previous)
    if not preferred and not fallback:
        log("[error] no acceptable US OpenVPN nodes; keeping the previously committed mihomo.yaml unchanged")
        return 2

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    tmp = output.with_name(output.name + ".tmp")
    tmp.write_text(render(preferred, fallback), encoding="utf-8")
    os.replace(tmp, output)
    store.put_selection(preferred, fallback)
    try:
        output.chmod(0o644)
    except OSError:
        pass
    log(f"[done] preferred={len(preferred)} fallback={len(fallback)} candidates={len(candidates)}")
    log(f"[output] {output}")
    return 0


def run(cfg: dict, store: Store, output_path: str) -> int:
    _require_verdict_providers(cfg)
    pool = collect(cfg, store)
    return finish(cfg, store, pool, probe_pool(pool, cfg), output_path)
