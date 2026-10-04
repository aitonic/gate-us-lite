from __future__ import annotations

import argparse
import concurrent.futures
import os
import sys
from pathlib import Path

from .config import load_config
from .intel import enrich
from .mihomo import render
from .probe import tcp_probe
from .select import merge_candidates, rough_rank, evaluate, choose
from .sources import vpngate, ipspeed, vpnbook, publicvpnlist, vpngate_scraper
from .store import Store

SOURCE_NAMES = ("vpngate", "ipspeed", "vpnbook", "publicvpnlist", "vpngate_scraper")


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def _fetch_one(name: str, cfg: dict):
    general = cfg["general"]
    country = general["country"].upper()
    timeout = int(general["timeout_seconds"])
    profile_timeout = int(general.get("profile_fetch_timeout_seconds", 8))
    secondary_limit = int(general.get("secondary_source_materialize_limit", 40))

    if name == "vpngate":
        return vpngate(country, timeout)
    if name == "ipspeed":
        return ipspeed(country, timeout, materialize_limit=secondary_limit, profile_timeout=profile_timeout)
    if name == "vpnbook":
        return vpnbook(
            country,
            timeout,
            host_limit=int(general.get("vpnbook_host_limit", 4)),
            profile_timeout=profile_timeout,
        )
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


def generate(config_path: str, state_path: str, output_path: str) -> int:
    cfg = load_config(config_path)
    store = Store(state_path)
    source_health: dict[str, dict] = {}
    observable_fresh = []
    generation_gathered = []
    try:
        enabled = [s for s in SOURCE_NAMES if cfg["sources"].get(s, False)]
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
                            cached = store.cached_candidates(name, max_age=86400)
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
                        cached = store.cached_candidates(name, max_age=86400)
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
                    cached = store.cached_candidates(name, max_age=86400)
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
        candidates = prelim[: int(cfg["general"].get("max_candidates_for_intel", 30))]

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
            )
            return c, data

        intel_workers = max(1, min(12, int(cfg["general"].get("intel_workers", 6))))
        with concurrent.futures.ThreadPoolExecutor(max_workers=intel_workers) as ex:
            futures = [ex.submit(fetch_intel, c) for c in uncached]
            for c, data in (f.result() for f in concurrent.futures.as_completed(futures)):
                store.put_intel(c.ip_for_intel, data)
                c.intel = data
                evaluate(c, filters)

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

        status = ", ".join(
            f"{k}={v.get('status')}:{v.get('count', 0)}+cache{v.get('cached', 0)}"
            for k, v in sorted(source_health.items())
        )
        log(f"[done] preferred={len(preferred)} fallback={len(fallback)} candidates={len(candidates)} fresh={len(fresh_merged)}")
        log(f"[sources] {status}")
        log(f"[output] {output}")
        return 0
    finally:
        store.close()


def main(argv=None):
    ap = argparse.ArgumentParser(description="Generate a multi-source US OpenVPN Mihomo YAML")
    ap.add_argument("--config", default="config.toml")
    ap.add_argument("--state", default=".state/state.sqlite3")
    ap.add_argument("--output", default="mihomo.yaml")
    args = ap.parse_args(argv)
    raise SystemExit(generate(args.config, args.state, args.output))
