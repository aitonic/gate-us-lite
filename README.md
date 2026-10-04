# gate-us-lite

A lightweight **GitHub Actions-only** generator for a curated US OpenVPN list in Mihomo YAML format.

There is no local service, daemon, systemd timer, Docker stack, HTTP/SOCKS proxy, or deployment step. GitHub Actions fetches and evaluates the sources, keeps its small selector history in the Actions cache, and commits only the generated `mihomo.yaml` when the effective configuration changes.

## Pipeline

```text
VPN Gate ---------\
IPSpeed -----------+--> source snapshot gate --> metadata pre-filter
VPNBook -----------+             |                        |
PublicVPNList -----+             +--> last-good cache     v
VPNGate Scraper ---/                                safe OVPN parse
                                                        |
                                                  TCP soft probe
                                                        |
                                               IP quality + history
                                                        |
                                                        v
                                              preferred + fallback
                                                        |
                                                        v
                                                  mihomo.yaml
```

The workflow runs every 30 minutes at minute `7` and `37`, and can also be started manually with **Actions -> Generate Mihomo US VPN list -> Run workflow**.

## Output

The only generated repository file is:

```text
mihomo.yaml
```

It contains:

- up to 3 `US-Pxx-*` preferred OpenVPN nodes;
- up to 8 `US-Bxx-*` fallback nodes;
- `US-PREFERRED`, a fallback group containing the preferred set;
- `US-STABLE`, the recommended fallback group containing preferred nodes first and then fallback nodes.

`US-STABLE` uses Mihomo `fallback`, so it keeps the first healthy node instead of constantly changing IP for small latency differences.

The generator intentionally omits timestamps and changing quality scores from the YAML. Therefore the workflow only commits when the effective Mihomo configuration actually changes.

## Data sources

Primary adapters:

- **VPN Gate official API** -- direct volunteer relay source.
- **IPSpeed** -- independent OpenVPN listings with uptime/ping metadata.
- **VPNBook** -- stable US OpenVPN endpoints with credentials parsed at refresh time.
- **PublicVPNList** -- optional verified/full-tunnel catalog.
- **Vpngate-Scraper-API** -- VPNGate-family recovery source. It is tagged as the same `vpngate` source family so mirrors do not count as independent evidence.

Source failures are isolated. Last successful per-source candidates are cached for 24 hours in `.state/state.sqlite3`, which is preserved between workflow runs with GitHub Actions cache. If no acceptable node can be produced, the workflow fails and leaves the previously committed `mihomo.yaml` untouched.

### Low-watermark protection

A technically successful source response is not automatically considered healthy. For each source the selector keeps a rolling median of the last successful candidate counts. If a new non-empty snapshot suddenly falls below 40% of a sufficiently large baseline, the source is marked **degraded**:

- the small fresh snapshot is still allowed to contribute current evidence;
- it does **not** replace the last-good source cache;
- fresh + last-good candidates are merged for generation;
- only genuinely fresh candidates count toward availability history.

This protects the output from transient partial lists or source rebuild windows, an operational lesson also seen in CFNext's VPN Gate handling.

### PublicVPNList lazy materialization

PublicVPNList can expose a much larger metadata catalog than the final selector needs. The generator therefore ranks metadata first using technical score, 7-day uptime, speed and latency, deduplicates by source family/IP, and downloads full OVPN profiles only for the best subset (`publicvpnlist_materialize_limit`, default 40). This keeps Actions fast and avoids hundreds of unnecessary config downloads.

## Repository secrets

All keys are optional. Add them under **Settings -> Secrets and variables -> Actions** if available:

- `PUBLICVPNLIST_API_KEY` -- enables the larger PublicVPNList verified pool.
  PublicVPNList also offers short-lived 24-hour access keys; for unattended scheduled Actions, use permanent access when available. An expired key degrades only this source and does not invalidate last-good state.
- `ABUSEIPDB_API_KEY` -- adds recent abuse reputation evidence.
- `PROXYCHECK_API_KEY` -- adds proxy/VPN/risk evidence.

Without keys, the other sources and zero-key IP intelligence still work. If `PUBLICVPNLIST_API_KEY` is absent, that source is skipped cleanly.

## GitHub Actions permission

The workflow uses the repository `GITHUB_TOKEN` with `contents: write` only so it can commit `mihomo.yaml`. If the repository or organization forces the token to read-only, allow GitHub Actions write access or adjust the branch/ruleset policy for this workflow. The workflow must be committed to the repository **default branch** for both scheduled and manual dispatch behavior.

The selector cache is optional: cache-restore failures do not block generation, and a corrupted restored SQLite database is detected with `PRAGMA quick_check` and reset automatically. IP-intelligence calls and the Mihomo binary download also have explicit wall-clock budgets so degraded external APIs cannot consume the entire 12-minute job.

The workflow intentionally has **no `pull_request` or `pull_request_target` trigger**, so untrusted pull-request code is never executed with the write token or repository secrets. See `CI-READINESS.md` for the complete preflight checklist.

## Selection model

1. Fetch all enabled sources independently.
2. Detect abnormally small source snapshots before replacing last-good cache.
3. For VPN Gate, prefer the named Base64 profile column but safely fall back to scanning only the final CSV columns if the upstream layout changes.
4. For PublicVPNList, pre-rank metadata and materialize only the best OVPN subset.
5. Parse downloaded OpenVPN profiles with an allow-list. Script/plugin/management hooks and external file references are rejected rather than forwarded.
6. Deduplicate by endpoint and preserve source-family provenance.
7. Record **fresh observations only**. Cached recovery candidates may keep generation alive but never fake 1h/24h/7d availability.
8. Run a cheap TCP connect probe on the top TCP candidates before expensive IP intelligence. It is only a soft GitHub-runner signal, not an OpenVPN handshake.
9. Enrich only the top candidate set with IP/ASN/ISP/risk data.
10. Reject severe cases such as Tor, residential-proxy signals, strong US geolocation mismatch, and severe recent abuse.
11. Prefer fixed-line ISP-like networks, longer availability, good source measurements, successful TCP reachability, and ASN diversity.
12. Two consecutive TCP probe failures keep a node out of Preferred but still allow it to remain fallback.
13. Keep the previous primary first while it remains eligible.
14. Atomically replace `mihomo.yaml` only after at least one acceptable node exists.

## State model

The Actions cache persists `.state/state.sqlite3`. It stores:

- actual refresh runs;
- fresh endpoint observations;
- TCP probe observations;
- source count snapshots and status;
- versioned last-good source caches;
- IP-intelligence cache;
- previous Preferred/Fallback selection.

Source cache entries include an internal schema version. A breaking parser/cache change invalidates old cached candidates instead of silently reusing incompatible state.

## IP-risk limits

A residential/fiber ASN does **not** imply a private or clean residential IP. VPNGate-family addresses are public shared VPN relays. The project also deliberately avoids treating generic mail DNSBL membership as browser/account reputation; policy lists such as Spamhaus PBL commonly contain normal access-network addresses.

Destination services maintain private reputation systems, so this selector improves node quality but cannot guarantee that a site will accept any particular IP.

## Important configuration knobs

```toml
[general]
publicvpnlist_materialize_limit = 40
tcp_probe_limit = 40
tcp_probe_timeout_seconds = 2.0
source_baseline_window = 12
source_low_watermark_ratio = 0.40
source_low_watermark_min_baseline = 4

[filters]
max_preferred_tcp_fail_streak = 2
```

The defaults are intentionally conservative and lightweight. Small sources such as VPNBook do not trigger the low-watermark rule because their normal baseline is below the minimum threshold.

## Development check

No third-party Python packages are required:

```bash
python -m unittest discover -s tests -v
python -m compileall -q gate_us_lite tests
```

To reproduce one workflow generation locally for development only:

```bash
python -m gate_us_lite --config config.toml --state .state/state.sqlite3 --output mihomo.yaml
```

This command is not required in normal use; the intended runtime is GitHub Actions.
