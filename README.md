# gate-us-lite

A lightweight **GitHub Actions-only** generator for a curated US OpenVPN list in Mihomo YAML format.

There is no local service, daemon, systemd timer, Docker stack, HTTP/SOCKS proxy, or deployment step. GitHub Actions fetches and evaluates the sources, keeps its small selector history in the Actions cache, and commits only the generated `mihomo.yaml` when the effective configuration changes.

## Pipeline

```text
VPN Gate ---------\
PublicVPNList -----+--> source snapshot gate --> metadata pre-filter
VPNGate Scraper ---/             |                        |
                                 +--> last-good cache     v
                                                    safe OVPN parse
                                                        |
                                                  TCP soft probe
                                                        |
                                              Mihomo tunnel probe
                                                        |
                                               IP quality + history
                                                        |
                                                        v
                                              preferred + fallback
                                                        |
                                                        v
                                                  mihomo.yaml
```

The workflow runs every second day at 03:07 UTC (cron `7 3 */2 * *`; the day steps restart each month, so a 31-day month runs on the 31st and again on the 1st), and can also be started manually with **Actions -> Generate Mihomo US VPN list -> Run workflow**. It is split into three jobs (`collect` -> `probe` -> `publish`) so the process that dials untrusted VPN servers never sees a secret or a write token; see [GitHub Actions permission](#github-actions-permission).

**Better no node than a dangerous one.** A node is published only if it completes a real OpenVPN handshake *and* ipwho.is plus ProxyCheck both returned a verdict for its observed exit address *and* that is a US address which is not a Tor exit, a compromised host or part of a residential-proxy network, and has no severe abuse reports. Every node is still a public relay run by someone else (see the [trust model](#trust-model)). Hosting, known-VPN and high-risk-score verdicts do not reject a node, because ProxyCheck gave them to every public relay in the samples taken so far (see [IP-risk limits](#ip-risk-limits)); they only lower its rank. When no node qualifies the run fails and the previously committed `mihomo.yaml` stays in place.

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
- **PublicVPNList** -- optional verified/full-tunnel catalog. Each record keeps the family of its upstream source (VPN Gate, IPSpeed, ...), so mirrors do not count as independent evidence.
- **Vpngate-Scraper-API** -- VPNGate-family recovery source. It is tagged as the same `vpngate` source family so mirrors do not count as independent evidence.

The US supply is small. On 2026-10-07 the VPN Gate list held 100 servers worldwide, 4 of them in the US, and the scraper's README listed 5 US servers of the same family; PublicVPNList reported 108 US OpenVPN records but offered no download link for any of them (see `PUBLICVPNLIST_API_KEY`). One run therefore sees roughly 5-10 US candidates, and only the ones that answer a real OpenVPN handshake and pass the checks below are published.

Source failures are isolated. The last successful candidates of each source are kept for `source_cache_max_age_seconds` (4 days, so the stand-in outlives one missed run of the every-second-day schedule) in `.state/state.sqlite3`, which is preserved between workflow runs with GitHub Actions cache; they go through the same tunnel probe and address checks as fresh candidates. If no acceptable node can be produced, the workflow fails and leaves the previously committed `mihomo.yaml` untouched.

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
  PublicVPNList also offers short-lived 24-hour access keys; for unattended scheduled Actions, use permanent access when available. An expired key (HTTP 401) degrades only this source and does not invalidate last-good state. When the key works but the source still yields nothing, the log names the stage that lost the records: `[warn] publicvpnlist: <records> records, <n> with a download link, 0 usable profiles (<reasons>)`. PublicVPNList documents that OpenVPN keeps "its existing protected download flow" with single-use download tokens, so `config_download_url` can be null for OpenVPN records and an unattended run cannot fetch those profiles. On 2026-10-07 a permanent key returned 106 US records, none with a download link; that matches the documented flow and does not point to a key problem.
- `ABUSEIPDB_API_KEY` -- adds recent abuse reputation evidence and an independent second opinion on hosting (usage type `Data Center/Web Hosting/Transit`) and Tor.
- `PROXYCHECK_API_KEY` -- the only provider of Tor, compromised-host, residential-proxy, proxy/VPN and risk verdicts (and the authoritative hosting verdict). **Effectively required:** without a ProxyCheck verdict an exit address is unknown, and unknown is never published (`require_known_intel`). While the filter is on and the key is missing, `publish` stops with exit code 4 and an explicit message. A free ProxyCheck key allows 1,000 queries a day (its documented limit); one run looks up at most `max_candidates_for_intel` (30) addresses, far below that limit at one run every second day. A reply with a missing or null verdict counts as an error, never as clean.

If `PUBLICVPNLIST_API_KEY` is absent, that source is skipped cleanly. Without `ABUSEIPDB_API_KEY` the abuse signal is simply missing.

## GitHub Actions permission

The workflow runs three jobs. A separate job is a separate VM, which is the only real isolation boundary GitHub Actions offers: steps of one job, and processes of one user, can read each other's environment and persist.

| Job | Does | Secrets | `GITHUB_TOKEN` |
| --- | --- | --- | --- |
| `collect` | tests, fetches the sources, merges, pre-ranks, TCP probe | `PUBLICVPNLIST_API_KEY` | `contents: read`, not persisted |
| `probe` | dials the candidates through real OpenVPN tunnels in a local Mihomo | none | `contents: read`, not persisted |
| `publish` | IP intelligence, selection, `mihomo -t`, commit to this repo, push to the dist repo | `ABUSEIPDB_API_KEY`, `PROXYCHECK_API_KEY`, `DIST_REPO_TOKEN` | `contents: write` |

Jobs hand work over as one-day artifacts (`pool`, `state`, `verdicts`): `collect` uploads the candidate pool and the selector state, `probe` uploads its verdicts. `publish` verifies the pool and the state against SHA-256 values that `collect` exposed as job outputs, before it fetches the verdicts, and treats the verdicts as untrusted input: it keeps only entries that name a pooled candidate and carry a public exit address. The selector state is saved back to the Actions cache only after that check passed. If `probe` cannot deliver verdicts (Mihomo missing or not starting, no direct connectivity for the control request) the run fails with exit code 3 and nothing is published.

Residual risk: the probe job still holds the run's runtime token, so a compromised probe job could in principle write artifacts or caches for this repository. It cannot reach secrets or push code, artifacts are verified by hash and verdicts are re-validated by `publish`. What it could still do is plant a forged Actions cache entry that a later `collect` run restores; since that cache holds selector history and intelligence, the realistic worst case is promoting a relay the attacker also operates. Signing the cache was considered and rejected: it needs another secret in a job that parses untrusted upstream data, and the state changes during `collect`, so `publish` could not verify a signature. How far GitHub scopes the runtime token has not been verified, so this is a strong reduction of the blast radius, not a guarantee.

If the repository or organization forces the token to read-only, allow GitHub Actions write access or adjust the branch/ruleset policy for the `publish` job. The workflow must be committed to the repository **default branch** for both scheduled and manual dispatch behavior.

The selector cache is optional: cache-restore failures do not block generation, and a corrupted restored SQLite database is detected with `PRAGMA quick_check` and reset automatically. The state is saved by `publish` even when no node is acceptable, so the intelligence cache survives failed runs. IP-intelligence calls, the tunnel probe and the Mihomo binary download also have explicit wall-clock budgets so degraded external APIs or dead nodes cannot consume a job.

The pinned, checksum-verified Mihomo binary is installed by the local composite action `.github/actions/install-mihomo` in every job (tests and config validation in `collect`/`publish`, tunnel probe in `probe`). The probing Mihomo process additionally starts with a scrubbed environment.

Third-party actions are pinned to full commit SHAs (the trailing comment names the release), so a moved tag cannot change what runs with the write token. A run that is already publishing is never cancelled half-way (`cancel-in-progress: false`); a newer run waits for it. All HTTP requests are `https` only, and request headers such as API keys are never forwarded to another origin by a redirect.

The workflow intentionally has **no `pull_request` or `pull_request_target` trigger**, so untrusted pull-request code is never executed with the write token or repository secrets. See `CI-READINESS.md` for the complete preflight checklist.

## Selection model

1. Fetch all enabled sources independently.
2. Detect abnormally small source snapshots before replacing last-good cache.
3. For VPN Gate, prefer the named Base64 profile column but safely fall back to scanning only the final CSV columns if the upstream layout changes.
4. For PublicVPNList, pre-rank metadata and materialize only the best OVPN subset.
5. Parse downloaded OpenVPN profiles with an allow-list. Script/plugin/management hooks and external file references are rejected rather than forwarded.
6. Deduplicate by endpoint and preserve source-family provenance.
7. Record **fresh observations only**. Cached recovery candidates may keep generation alive but never fake 1h/24h/7d availability.
8. Run a cheap TCP connect probe on the top TCP candidates. It is only a soft GitHub-runner signal that orders the candidates for the next step, not an OpenVPN handshake.
9. Dial the top candidates (`tunnel_probe_limit`) through real OpenVPN tunnels in a local Mihomo process (the `probe` job). A candidate survives only if it completes the handshake and fetches the Cloudflare trace through the tunnel from a public exit address that differs from the runner's own. That exit address replaces the endpoint address in the lookups below. If the probe cannot run at all, nothing is published.
10. Enrich only the surviving top candidates with ipwho.is (country, ASN, ISP), ProxyCheck (Tor, compromised host, hosting, proxy/VPN, residential proxy, risk; detections of the last `proxycheck_lookback_days` days) and optionally AbuseIPDB (abuse score plus an independent hosting/Tor opinion).
11. Reject, for Preferred **and** Fallback alike: unknown intelligence (`require_known_intel`; this includes a ProxyCheck reply with a missing or null verdict), invalid or non-US exit addresses, Tor, compromised hosts, residential-proxy networks and severe recent abuse. Hosting/datacenter addresses (`reject_hosting`), proxy/VPN detections (`reject_proxy`) and a ProxyCheck risk above `max_proxycheck_risk` reject a node only when configured; by default they only lower its rank.
12. Rank the rest: fixed-line ISP-like networks, longer availability, good source measurements, successful TCP reachability, ASN diversity, and a penalty for hosting, proxy/VPN and risk verdicts.
13. A node that is clean but slow, dead on TCP twice in a row, or rarely available is kept out of Preferred and may remain Fallback.
14. Keep the previous primary first while it remains eligible.
15. Atomically replace `mihomo.yaml` only after at least one acceptable node exists; otherwise exit with code 2 and keep the old file.

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

ProxyCheck flagged every public relay in the sample taken so far. On 2026-10-07 all seven US candidates of the VPN Gate family were flagged as proxy/VPN with a risk score of 34 to 100, and three of them belonged to the PacketStream residential-proxy network. ProxyCheck's base score follows the detection type (proxy and compromised score 100), so a risk limit would reject every public relay without telling them apart. The defaults therefore reject only what does separate relays: Tor, compromised hosts, residential-proxy networks, abuse reports, a wrong country and a missing verdict. A residential-proxy exit is another person's home connection rented out through a proxy network, which is why that check stays on.

Destination services maintain private reputation systems, so this selector improves node quality but cannot guarantee that a site will accept any particular IP.

### Trust model

Every node is a relay run by someone else: VPN Gate volunteers, free VPN services, anonymous hosts. The relay operator can see which hosts you connect to and can read or alter whatever passes through unencrypted, DNS queries included; PublicVPNList says the same about its catalog ("Unknown third-party endpoints can still log or alter traffic; use end-to-end encryption and avoid sensitive accounts"). The filters above judge the **address** (Tor, compromised host, residential-proxy network, abuse reports, country) and that the tunnel really works; they say nothing about the honesty of the operator, and a published node is still a public relay that ProxyCheck will usually list as a VPN or proxy. Treat the nodes as untrusted networks suited to low-risk traffic: rely on HTTPS/TLS/SSH end to end and keep credentials and sensitive accounts off them.

## Important configuration knobs

```toml
[general]
publicvpnlist_materialize_limit = 40
tcp_probe_limit = 40
tcp_probe_timeout_seconds = 2.0
tunnel_probe_limit = 60
tunnel_probe_timeout_seconds = 15
proxycheck_lookback_days = 30
source_cache_max_age_seconds = 345600
source_baseline_window = 12
source_low_watermark_ratio = 0.40
source_low_watermark_min_baseline = 4

[filters]
require_known_intel = true
reject_tor = true
reject_compromised = true
reject_residential_proxy = true
reject_country_mismatch = true
reject_hosting = false
reject_proxy = false
max_proxycheck_risk = 100
max_preferred_tcp_fail_streak = 2
```

The defaults are intentionally conservative and lightweight. Sources whose normal baseline is below `source_low_watermark_min_baseline` do not trigger the low-watermark rule.

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

This command is not required in normal use; the intended runtime is GitHub Actions. It runs the stages the workflow runs as separate jobs (`collect`, `probe`, `finish`) in one process; each can also be run on its own (`python -m gate_us_lite probe --candidates handoff/candidates.json --verdicts handoff/verdicts.json`). The tunnel probe needs a Mihomo binary (`MIHOMO_BIN`, default `mihomo` on `PATH`) and direct connectivity; without it the command exits with code 3 and publishes nothing. Exit codes: `0` published, `2` no acceptable node, `3` tunnel probe unavailable, `4` configuration error (for example a missing `PROXYCHECK_API_KEY`).
