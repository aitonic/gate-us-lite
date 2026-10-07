# gate-us-lite v0.3.1 — Engineering Handoff

> Handoff snapshot: 2026-10-07  
> Runtime model: GitHub Actions only  
> Primary artifact: `mihomo.yaml`  
> Intended use: automatically curate stable, suitable US OpenVPN egress candidates for AI applications and general development traffic.

## 1. Project objective

`gate-us-lite` is deliberately narrow. It aggregates a small set of public OpenVPN sources, normalizes untrusted profiles, evaluates US endpoints for technical quality and basic IP/network risk, maintains lightweight historical state across GitHub Actions runs, and commits a compact Mihomo YAML containing a preferred pool and a fallback pool.

The project is **not** a VPN daemon, proxy gateway, Web UI, Docker stack, residential-proxy platform, or general-purpose VPN aggregator. The intended runtime is GitHub Actions; the consumer is Mihomo-compatible software.

### Success criteria

A successful scheduled run should:

1. fetch all enabled sources independently;
2. survive one or more source failures without destroying the previous good state;
3. reject unsafe/unparseable OpenVPN profiles;
4. separate fresh observations from cached recovery data;
5. prefer stable US ISP-like endpoints and **publish nothing rather than a risky node**: hosting, proxy/VPN, Tor, residential-proxy, high-risk, high-abuse and unknown-reputation addresses are rejected outright;
6. prefer preserve a healthy previous primary to reduce IP churn;
7. keep ASN diversity in the Preferred pool;
8. generate a valid, non-empty `mihomo.yaml`;
9. commit only when the effective YAML changes;
10. leave the previously committed YAML untouched if no acceptable candidate can be generated.

## 2. Current package state

Current package metadata:

- `pyproject.toml`: **0.3.1**
- Python requirement: `>=3.11`
- third-party Python dependencies: **none**
- GitHub Actions Python: **3.13**
- unit tests: **107**

Verification performed for this handoff:

```bash
python -m unittest discover -s tests -v
python -m compileall -q gate_us_lite tests
```

Result: **107 tests passed (1 skipped when no Mihomo binary is available); compileall passed**. `ruff check --select F,B,E9` and `actionlint` are clean.

### Version consistency

`pyproject.toml` and `gate_us_lite/__init__.py` are both `0.3.1`. A regression test now enforces this invariant.

## 3. Repository map

```text
.
├── .github/
│   ├── actions/install-mihomo/action.yml
│   └── workflows/generate-mihomo.yml
├── README.md
├── SOURCES.md
├── HANDOFF.md
├── SUMMARY.md
├── config.toml
├── pyproject.toml
├── tests/
└── gate_us_lite/
    ├── __init__.py
    ├── __main__.py
    ├── cli.py
    ├── config.py
    ├── http.py
    ├── intel.py
    ├── log.py
    ├── mihomo.py
    ├── models.py
    ├── ovpn.py
    ├── pipeline.py
    ├── probe.py
    ├── select.py
    ├── sources.py
    ├── store.py
    └── tunnel.py
```

### Module ownership

| Module | Responsibility |
|---|---|
| `cli.py` | Argument parsing, the `all`/`collect`/`probe`/`finish` stages, JSON hand-over between jobs (candidate pool, verdicts), exit codes |
| `pipeline.py` | Source concurrency, degraded-source handling, TCP probes, tunnel verdicts, enrichment, selection, atomic output |
| `log.py` | Stderr progress logging and `tally`, the most frequent reasons for a log line |
| `sources.py` | VPNGate, PublicVPNList, Vpngate-Scraper adapters |
| `ovpn.py` | Security-sensitive OpenVPN allow-list parser |
| `intel.py` | IP/public-network validation, ipwho.is (country/ASN/ISP), optional ProxyCheck v3 (hosting/Tor/proxy/risk/residential proxy), optional AbuseIPDB, ISP/hosting heuristics |
| `store.py` | SQLite observations, source snapshots, last-good caches, probe history, intel cache, sticky selection state |
| `select.py` | Deduplication, rough rank, risk evaluation, Preferred/Fallback selection, ASN diversity, sticky primary |
| `probe.py` | Lightweight TCP connect probe only; not a full OpenVPN handshake |
| `tunnel.py` | Local Mihomo process that dials candidates through their OpenVPN tunnels in parallel and returns exit IPs or failure reasons |
| `mihomo.py` | Deterministic Mihomo OpenVPN node + fallback-group rendering, plus the per-candidate probe configuration |
| `config.py` | TOML defaults, optional secret environment variables, `ConfigurationError` |
| `http.py` | `fetch`: https only, bounded retries and size, redirects never carry request headers (API keys) to another origin; failures raise `FetchError` with a `reason` such as `HTTPError 410` |

## 4. GitHub Actions contract

Workflow: `.github/workflows/generate-mihomo.yml`

Triggers:

```yaml
workflow_dispatch:
schedule:
  - cron: "7 3 */2 * *"
```

The workflow therefore runs every second day at 03:07 UTC. The day steps of cron restart each month, so a 31-day month runs on the 31st and again on the 1st (cron cannot express an exact 48-hour period). A manual `workflow_dispatch` run refreshes the output at any time.

Time-dependent settings are sized for this cadence. `source_cache_max_age_seconds` (4 days) keeps the last good snapshot of a source usable after one missed run. The intelligence cache (24 h) no longer carries over between runs, so every run looks the exit addresses up again (at most `max_candidates_for_intel`, 30). The 24-hour availability signal carries no information: a window of 24 hours holds at most the current run (unless a manual run was started the same day), so `availability_24h` is 1.0 for every node present in the run and the `min_preferred_availability_24h` gate, which needs `seen_24h >= 2`, never applies. `availability_7d` (three or four snapshots) is the persistence signal, and the tunnel probe is the liveness check.

The workflow has three jobs. A job is a separate VM, the only real isolation boundary on GitHub Actions.

| Job | Stage | Secrets | Token | Timeout |
|---|---|---|---|---|
| `collect` | tests, then `python -m gate_us_lite collect` | `PUBLICVPNLIST_API_KEY` | `contents: read`, credentials not persisted | 10 min |
| `probe` | `python -m gate_us_lite probe` (the only job that dials untrusted VPN servers) | none | `contents: read`, credentials not persisted | 8 min |
| `publish` | `python -m gate_us_lite finish`, `mihomo -t`, commit, dist push | `ABUSEIPDB_API_KEY`, `PROXYCHECK_API_KEY`, `DIST_REPO_TOKEN` | `contents: write` | 8 min |

Important workflow properties:

- workflow-level `permissions: contents: read`; only `publish` has `contents: write`
- no `pull_request` or `pull_request_target` trigger
- `concurrency.cancel-in-progress: false`: a run that is already publishing is never interrupted half-way, a newer run waits for it
- every third-party action is pinned to a full commit SHA with the release in a trailing comment (checkout v7.0.1, setup-python v7.0.0, cache v6.1.0, upload-artifact v7.0.1, download-artifact v8.0.1, resolved through the GitHub refs API on 2026-10-07); a regression test enforces the format and one SHA per action
- hand-over through one-day artifacts `pool`, `state` and `verdicts` (uploaded with `overwrite: true` so a re-run does not fail on the names left by the previous attempt); `collect` exposes the SHA-256 of the pool and of the selector state as job outputs and `publish` verifies both right after downloading them and before it fetches the verdicts; the verdicts are filtered again by `cli._read_alive`
- the Actions cache persists `.state/`: restored by `collect` (`actions/cache/restore`), saved by `publish` (`actions/cache/save`, `if: !cancelled() && steps.generate.conclusion != 'skipped'`) so a run without acceptable nodes still keeps its intelligence cache, while a state that failed the integrity check (the generate step was skipped) is never persisted
- the pinned Mihomo binary is installed by the local composite action `.github/actions/install-mihomo` (SHA-256 verified); `MIHOMO_BIN: /tmp/mihomo` is set workflow-wide
- tests run in `collect` before any secret is used or any source is contacted
- `mihomo.yaml` is validated by a pinned real Mihomo binary before publication
- only `mihomo.yaml` is staged and committed
- no commit occurs when YAML is unchanged

The repository token must be allowed to push to the default branch. Branch protection may need an explicit exception depending on repository policy.

## 5. Data-source model

Enabled by default:

| Adapter | Role | `source_family` behavior |
|---|---|---|
| VPN Gate official | primary volunteer-relay source | `vpngate` |
| PublicVPNList | optional verified/full-tunnel catalog | preserves upstream family where identifiable |
| Vpngate-Scraper-API | VPNGate recovery/mirror source | `vpngate` |

### Why `source_family` exists

Mirrors must not be treated as independent confirmation. For example, a VPNGate server seen via VPNGate official, Vpngate-Scraper, and PublicVPNList-with-source=VPNGate still represents one underlying source family.

PublicVPNList source normalization currently recognizes source names containing (ignoring case, spaces and punctuation):

- `vpngate`
- `ipspeed`

Everything else falls back to the source string itself.

This mapping is intentionally simple and is a future extension point.

## 6. Secrets and API behavior

Workflow environment:

```yaml
PUBLICVPNLIST_API_KEY: ${{ secrets.PUBLICVPNLIST_API_KEY }}
ABUSEIPDB_API_KEY: ${{ secrets.ABUSEIPDB_API_KEY }}
PROXYCHECK_API_KEY: ${{ secrets.PROXYCHECK_API_KEY }}
```

All three are optional for the overall generator.

### `PUBLICVPNLIST_API_KEY`

Current PublicVPNList policy requires Bearer authentication for API/export access. Temporary keys expire after 24 hours; permanent personal access is individually reviewed. For a continuously scheduled GitHub Action, a permanent key is the practical option.

Current behavior when absent: **PublicVPNList is skipped cleanly**.

Contract facts (OpenAPI 1.4.0 and the API pages, read 2026-10-07): a free key lasts 24 hours and is issued after reCAPTCHA; `401` means a missing, expired or revoked key; an empty catalog is HTTP `200` with `data: []`; the limit is 60 requests per minute. `config_download_url` is `string | null`: for OpenVPN the documentation points to `server_page_url`, a protected download page, when it is null, which an unattended run cannot use. The adapter keeps only records with a download link and downloads the best `publicvpnlist_materialize_limit` of them. The key is sent to `publicvpnlist.com` and its subdomains only.

When the key works but nothing comes out, the source raises an error that names the stage that lost the records, for example `[warn] publicvpnlist: 104 records, 0 with a download link, 0 usable profiles` or `... 8 with a download link, 0 usable profiles (8x HTTPError 410)`. An empty catalog is a plain empty result. As of 2026-10-07 the cause of an `empty` line seen in a scheduled run of the earlier code (which did not report the stage) has not been determined: no key was available to reproduce it.

### `ABUSEIPDB_API_KEY`

Optional enrichment only. When configured, the code requests recent 30-day abuse data and stores:

- abuse confidence;
- total reports;
- last reported timestamp;
- `usageType` and `isTor` (documented `check` response fields): usage type `Data Center/Web Hosting/Transit` sets `hosting` and `isTor` sets `tor`, so the verdict of either provider stands and the other one's silence never overrules it. AbuseIPDB takes its usage type from IPinfo, independent of ProxyCheck's data.

Current behavior when absent: **AbuseIPDB enrichment is skipped**.

### `PROXYCHECK_API_KEY`

Effectively required. With `require_known_intel = true` an address without a ProxyCheck verdict is unknown and never published. When configured, the code queries ProxyCheck v3 (`/v3/<ip>?key=...`) and maps `detections.tor`, `detections.hosting` (or `network.type == "Hosting"`), `detections.anonymous` (proxy/VPN aggregate), `detections.risk` and an `operator.services` entry `residential_proxies` (residential-proxy signal). It is the only provider of Tor, proxy, risk and residential-proxy verdicts. ProxyCheck documents that every key is always present and that missing data is `null`, so `tor`, `hosting`, `anonymous` must be booleans and `risk` a number; anything else raises, the status becomes `error`, and the address is unknown instead of silently clean (a schema drift therefore stops publication rather than approving everything). The request adds `days=<proxycheck_lookback_days>` (default 30, documented range 0.01-60; ProxyCheck's own default window is 2-7 days tuned to avoid false positives) so that recently flagged addresses stay flagged, even at low confidence. A free key allows 1,000 queries per day according to ProxyCheck's status-code table; the `[intel] errors:` log line shows quota and contract failures.

Current behavior when absent: with `require_known_intel = true` (default) the all-in-one run and `finish` raise `ConfigurationError` before doing any work and the CLI exits with code 4 and an explicit message; the run is not silently reduced to exit code 2. The current implementation does not use ProxyCheck anonymous mode. Setting `require_known_intel = false` would let nodes through on ipwho data alone, but then hosting, Tor, proxy and residential-proxy verdicts stay unknown (not clean); only the ISP keyword heuristics can still mark an address as hosting.

### Zero-key intelligence

`ipwho.is` remains the baseline zero-key IP intelligence source and contributes:

- country code;
- ASN;
- ISP/org/domain.

The free tier returns no `security` block, so ipwho.is never supplies hosting, proxy or Tor verdicts.

Failures are soft and stored as enrichment error fields rather than aborting the run.

## 7. Current end-to-end pipeline

```text
VPNGate ----------\
PublicVPNList -----+--> fetch concurrently
VPNGate Scraper ---/
          |
          v
source snapshot gate
  | ok         | degraded       | error/empty
  |            |                |
  |            + fresh + cache  + cache only
  |                             |
  +--------------+--------------+
                 v
        generation candidates
                 |
        fresh candidates only
                 +--> SQLite observations
                 |
                 v
       endpoint/source-family merge
                 |
          coarse metadata filter
                 |
            rough ranking
                 |
           TCP soft probe
                 |
   candidates.json -> [probe job]
      Mihomo tunnel probe (top N)
   verdicts.json   -> [publish job]
                 |
         top-N IP enrichment
                 |
  hard rejects (both tiers) + history score
                 |
       sticky primary + ASN diversity
                 |
      Preferred <= 3 / Fallback <= 8
                 |
                 v
             mihomo.yaml
```

## 8. Source low-watermark protection

This behavior was added after studying CFNext's real VPNGate low-count-cache failure mode.

Current config:

```toml
source_baseline_window = 12
source_low_watermark_ratio = 0.40
source_low_watermark_min_baseline = 4
```

For each source:

1. calculate the median candidate count of the most recent successful `ok` snapshots;
2. if the current response is non-empty, the baseline is sufficiently large, and current count is below 40% of baseline, mark the source `degraded`;
3. do not replace last-good cache with the degraded snapshot;
4. merge the degraded fresh snapshot with last-good cache for generation;
5. count only candidates from sources whose refresh status is `ok` as current availability evidence; degraded/empty/error/skipped runs do not become valid opportunities.

Sources whose baseline is below the configured minimum do not trigger this rule.

## 9. Fresh-vs-cache invariant

This is an important correctness rule:

> Cached candidates may preserve generation continuity, but cached candidates must never be counted as if they were freshly observed in the current run.

`pipeline.py` therefore maintains separate collections:

- `observable_fresh`
- `generation_gathered`

Only `observable_fresh` reaches `Store.observe()`.

This prevents source outages from falsely pushing a cached node toward 100% historical availability.

Any future source-adapter refactor must preserve this invariant.

## 10. PublicVPNList lazy materialization

The API may expose far more metadata records than the selector needs. Current logic:

1. query US/OpenVPN/online metadata;
2. pre-rank with technical score, 7-day uptime, throughput and latency;
3. deduplicate metadata by `(source_family, endpoint_hint)`;
4. keep only the best `publicvpnlist_materialize_limit` entries (default 40);
5. only then download and parse the full OVPN profiles.

This deliberately reduces Actions HTTP traffic compared with materializing every returned server.

PublicVPNList's own `technical_quality_score` is treated as a technical signal only, not an IP privacy/trust verdict.

## 11. VPNGate parser resilience

Preferred path:

```text
CSV header -> OpenVPN_ConfigData_Base64
```

Fallback path:

- only scan the final three CSV fields;
- require plausible Base64;
- decode with validation;
- require embedded `<ca>`;
- require an OpenVPN `remote host port` line;
- require client-like markers (`client` or `dev`);
- then pass the result through the project's safe OVPN parser.

This protects against upstream CSV column-layout changes without blindly accepting arbitrary Base64 fields.

## 12. OpenVPN security boundary

Every downloaded OVPN profile is untrusted input.

The project intentionally rejects directives that can execute code, call plugins, expose management interfaces, or run hooks, including:

- `script-security`
- `up`
- `down`
- `route-up`
- `ipchange`
- `learn-address`
- `client-connect`
- `client-disconnect`
- `plugin`
- `management`
- `auth-user-pass-verify`

The parser extracts and regenerates only explicitly supported fields.

Supported inline security material includes:

- `<ca>`
- `<cert>` / `<key>`
- `<tls-auth>` + `key-direction`
- `<tls-crypt>`
- `<tls-crypt-v2>`

Mihomo currently documents support for these OpenVPN fields.

### Important maintenance rule

Do not change the parser into "download OVPN and pass through". Any new OpenVPN directive should be reviewed and explicitly mapped into the internal model before it can reach generated YAML.

## 13. TCP soft probe and tunnel probe semantics

TCP probing is intentionally cheap:

- top candidate subset only;
- TCP profiles only;
- default timeout: 2 seconds;
- maximum worker pool: 6;
- records reachability and approximate connect latency.

It is **not** a full OpenVPN handshake and it runs from a GitHub-hosted runner, not from the user's network.

Policy:

- success adds a small ranking benefit;
- failure adds a ranking penalty;
- two consecutive TCP probe failures remove a node from Preferred;
- the same node can still remain in Fallback if it passes hard safety checks.

UDP nodes are not penalized for lacking this probe.

### Tunnel probe

`tunnel.py` starts one local Mihomo process (`MIHOMO_BIN`). Its config holds every probed candidate as an OpenVPN outbound, one `mixed` listener per outbound (`proxy: <outbound>`) and one listener pinned to `DIRECT`:

- the top `tunnel_probe_limit` candidates are probed in parallel, UDP and TCP alike;
- each candidate must fetch `https://www.cloudflare.com/cdn-cgi/trace` through its listener within `tunnel_probe_timeout_seconds`; the reported `ip=` must be public and different from the address the `DIRECT` listener reports for the runner, otherwise the traffic bypassed the tunnel;
- survivors take the observed address as `exit_ip`; for the others the failure reason is read from Mihomo's log (for example `make OpenVPN handshake: read hard reset response after 0 retransmits: context deadline exceeded`) and the three most common reasons are logged as `[tunnel] ...`;
- Mihomo v1.19.31 gives up an OpenVPN handshake after about 5 seconds, so a round with dead nodes takes about that long;
- the Mihomo child gets a scrubbed environment (only `HOME`);
- if the binary is missing, Mihomo exits at startup, never becomes ready or the `DIRECT` control request fails, `TunnelProbeUnavailable` is raised: nothing is published and the CLI exits with code 3. There is no unverified mode.

## 14. IP-quality model

The selector separates hard rejection from soft ranking, and hard rejection applies to Preferred **and** Fallback: a rejected node is never published. Only the quality gates below distinguish the two tiers.

### Hard rejection (`select._reject_reasons`)

All checks look at the intelligence for the **observed exit address** (the tunnel probe's `exit_ip`):

| Reason | Condition | Filter |
|---|---|---|
| `invalid_ip` | address is not public | always |
| `intel_unknown` | ipwho or ProxyCheck did not return `ok`, including a ProxyCheck reply with a missing or null verdict | `require_known_intel` (default true) |
| `country_mismatch` | ipwho country differs from the source's country (a blank country counts as a mismatch) | `reject_country_mismatch` |
| `tor` | ProxyCheck `detections.tor` or AbuseIPDB `isTor` | `reject_tor` |
| `residential_proxy` | ProxyCheck operator service `residential_proxies` | `reject_residential_proxy` |
| `hosting` | ProxyCheck hosting verdict, AbuseIPDB usage type `Data Center/Web Hosting/Transit`, or ISP keyword heuristic | `reject_hosting` |
| `proxy` | ProxyCheck `detections.anonymous` (proxy or VPN) | `reject_proxy` (default true) |
| `high_risk` | ProxyCheck risk above `max_proxycheck_risk` (default 25) | `max_proxycheck_risk` |
| `severe_recent_abuse` | AbuseIPDB confidence `>= 80` (when AbuseIPDB data exists) | always |

`max_proxycheck_risk = 25` is the top of ProxyCheck's documented "allow" band for addresses that are not anonymous. ProxyCheck's base risk scores are hosting 33, VPN 50, scraper and Tor 75, proxy and compromised 100, so `high_risk` also rejects those even if the dedicated filter is switched off.

### Preferred-only restrictions

A node that passed every hard check is kept out of Preferred (but may remain Fallback) when:

- source ping exceeds threshold;
- source speed is too low;
- enough history exists and 24h availability is below threshold;
- a TCP node has reached the consecutive-failure limit.

### Ranking boosts/penalties

Signals include:

- PublicVPNList technical validation;
- IPSpeed source-family weight (PublicVPNList records only);
- source 7-day uptime;
- source uptime;
- speed and ping;
- TCP reachability;
- locally observed 24h/7d availability;
- fixed-line ISP heuristics;
- hosting heuristics, with a clean bonus only when ProxyCheck evaluated the address and a penalty when hosting status is unknown (relevant once the hard rejects are relaxed);
- ProxyCheck proxy/risk penalties (relevant once the hard rejects are relaxed);
- optional AbuseIPDB confidence;
- multiple provenance records;
- recent TCP-failure streak.

Do not interpret the resulting score as a fraud probability. It is an internal ordering score only.

## 15. Stability/history state

SQLite file:

```text
.state/state.sqlite3
```

Persisted through GitHub Actions cache.

Current tables:

- `refresh_runs`
- `observations`
- `probe_observations`
- `intel_cache`
- `source_state`
- `source_snapshots`
- `source_cache`
- `selection_state`

### Availability calculation

For 1h / 24h / 7d:

```text
availability = distinct fresh observations / valid successful refresh opportunities for sources that have observed the endpoint
```

The denominator is source-aware: only successful refreshes of sources that have actually observed the endpoint count as opportunities. A source outage or degraded snapshot therefore cannot make a healthy endpoint look unavailable.

### Retention

Observation/probe data is pruned after roughly 9 days. Source-count snapshots are retained for roughly 14 days.

### Source cache

Last-good candidate cache:

- default max age at use: 24h;
- internal `SOURCE_CACHE_SCHEMA = 3`;
- schema mismatch invalidates the old cache rather than silently deserializing incompatible candidate data.

### IP intelligence cache

Current TTL: 24h. Intelligence that is not complete (ipwho or ProxyCheck failed, or no ProxyCheck key is configured) is cached for only 15 minutes (`intel_error_cache_ttl_seconds`), so a transient outage keeps nodes unknown for at most that long and a newly added key takes effect within that time. `INTEL_SCHEMA` (currently 4) invalidates entries produced by an older provider mapping. If ProxyCheck's quota is exhausted the API answers with a non-ok `status`, which turns every uncached node unknown for that run; the 24h cache keeps the repeated exit addresses of a stable selection from consuming the quota.

## 16. Sticky primary and ASN diversity

Preferred selection behavior:

1. rank candidates by selection score;
2. if previous primary is still Preferred-eligible, keep it first;
3. fill remaining Preferred slots with different ASN keys where possible;
4. if ASN diversity prevents filling all slots, relax diversity to fill the configured Preferred limit;
5. choose Fallback from the remaining safe ranked candidates.

This is intentional. The project optimizes for stable egress identity, not continual switching to whichever node is a few milliseconds faster.

## 17. Mihomo output contract

Only one generated repository artifact is intended:

```text
mihomo.yaml
```

Current contents:

- up to 3 preferred OpenVPN nodes, named `US-Pxx-*`;
- up to 8 fallback OpenVPN nodes, named `US-Bxx-*`;
- `US-PREFERRED` fallback group;
- `US-STABLE` fallback group with Preferred nodes ordered first.

Mihomo's `fallback` group chooses the first available proxy in configured order when the current proxy times out. This matches the project's sticky/stability-first design.

The YAML deliberately omits timestamps and changing internal scores so Git does not get a commit every run when the effective proxy configuration is unchanged.

## 18. Current configuration defaults

```toml
[general]
country = "US"
preferred_limit = 3
fallback_limit = 8
timeout_seconds = 20
max_candidates_for_intel = 30
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
max_ping_ms = 250
min_speed_mbps = 0.5
require_known_intel = true
reject_hosting = true
reject_tor = true
reject_proxy = true
reject_residential_proxy = true
reject_country_mismatch = true
max_proxycheck_risk = 25
min_preferred_availability_24h = 0.25
max_preferred_tcp_fail_streak = 2
```

These values are conservative defaults, not universal truth. Changes should be justified by observed run data rather than intuition.

## 19. Failure behavior

### One source fails

Use the last-good cache for that source (at most `source_cache_max_age_seconds` old) and continue with all other sources. A failed request for a source's own listing is an error that names its reason, never an empty result (failed downloads of single profiles are only counted and reported for PublicVPNList).

### Source returns an abnormally small non-empty result

Mark `degraded`, keep the fresh data as evidence, merge last-good cache for generation, and do not replace the cache.

### PublicVPNList key missing/expired

Skip/fail that adapter only; other sources continue. A key that works but yields no usable profile is an error naming the stage that lost the records (see the PublicVPNList section).

### IP intelligence provider fails

ipwho or ProxyCheck failing makes the affected nodes unknown, so they are not published until a later run succeeds (error results are retried after 15 minutes). If that is every node, the run exits with code 2 and the old YAML stays. An AbuseIPDB failure only drops the abuse signal. Nothing here fails generation by itself. The `[intel] errors:` log line lists the three most common provider failure reasons (HTTP status, quota, incomplete verdict).

### ProxyCheck key missing

With `require_known_intel = true` no node can ever be published without it, so `finish` (and the all-in-one run, before it fetches anything) stops at once with `ConfigurationError` (exit code 4, nothing published, previous YAML untouched). In the workflow this happens in `publish`, after `collect` and `probe` have run; it is a one-time setup error, not a recurring state.

### Candidate fails the tunnel probe

The candidate is dropped for this run: it is not published and gets no intelligence lookup. Cached last-good candidates go through the same probe, so a dead cached node is not republished.

### Tunnel probe harness unavailable

The Mihomo binary is missing, exits at startup, never becomes ready, or the `DIRECT` control request fails: the run exits with code 3 and publishes nothing (`publish` is skipped because `probe` failed). The same exit code is used when `finish` finds no verdicts file.

### Verdicts or candidate pool are tampered with

`publish` compares the SHA-256 of the downloaded pool and selector state with the ones `collect` exposed as job outputs (a mismatch fails the job before the verdicts are fetched and the state is not saved to the cache), and keeps only verdict entries that name a pooled candidate and carry a public exit address. This limits what a compromised `probe` job can influence; see the residual risk in section 21.

### No acceptable candidate remains

Return non-zero (this includes every candidate failing the tunnel probe) and do **not** atomically replace `mihomo.yaml`. In GitHub Actions this prevents committing an empty/broken replacement.

## 20. Tests currently protecting critical invariants

`tests/` covers at least:

- safe OVPN parsing;
- unsafe script-hook rejection;
- LF/CRLF remote parsing;
- regression: `proto tcp` is not consumed as remote-proto text;
- Mihomo TLS-auth preservation;
- VPNGate US filter + uptime unit conversion;
- VPNGate trailing-column Base64 fallback;
- Vpngate-Scraper config correlation;
- PublicVPNList source-family normalization;
- PublicVPNList lazy materialization, empty catalog versus records without download links versus unusable profiles (with reasons), key only sent to `publicvpnlist.com` and its subdomains, the scraper's fetch failure as an error;
- source cache window: a snapshot two days old still covers a failed source, an older one does not, and the window comes from the configuration;
- TCP probing;
- endpoint merge/provenance;
- ASN diversity;
- sticky primary;
- hard rejects for Preferred and Fallback alike (unknown intelligence, hosting, proxy, Tor, residential proxy, country, risk threshold, abuse) and their relaxation through the filters;
- repeated TCP failure behavior;
- actual-refresh-run availability denominator;
- source rolling baseline;
- source-cache schema invalidation;
- low-watermark detection;
- cached recovery not faking availability;
- generator writes YAML only, and the YAML carries no scores;
- tunnel probe: probe-config rendering (validated by a real Mihomo when available), exit-IP and tunnel-bypass guards, failure reasons from Mihomo's log, an unavailable harness failing closed;
- pipeline: dead nodes are dropped and the exit address is what intelligence checks, unknown or risky exits are not published, the previous YAML survives exit codes 2 and 3, the stage hand-over through files, verdict filtering, probe limit;
- intelligence: ProxyCheck v3 mapping, incomplete verdicts as errors, the lookback window in the request, AbuseIPDB hosting/Tor opinion, ipwho free tier without security verdicts, `hosting_known` semantics;
- pipeline configuration: missing ProxyCheck key (exit code 4), relaxed requirement, lookback window plumbing, provider failure summary;
- `fetch`: HTTP status in errors, proxy support, https only, redirects that never carry headers to another origin, `FetchError.reason`; `tally`;
- workflow contract: three jobs, no secrets or write token in `probe`, permissions and secrets per job, per-job timeouts, step ordering, pool and state fingerprints verified before the verdicts are fetched, state saved after a failed selection but never without the integrity check, SHA-pinned actions and the pinned Mihomo release, `cancel-in-progress: false`.

## 21. Known limitations and risks

These are the most useful starting points for future work.

### Security risk register

| Risk | Status | Reasoning |
|---|---|---|
| A relay operator can read or alter unencrypted traffic and DNS | accepted, inherent | Every node is a relay run by someone else; the filters judge addresses, not operators. README "Trust model" tells consumers to rely on end-to-end encryption. |
| A public relay that no configured provider knows still passes the filters | open, inherent | "Clean" means unknown to ipwho, ProxyCheck and AbuseIPDB, not "not a relay". ProxyCheck, for example, reports `us16.vpnbook.com` (a VPNBook server) with `vpn: false` and `anonymous: false`; it is rejected only because the address is hosting and its risk score is 33. |
| A provider changes or breaks its response | mitigated | ProxyCheck replies without complete booleans and a numeric risk are errors, so the address is unknown and not published. |
| The ProxyCheck free quota (1,000 queries/day) runs out | mitigated | Complete verdicts are cached for 24 h; exhaustion fails closed and shows up in the `[intel] errors:` line. |
| Profile download URLs come from upstream data | mitigated | `fetch` is https only, the PublicVPNList key is only sent to its own domain, redirects never carry headers to another origin, and fetched text only passes through the OVPN allow-list. |
| A compromised probe job forges artifacts | mitigated | Pool and state are verified by SHA-256, verdicts are filtered, the state is not cached after a failed check. |
| A compromised probe job plants a forged Actions cache entry | accepted | See the trust-boundary note below. |
| Scope of the Actions runtime token | open, unverified | Not checked against GitHub's documentation or a real run. |
| The previously published YAML stays in place after exit code 2 | open, decision needed | The retained nodes were acceptable once; the run found none acceptable now (flagged, dead, delisted, or only unverifiable because a provider was down). Keeping the file favours availability over "better no node than a risky one" on the consumer side. A grace period after which a node-less YAML is published would reverse that trade-off; it changes consumer behaviour, so it has not been added without a decision. |
| Legacy OpenVPN ciphers (CBC, SHA1/MD5 HMAC) are passed through | accepted | The relay terminates the tunnel anyway; weak data-channel crypto would only matter against a third party on the path (my assessment). |
| A node can be flagged or die between the probe and its use | accepted | Mihomo's `fallback` groups health-check every 300 s and skip dead nodes. A node that is flagged or listed after the probe stays in the YAML until the next run, which at one run every second day can take up to two days (a manual run refreshes it at once); a shorter cron interval narrows the window. That free relays come and go quickly is an assumption; no lifetime data was measured. |
| PublicVPNList free keys expire after 24 hours | mitigated | This repository uses a permanent key (confirmed by the maintainer). With a temporary key an unattended run gets HTTP 401 and the source drops out; the other sources continue and the last-good cache covers the gap for 4 days. |
| GitHub disables the schedule of a quiet public repository | open, unverified | GitHub's documentation (read 2026-10-07): in a public repository scheduled workflows are disabled after 60 days without repository activity, and `schedule` runs can be delayed or dropped under load. The YAML is deterministic, so commits only happen when the selection changes, which the strict policy can make rare. Whether this repository is public, and whether the workflow's own pushes count as activity, was not checked. If the schedule stops, re-enable the workflow in the Actions tab. |

### P0 — version metadata skew

Fix `gate_us_lite.__version__` so it matches `pyproject.toml` and add a regression test that asserts one source of truth.

### P0 — no real Mihomo binary validation in CI

CI now downloads a pinned Mihomo validator, verifies its SHA-256, and runs `mihomo -t -f mihomo.yaml` before any commit. This catches renderer/schema drift before publication.

Do this only with a pinned/reproducible download and checksum/version policy; do not silently curl an unpinned latest binary.

### P0/P1 — no live-source integration smoke test separate from generation

Most tests mock source responses. Production generation itself exercises real sources, but there is no small explicit source-contract smoke test that reports which adapter changed format. Consider adding adapter diagnostics to the scheduled/manual workflow logs while keeping repository output limited to `mihomo.yaml`.

### P1 — PublicVPNList freshness is underused

`last_checked_at` is stored but not currently part of hard freshness filtering. `status=online` plus technical score helps, but the selector could explicitly penalize or reject stale checker timestamps.

### P1 — PublicVPNList source-family normalization is narrow

Only VPNGate and IPSpeed are normalized specially. If PublicVPNList exposes more upstream sources, extend normalization carefully so mirrors do not masquerade as independent evidence.

### P1 — tunnel probe scope and trust boundary

The tunnel probe proves an OpenVPN handshake and a Cloudflare trace fetch from the runner at generation time. Results still reflect the runner's network rather than the user's, and a node can die before the next scheduled run.

The probe makes a runner dial untrusted servers. It therefore runs in its own job without secrets or a write token, and its Mihomo child additionally gets a scrubbed environment. A vulnerability in Mihomo's OpenVPN client would still run with that job's runtime token (needed for artifacts and cache), so a compromised probe job could in principle write artifacts or caches of this repository. The candidate pool and the selector state are protected by fingerprints taken in `collect` and verified by `publish`, the verdicts are filtered by `publish`, and every published node must additionally look clean to ipwho and ProxyCheck. What stays open is a forged Actions cache entry: a later `collect` restores the newest entry with the state key prefix and trusts it, and nothing downstream can tell it from the genuine one. The realistic worst case is promoting a relay the attacker also operates with forged history and intelligence, which is the situation the trust model already assumes for any volunteer relay, only chosen instead of random. Signing the cache was considered and rejected: the key would have to live in a job that parses untrusted upstream data, and the state changes during `collect`, so `publish` could not verify a signature over the restored bytes. A candidate hardening that needs a real GitHub run to validate is starting the Mihomo child as an unprivileged user (for example `sudo -n -u nobody`) so that it cannot read the runner's process environment; it was not added because it cannot be exercised outside GitHub and a mistake would leave the probe permanently red (fail closed). I did not verify how far GitHub scopes the runtime token (for example whether one job can replace another job's artifact), so treat the isolation as a strong reduction of the blast radius, not as a guarantee.

As of 2026-10-07 a node completing the handshake has not been observed from a development machine (all tested nodes were unreachable from there); check the `[tunnel] ... alive=` line of the first scheduled run.

### P1 — runner-network bias

GitHub-hosted runner reachability and latency are not the same as the final user's network. Keep runner probes as soft evidence only.

### P1 — IP reputation remains incomplete

No public combination can guarantee acceptance by AI providers, Google, financial services, or other private risk systems. A fixed-line ISP classification is not equivalent to a private residential IP. VPNGate-family nodes are publicly shared VPN relays and may be recognized as such by destination services. Candidate detectors were checked on 2026-10-07: ipapi.is no longer returns `is_datacenter`, `is_vpn`, `is_proxy`, `is_tor` or `is_abuser` without an API key (a free account with a key returns them and allows 1,000 lookups per day), so it would be a second key-requiring provider; its recall on volunteer relays could not be measured without a key, and no gap that a second provider would close has been demonstrated, so it was not added.

### P2 — optional front/dialer proxy

CFNext uses a Cloudflare tunnel in front of VPNGate to solve networks that cannot directly establish some OpenVPN connections. Do **not** copy that architecture by default. If real user evidence later shows direct OpenVPN reachability is the bottleneck, add an optional Mihomo `dialer-proxy` field rather than turning this project into a Cloudflare tunneling platform.

### P2 — additional independent sources

Only add another source when it meaningfully increases independent US endpoint coverage or resilience. Do not count mirrors of the same VPNGate data as source diversity. IPSpeed's own page sits behind a Cloudflare managed challenge that the stdlib HTTP client cannot pass, and VPNBook's US servers are OVH hosting addresses (ProxyCheck `network.type = Hosting`) behind a JavaScript-driven download page, so they would be rejected as hosting anyway; revisit either only with new evidence.

## 22. Recommended next optimization order

### P0 — correctness/release hygiene

1. synchronize version metadata;
2. add a version-consistency test;
3. add pinned real-Mihomo config validation to Actions;
4. keep all existing regression tests green.

### P1 — quality and observability

1. add PublicVPNList `last_checked_at` freshness handling;
2. improve source-family normalization/provenance;
3. expose concise per-source health in GitHub Actions step summary/logs without generating another repository artifact;
4. add integration fixtures captured from real source shapes when adapters change;
5. review whether 24h intel cache is the right TTL for abuse/risk signals separately from ASN/ISP identity.

### P2 — only if real usage justifies it

1. optional `dialer-proxy` support for networks where direct OpenVPN is unreliable;
2. one or two additional genuinely independent free OpenVPN sources;
3. optional country generalization if the project is no longer US-only.

## 23. Explicit non-goals for future agents

Unless the user explicitly changes direction, do **not**:

- add a local daemon or systemd service;
- add a Web UI;
- add Docker/Kubernetes;
- turn this into an HTTP/SOCKS gateway;
- add a database server beyond SQLite Actions state;
- introduce AI/LLM ranking;
- output hundreds of nodes just because a source provides them;
- perform constant latency-based primary switching;
- trust arbitrary OVPN directives;
- add many mirrors and call them independent sources;
- copy CFNext's TCP-only restriction (it exists because of Cloudflare Worker transport constraints, not because UDP OpenVPN is inherently undesirable here).

## 24. External facts last re-verified for this handoff

Re-verified on 2026-10-02 and 2026-10-07:

- PublicVPNList currently requires Bearer-key access for API/downloads; temporary access is 24 hours and permanent personal access is reviewed individually.
- PublicVPNList states that its technical quality score is a reachability/performance/freshness signal, not a privacy/identity/trust assessment.
- Mihomo currently documents OpenVPN fields including `tls-auth`, `key-direction`, `tls-crypt`, and `tls-crypt-v2`.
- Mihomo `fallback` selects the first available node in configured order when the current node times out.
- The ipwho.is free tier returns no `security` object.
- ProxyCheck v3 returns `detections` (`tor`, `hosting`, `anonymous`, `risk`, ...), `network.type` and `operator.services`; its documentation puts risk 0-25 in the "allow" band for addresses that are not anonymous and lists base scores of hosting 33, VPN 50, scraper and Tor 75, proxy and compromised 100.
- `actions/upload-artifact`, `actions/download-artifact` and `actions/cache/{restore,save}` expose the inputs the workflow uses (`include-hidden-files`, `retention-days`, `if-no-files-found`, `name`, `path`, `key`, `restore-keys`).
- PublicVPNList publishes IPSpeed rows; VPNBook is metadata-only there and not published through the API.
- Mihomo v1.19.31 `mixed` listeners accept `proxy: <outbound>`, and its OpenVPN handshake gives up after about 5 seconds.
- ProxyCheck v3 documents that every key is always present with `null` for missing data, supports `days` between 0.01 and 60 (default behavior is a conservative 2-7 day window), recommends longer windows plus the confidence score for deployments that prefer blocking over false negatives, and allows 1,000 queries per day on a free key.
- AbuseIPDB's `check` response carries `usageType` (for example `Data Center/Web Hosting/Transit`) and `isTor`; usage type, ISP and domain come from IPinfo.
- ipapi.is serves only eleven geolocation and ownership fields without an API key (no detection flags since 2026-09-01) and 30 lookups per client IP per day.
- PublicVPNList documents that unknown third-party endpoints can log or alter traffic and that its JSON API permits 60 requests per minute.
- The GitHub refs API resolved `actions/checkout@v7`, `actions/setup-python@v7`, `actions/cache@v6`, `actions/upload-artifact@v7` and `actions/download-artifact@v8` to the commits pinned in the workflow.
- CFNext documents VPNGate cache protection: low server count can force refresh, failed refresh falls back to cached data, and its VPNGate path was motivated by observed incomplete snapshots.

Reference URLs are kept in `SOURCES.md`.

## 25. Safe handoff procedure for the next agent

Before changing code:

```bash
python -m unittest discover -s tests -v
python -m compileall -q gate_us_lite tests
```

Then read, in order:

1. `SUMMARY.md`
2. this `HANDOFF.md`
3. `README.md`
4. `config.toml`
5. `.github/workflows/generate-mihomo.yml`
6. `gate_us_lite/cli.py` and `gate_us_lite/pipeline.py`
7. `gate_us_lite/sources.py`
8. `gate_us_lite/ovpn.py`
9. `gate_us_lite/store.py`
10. `gate_us_lite/select.py`
11. `tests/`

For every behavioral change:

- preserve the untrusted-OVPN security boundary;
- preserve fresh/cache separation;
- preserve last-good behavior on source failure/degradation;
- add or update a regression test;
- rerun unit tests and compileall;
- keep the normal repository artifact contract to `mihomo.yaml` only.
