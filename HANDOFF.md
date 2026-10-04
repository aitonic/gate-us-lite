# gate-us-lite v0.3.1 — Engineering Handoff

> Handoff snapshot: 2026-10-02  
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
5. prefer stable US ISP-like endpoints while avoiding obvious hosting/Tor/residential-proxy/high-abuse candidates;
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
- unit tests: **33**

Verification performed for this handoff:

```bash
python -m unittest discover -s tests -v
python -m compileall -q gate_us_lite tests
```

Result after the audit remediation: **33 tests passed; compileall passed**.

### Version consistency

`pyproject.toml` and `gate_us_lite/__init__.py` are both `0.3.1`. A regression test now enforces this invariant.

## 3. Repository map

```text
.
├── .github/workflows/generate-mihomo.yml
├── README.md
├── SOURCES.md
├── HANDOFF.md
├── SUMMARY.md
├── config.toml
├── pyproject.toml
├── tests/test_core.py
└── gate_us_lite/
    ├── __init__.py
    ├── __main__.py
    ├── cli.py
    ├── config.py
    ├── http.py
    ├── intel.py
    ├── mihomo.py
    ├── models.py
    ├── ovpn.py
    ├── probe.py
    ├── select.py
    ├── sources.py
    └── store.py
```

### Module ownership

| Module | Responsibility |
|---|---|
| `cli.py` | Orchestration, source concurrency, degraded-source handling, TCP probes, enrichment, selection, atomic output |
| `sources.py` | VPNGate, IPSpeed, VPNBook, PublicVPNList, Vpngate-Scraper adapters |
| `ovpn.py` | Security-sensitive OpenVPN allow-list parser |
| `intel.py` | IP/public-network validation, ipwho.is, optional ProxyCheck, optional AbuseIPDB, ISP/hosting heuristics |
| `store.py` | SQLite observations, source snapshots, last-good caches, probe history, intel cache, sticky selection state |
| `select.py` | Deduplication, rough rank, risk evaluation, Preferred/Fallback selection, ASN diversity, sticky primary |
| `probe.py` | Lightweight TCP connect probe only; not a full OpenVPN handshake |
| `mihomo.py` | Deterministic Mihomo OpenVPN node + fallback-group rendering |
| `config.py` | TOML defaults + optional secret environment variables |

## 4. GitHub Actions contract

Workflow: `.github/workflows/generate-mihomo.yml`

Triggers:

```yaml
workflow_dispatch:
schedule:
  - cron: "7,37 * * * *"
```

The run interval is therefore approximately every 30 minutes, offset from the top of the hour.

Important workflow properties:

- `permissions: contents: write`
- no `pull_request` or `pull_request_target` trigger
- `concurrency.cancel-in-progress: true`
- `timeout-minutes: 12`
- Actions cache persists `.state/`
- tests run before generation
- `mihomo.yaml` is validated by a pinned real Mihomo binary before publication
- only `mihomo.yaml` is staged and committed
- no commit occurs when YAML is unchanged

The repository token must be allowed to push to the default branch. Branch protection may need an explicit exception depending on repository policy.

## 5. Data-source model

Enabled by default:

| Adapter | Role | `source_family` behavior |
|---|---|---|
| VPN Gate official | primary volunteer-relay source | `vpngate` |
| IPSpeed | independent OpenVPN source | `ipspeed` |
| VPNBook | relatively fixed official US configs | `vpnbook` |
| PublicVPNList | optional verified/full-tunnel catalog | preserves upstream family where identifiable |
| Vpngate-Scraper-API | VPNGate recovery/mirror source | `vpngate` |

### Why `source_family` exists

Mirrors must not be treated as independent confirmation. For example, a VPNGate server seen via VPNGate official, Vpngate-Scraper, and PublicVPNList-with-source=VPNGate still represents one underlying source family.

PublicVPNList source normalization currently recognizes strings containing:

- `vpngate`
- `ipspeed`
- `vpnbook`

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

### `ABUSEIPDB_API_KEY`

Optional enrichment only. When configured, the code requests recent 30-day abuse data and stores:

- abuse confidence;
- total reports;
- last reported timestamp.

Current behavior when absent: **AbuseIPDB enrichment is skipped**.

### `PROXYCHECK_API_KEY`

Optional enrichment only. When configured, the code requests proxy/VPN/risk/ASN data and derives a residential-proxy signal.

Current behavior when absent: **ProxyCheck enrichment is skipped**. The current implementation does not use ProxyCheck anonymous mode.

### Zero-key intelligence

`ipwho.is` remains the baseline zero-key IP intelligence source and contributes:

- country code;
- ASN;
- ISP/org/domain;
- proxy/VPN/Tor/hosting security flags when returned.

Failures are soft and stored as enrichment error fields rather than aborting the run.

## 7. Current end-to-end pipeline

```text
VPNGate ----------\
IPSpeed -----------+
VPNBook -----------+--> fetch concurrently
PublicVPNList -----+
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
         top-N IP enrichment
                 |
    risk evaluation + history score
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

Small naturally sparse sources such as VPNBook do not trigger this rule when their baseline is below the configured minimum.

## 9. Fresh-vs-cache invariant

This is an important correctness rule:

> Cached candidates may preserve generation continuity, but cached candidates must never be counted as if they were freshly observed in the current run.

`cli.py` therefore maintains separate collections:

- `fresh_gathered`
- `generation_gathered`

Only `fresh_gathered` reaches `Store.observe()`.

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

## 13. TCP soft probe semantics

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

## 14. IP-quality model

The selector intentionally separates hard rejection from soft ranking.

### Hard rejection

Current hard reject reasons include:

- invalid/non-public IP;
- US country mismatch when intelligence has a country code;
- Tor;
- residential-proxy signal;
- severe recent AbuseIPDB confidence (`>= 80`) when AbuseIPDB data exists.

### Preferred-only restrictions

A candidate may still be allowed into Fallback but excluded from Preferred when:

- hosting/datacenter is detected and `reject_hosting = true`;
- optional ProxyCheck proxy status is enabled for rejection;
- source ping exceeds threshold;
- source speed is too low;
- enough history exists and 24h availability is below threshold;
- a TCP node has reached the consecutive-failure limit.

### Ranking boosts/penalties

Signals include:

- PublicVPNList technical validation;
- VPNBook/IPSpeed source-family weight;
- source 7-day uptime;
- source uptime;
- speed and ping;
- TCP reachability;
- locally observed 24h/7d availability;
- fixed-line ISP heuristics;
- hosting heuristics;
- optional ProxyCheck risk;
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
- internal `SOURCE_CACHE_SCHEMA = 2`;
- schema mismatch invalidates the old cache rather than silently deserializing incompatible candidate data.

### IP intelligence cache

Current TTL: 24h.

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
source_baseline_window = 12
source_low_watermark_ratio = 0.40
source_low_watermark_min_baseline = 4

[filters]
max_ping_ms = 250
min_speed_mbps = 0.5
reject_hosting = true
reject_tor = true
reject_proxy = false
reject_residential_proxy = true
reject_country_mismatch = true
min_preferred_availability_24h = 0.25
max_preferred_tcp_fail_streak = 2
```

These values are conservative defaults, not universal truth. Changes should be justified by observed run data rather than intuition.

## 19. Failure behavior

### One source fails

Use a recent last-good cache for that source and continue with all other sources.

### Source returns an abnormally small non-empty result

Mark `degraded`, keep the fresh data as evidence, merge last-good cache for generation, and do not replace the cache.

### PublicVPNList key missing/expired

Skip/fail that adapter only; other sources continue.

### IP intelligence provider fails

Keep whatever other intelligence succeeded. A single enrichment provider failure should not fail generation.

### No acceptable candidate remains

Return non-zero and do **not** atomically replace `mihomo.yaml`. In GitHub Actions this prevents committing an empty/broken replacement.

## 20. Tests currently protecting critical invariants

`tests/test_core.py` covers at least:

- safe OVPN parsing;
- unsafe script-hook rejection;
- LF/CRLF remote parsing;
- regression: `proto tcp` is not consumed as remote-proto text;
- Mihomo TLS-auth preservation;
- VPNGate US filter + uptime unit conversion;
- VPNGate trailing-column Base64 fallback;
- IPSpeed parsing;
- VPNBook dynamic credentials + TCP/443 normalization;
- Vpngate-Scraper config correlation;
- PublicVPNList source-family normalization;
- PublicVPNList lazy materialization;
- TCP probing;
- endpoint merge/provenance;
- ASN diversity;
- sticky primary;
- hosting-only fallback behavior;
- repeated TCP failure behavior;
- actual-refresh-run availability denominator;
- source rolling baseline;
- source-cache schema invalidation;
- low-watermark detection;
- cached recovery not faking availability;
- generator writes YAML only.

## 21. Known limitations and risks

These are the most useful starting points for future work.

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

Only VPNGate/IPSpeed/VPNBook are normalized specially. If PublicVPNList exposes more upstream sources, extend normalization carefully so mirrors do not masquerade as independent evidence.

### P1 — VPNBook adapter is HTML/config-discovery sensitive

The implementation intentionally tries several config URL patterns and dynamically parses current credentials. A site layout change can reduce this source to zero. Keep failure isolated; do not make VPNBook a required source.

### P1 — no full OpenVPN handshake from GitHub Actions

The TCP probe checks only endpoint port reachability. UDP has no equivalent probe, and neither TCP nor UDP is validated through a complete OpenVPN session by this project. PublicVPNList can provide externally verified tunnel data when enabled, and Mihomo performs runtime health checks later.

### P1 — runner-network bias

GitHub-hosted runner reachability and latency are not the same as the final user's network. Keep runner probes as soft evidence only.

### P1 — IP reputation remains incomplete

No public combination can guarantee acceptance by AI providers, Google, financial services, or other private risk systems. A fixed-line ISP classification is not equivalent to a private residential IP. VPNGate-family nodes are publicly shared VPN relays and may be recognized as such by destination services.

### P2 — optional front/dialer proxy

CFNext uses a Cloudflare tunnel in front of VPNGate to solve networks that cannot directly establish some OpenVPN connections. Do **not** copy that architecture by default. If real user evidence later shows direct OpenVPN reachability is the bottleneck, add an optional Mihomo `dialer-proxy` field rather than turning this project into a Cloudflare tunneling platform.

### P2 — additional independent sources

Only add another source when it meaningfully increases independent US endpoint coverage or resilience. Do not count mirrors of the same VPNGate data as source diversity.

## 22. Recommended next optimization order

### P0 — correctness/release hygiene

1. synchronize version metadata;
2. add a version-consistency test;
3. add pinned real-Mihomo config validation to Actions;
4. keep all 23 existing regression tests green.

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

Re-verified on 2026-10-02:

- PublicVPNList currently requires Bearer-key access for API/downloads; temporary access is 24 hours and permanent personal access is reviewed individually.
- PublicVPNList states that its technical quality score is a reachability/performance/freshness signal, not a privacy/identity/trust assessment.
- Mihomo currently documents OpenVPN fields including `tls-auth`, `key-direction`, `tls-crypt`, and `tls-crypt-v2`.
- Mihomo `fallback` selects the first available node in configured order when the current node times out.
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
6. `gate_us_lite/cli.py`
7. `gate_us_lite/sources.py`
8. `gate_us_lite/ovpn.py`
9. `gate_us_lite/store.py`
10. `gate_us_lite/select.py`
11. `tests/test_core.py`

For every behavioral change:

- preserve the untrusted-OVPN security boundary;
- preserve fresh/cache separation;
- preserve last-good behavior on source failure/degradation;
- add or update a regression test;
- rerun unit tests and compileall;
- keep the normal repository artifact contract to `mihomo.yaml` only.
