# gate-us-lite v0.3.1 — Project Summary

## What this project is

A lightweight **GitHub Actions-only** pipeline that automatically finds, filters, ranks, and publishes a small set of US OpenVPN endpoints as a Mihomo configuration.

Its practical goal is to provide stable US egress candidates for AI applications and development traffic without operating a local VPN-management service.

Normal runtime:

```text
multiple public OpenVPN sources
        ↓
source-health protection
        ↓
safe OVPN normalization
        ↓
IP + stability evaluation
        ↓
3 Preferred + up to 8 Fallback
        ↓
mihomo.yaml
```

There is no local daemon, systemd service, Docker deployment, Web UI, SOCKS/HTTP gateway, or external database.

## Why it exists

VPNGate alone can have very few US servers in a given snapshot and public VPN lists can fluctuate or partially fail. A useful long-running configuration therefore needs both:

- **source diversity** — more than one independent source;
- **quality control** — avoid blindly publishing every available node.

The project combines both while staying small.

## Current data sources

1. **VPN Gate official API** — volunteer relay source.
2. **IPSpeed** — independent OpenVPN list.
3. **VPNBook** — official free OpenVPN endpoints.
4. **PublicVPNList** — optional authenticated catalog with technical verification data.
5. **Vpngate-Scraper-API** — recovery/mirror source, explicitly treated as the same VPNGate source family.

The project tracks `source_family` so mirrors do not create fake source diversity.

## Current selection philosophy

The goal is **not** "pick the lowest ping every five minutes".

The project prefers:

- US endpoints;
- stable recent availability;
- fixed-line ISP-like networks;
- non-hosting/non-Tor/non-residential-proxy candidates;
- reasonable source speed/ping;
- ASN diversity;
- a previous primary that is still healthy.

This reduces unnecessary egress-IP churn.

## v0.3.0 improvements inspired by CFNext

The current version absorbed six useful operational ideas without copying CFNext's Cloudflare tunnel architecture:

1. **Low-watermark snapshot protection**  
   A suspiciously small but non-empty source response no longer overwrites the last-good cache.

2. **Fresh/cache separation**  
   Cached recovery nodes can keep generation alive but cannot fake 24h/7d availability.

3. **PublicVPNList lazy materialization**  
   Metadata is ranked first; only the best subset has full OVPN configs downloaded.

4. **VPNGate Base64 fallback**  
   The named CSV column is preferred, with a tightly constrained trailing-column fallback for upstream layout changes.

5. **TCP soft probe**  
   TCP reachability from GitHub Actions is used as a small ranking signal, not as a hard truth about the user's network.

6. **Versioned source cache**  
   Incompatible cached candidate schemas are invalidated automatically.

A separate OpenVPN parser regression was also fixed: a `proto tcp` line can no longer be accidentally consumed as the optional protocol on the preceding `remote` line.

## GitHub Actions behavior

Workflow:

```text
.github/workflows/generate-mihomo.yml
```

Runs:

- every 30 minutes at minute 7 and 37;
- manually via `workflow_dispatch`.

Each run:

1. checks out the default branch;
2. uses Python 3.13;
3. restores `.state` from Actions cache;
4. runs all tests;
5. generates `mihomo.yaml`;
6. validates the generated configuration with a pinned real Mihomo binary in CI;
7. commits only if `mihomo.yaml` changed.

If generation cannot produce a safe node, the workflow fails and does **not** replace the previous YAML with an empty file.

## Output

The only normal generated repository artifact is:

```text
mihomo.yaml
```

It contains:

- `US-Pxx-*` Preferred nodes, maximum 3;
- `US-Bxx-*` Fallback nodes, maximum 8;
- `US-PREFERRED` Mihomo fallback group;
- `US-STABLE` recommended fallback group.

Mihomo fallback behavior matches the design: it uses the first healthy node in configured order rather than continually chasing tiny latency differences.

## State

Actions cache persists:

```text
.state/state.sqlite3
```

State includes:

- actual refresh runs;
- fresh endpoint observations;
- 1h/24h/7d availability;
- TCP probe history;
- source-count baselines;
- last-good source candidate caches;
- IP-intelligence cache;
- previous Preferred/Fallback selection.

SQLite is runtime state only and is not intended to be committed.

## API keys

All keys are optional for the overall generator:

```text
PUBLICVPNLIST_API_KEY
ABUSEIPDB_API_KEY
PROXYCHECK_API_KEY
```

Behavior:

- no PublicVPNList key -> PublicVPNList source is skipped;
- no AbuseIPDB key -> abuse enrichment is skipped;
- no ProxyCheck key -> ProxyCheck enrichment is skipped;
- `ipwho.is` remains the zero-key baseline IP/ASN/ISP source.

For scheduled long-term use, PublicVPNList permanent access is preferable to its 24-hour temporary key.

## Security model

Downloaded `.ovpn` files are treated as hostile input.

The project does **not** pass arbitrary OpenVPN profiles through to Mihomo. It rejects executable/plugin/management directives and rebuilds only a small allow-listed model.

Supported embedded material currently includes:

- CA;
- client cert/key;
- username/password authentication;
- `tls-auth` / `key-direction`;
- `tls-crypt`;
- `tls-crypt-v2`;
- safe cipher/auth/data-cipher fields;
- `comp-lzo` in known values.

This boundary should remain strict.

## Current validation state

Re-verified for this handoff on 2026-10-02:

```text
30 unit tests: PASS
compileall: PASS
```

Current tests cover source parsing, OVPN safety, source-aware availability, deterministic merge behavior, mirror-family evidence, Intel fail-open protection, bounded source materialization, TCP probe behavior, version consistency, selection behavior, and Mihomo rendering.

## Audit remediation status

The audit findings have been implemented in this revision:

- package version metadata is synchronized at `0.3.1` and regression-tested;
- availability denominators are source-aware and ignore `error` / `empty` / `degraded` runs as valid observation opportunities;
- mirror provenance no longer creates fake independent-source score;
- candidate merging is deterministic and source-priority driven;
- unknown IP intelligence cannot enter Preferred; failed intelligence lookups use a short retry cache;
- PublicVPNList uses bounded freshness and checked-tunnel measurements where available;
- secondary source profile materialization is bounded by count and per-profile timeout;
- OVPN keepalive fields are preserved as Mihomo `ping` / `ping-restart`;
- health checks require HTTP 204;
- GitHub Actions validates `mihomo.yaml` with a pinned Mihomo binary before commit.

### Remaining non-blocking follow-ups

- `source_state` remains diagnostic persistence rather than an active decision input;
- live upstream contract drift still depends on scheduled-run diagnostics and tests;
- pinning the Mihomo validator means its version should be bumped deliberately rather than following `latest`.

## Things not to add by default

Keep the project light. Do not add unless the user explicitly changes the goal:

- local service/daemon;
- Web UI;
- Docker/Kubernetes;
- HTTP/SOCKS proxy server;
- AI-based ranking;
- huge output lists;
- aggressive latency-driven IP switching;
- arbitrary OVPN pass-through;
- Cloudflare tunneling copied wholesale from CFNext;
- many VPNGate mirrors presented as independent sources.

## Key references

- VPN Gate API: https://www.vpngate.net/api/iphone/
- VPNGateSub: https://github.com/HXinTeam/VPNGateSub
- gatevpn: https://github.com/illria/gatevpn
- Vpngate-Scraper-API: https://github.com/fdciabdul/Vpngate-Scraper-API
- CFNext: https://github.com/PAICNI/CFNext
- PublicVPNList API: https://publicvpnlist.com/api/
- Mihomo OpenVPN: https://wiki.metacubex.one/en/config/proxies/openvpn/
- Mihomo fallback: https://wiki.metacubex.one/en/config/proxy-groups/fallback/

For implementation-level detail, read `HANDOFF.md` next.
