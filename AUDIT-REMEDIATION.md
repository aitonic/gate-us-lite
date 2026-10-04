# Audit remediation changelog

This package applies the architecture/logic audit fixes requested after the v0.3.0 handoff.

## P0/P1 fixes

- Source-aware availability denominator (`source_refreshes`).
- Degraded/error/empty/skipped runs no longer punish endpoint availability.
- Cached last-good nodes no longer fake live observations.
- `source_family`/`evidence_families` now prevents mirror fake diversity.
- Deterministic canonical candidate merge independent of thread completion order.
- IP-intelligence unknown state is fail-closed for Preferred; failed lookup cache is short-lived.
- Safer hosting keyword matching (`colo` no longer matches `Colorado`; overly broad `server` removed).
- PublicVPNList freshness query and additional checked-tunnel timing signals.
- Bounded secondary OVPN materialization and per-profile fetch timeout.
- OVPN `keepalive`, `ping`, `ping-restart` retention.
- Mihomo group `expected-status: 204`.
- Real pinned Mihomo CI validation with SHA-256 verification.
- Package version synchronization and regression test.

## Verification

- `python -m unittest discover -s tests -v`: 30/30 PASS
- `python -m compileall -q gate_us_lite tests`: PASS
