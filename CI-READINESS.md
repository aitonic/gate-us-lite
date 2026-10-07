# GitHub Actions CI Readiness — v0.3.1

This is a deployment preflight for `.github/workflows/generate-mihomo.yml`.

## Result

The repository is ready to run on a standard GitHub-hosted `ubuntu-latest` runner once the workflow is present on the repository default branch.

Verified locally:

- Python 3.13 test suite passes.
- `python -m compileall` passes.
- `python -m gate_us_lite --config config.toml --state .state/state.sqlite3 --output mihomo.yaml` runs the stages in one process and exits with code 2 (nothing published) when no node is acceptable or 3 when the tunnel probe is unavailable.
- generated YAML has the expected proxy and group markers.
- the workflow has three jobs (`collect` -> `probe` -> `publish`); only `publish` has `contents: write` (for the generated-file commit) and the publishing secrets, and the `probe` job that dials untrusted VPN servers has neither secrets nor a write token (workflow contract tests and `actionlint` pass).
- every third-party action is pinned to a full commit SHA; `publish` verifies the SHA-256 of the candidate pool and of the selector state before it fetches the verdicts, and only caches a state that passed; `cancel-in-progress` is `false` so a publishing run is never cancelled half-way.
- exact Mihomo v1.19.31 Linux amd64-v1 asset SHA-256 is pinned and verified by the local composite action `.github/actions/install-mihomo` in every job, before the tests, the tunnel probe and `mihomo -t` validation.
- selector-state cache restore is optional; a cache service failure does not block generation.
- a corrupted restored SQLite database is detected with `PRAGMA quick_check` and discarded automatically.
- IP-intelligence requests are budgeted at 6 seconds, zero retries, six workers by default; transient provider failures turn the affected nodes unknown (not published, retried after 15 minutes) rather than exhausting the job timeout.
- Mihomo binary download has connect and total time limits.

## Required GitHub repository settings

Add these repository Actions secrets (values are never stored in the repository):

- `PUBLICVPNLIST_API_KEY`
- `ABUSEIPDB_API_KEY`
- `PROXYCHECK_API_KEY` (effectively required: without it `publish` fails with exit code 4 and an explicit message; the free tier allows 1,000 queries per day)

The workflow file must be committed to the default branch for scheduled and manual dispatch behavior.

The repository or organization must allow GitHub Actions to use a writable `GITHUB_TOKEN`, and branch/ruleset policy must permit `github-actions[bot]` to push the generated `mihomo.yaml` to the default branch. If the default branch requires pull requests or blocks bot pushes, generation and validation can succeed while the final `git push` fails; that is a repository policy issue rather than an application failure.

## First-run behavior

No existing `.state` cache is required. The first run creates the SQLite state database. If an external source is unavailable the pipeline falls back to its last-good cache; if an intelligence provider is unavailable the affected nodes are unknown and are not published. A run only publishes when at least one node passed the tunnel probe and every safety check and the generated YAML passes Mihomo validation; `PROXYCHECK_API_KEY` is effectively required for that.

## Suggested first GitHub run

Use **Actions → Generate Mihomo US VPN list → Run workflow** once after adding the three secrets. Check the `Probe tunnels` step of the `probe` job, then the `Generate mihomo.yaml`, `Validate with Mihomo binary`, and `Commit generated YAML when changed` steps of the `publish` job. Read the `[tunnel] probed=... alive=... failed=...` line of the `probe` job and the `[intel]`/`[select] rejected: ...` lines of the `publish` job: the three-job workflow and the tunnel probe have not yet run on a GitHub-hosted runner, and if every candidate fails for the same reason the probe or client compatibility is more likely at fault than the nodes (the `[tunnel]` line lists the three most common reasons). The `[select] rejected:` line shows which safety rule removed how many nodes; a long run of exit code 2 means the strict policy leaves nothing, not that the pipeline is broken. If `PUBLICVPNLIST_API_KEY` is set but the `collect` log shows `[warn] publicvpnlist: <records> records, <n> with a download link, 0 usable profiles (...)`, the log names the stage that lost the records; HTTP 401 means the key (a free one lasts 24 hours) expired. After that, the scheduled runs (every second day at 03:07 UTC) can operate unattended.
