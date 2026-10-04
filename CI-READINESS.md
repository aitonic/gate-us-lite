# GitHub Actions CI Readiness — v0.3.1

This is a deployment preflight for `.github/workflows/generate-mihomo.yml`.

## Result

The repository is ready to run on a standard GitHub-hosted `ubuntu-latest` runner once the workflow is present on the repository default branch.

Verified locally:

- Python 3.13 test suite passes.
- `python -m compileall` passes.
- `python -m gate_us_lite --config config.toml --state .state/state.sqlite3 --output mihomo.yaml` works with a cold/last-good state path.
- generated YAML has the expected proxy and group markers.
- workflow has `contents: write` for the generated-file commit.
- exact Mihomo v1.19.31 Linux amd64-v1 asset SHA-256 is pinned before `mihomo -t` validation.
- selector-state cache restore is optional; a cache service failure does not block generation.
- a corrupted restored SQLite database is detected with `PRAGMA quick_check` and discarded automatically.
- IP-intelligence requests are budgeted at 6 seconds, zero retries, six workers by default; transient provider failures degrade to unknown rather than exhausting the job timeout.
- Mihomo binary download has connect and total time limits.

## Required GitHub repository settings

Add these repository Actions secrets (values are never stored in the repository):

- `PUBLICVPNLIST_API_KEY`
- `ABUSEIPDB_API_KEY`
- `PROXYCHECK_API_KEY`

The workflow file must be committed to the default branch for scheduled and manual dispatch behavior.

The repository or organization must allow GitHub Actions to use a writable `GITHUB_TOKEN`, and branch/ruleset policy must permit `github-actions[bot]` to push the generated `mihomo.yaml` to the default branch. If the default branch requires pull requests or blocks bot pushes, generation and validation can succeed while the final `git push` fails; that is a repository policy issue rather than an application failure.

## First-run behavior

No existing `.state` cache is required. The first run creates the SQLite state database. If an external source or intelligence provider is unavailable, the pipeline uses its configured degraded/unknown behavior. A run only publishes when at least one acceptable node can be rendered and the generated YAML passes Mihomo validation.

## Suggested first GitHub run

Use **Actions → Generate Mihomo US VPN list → Run workflow** once after adding the three secrets. Check the `Generate mihomo.yaml`, `Validate with Mihomo binary`, and `Commit generated YAML when changed` steps. After that, the scheduled runs at minute 07 and 37 can operate unattended.
