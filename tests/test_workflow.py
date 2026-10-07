import re
import unittest
from pathlib import Path

from gate_us_lite.config import DEFAULTS

WORKFLOW = Path(".github/workflows/generate-mihomo.yml")
INSTALL_ACTION = Path(".github/actions/install-mihomo/action.yml")


def split_jobs(text: str) -> dict[str, str]:
    parts = re.split(r"(?m)^  ([a-z]+):\n", text.split("\njobs:\n", 1)[1])
    return dict(zip(parts[1::2], parts[2::2]))


def assert_in_order(case: unittest.TestCase, text: str, *markers: str) -> None:
    positions = [text.index(marker) for marker in markers]
    case.assertEqual(positions, sorted(positions), markers)


class TestWorkflowContract(unittest.TestCase):
    def setUp(self):
        self.text = WORKFLOW.read_text(encoding="utf-8")
        self.jobs = split_jobs(self.text)

    def test_untrusted_servers_are_dialed_in_a_separate_job(self):
        self.assertEqual(list(self.jobs), ["collect", "probe", "publish"])
        self.assertIn("needs: collect\n", self.jobs["probe"])
        self.assertIn("needs: [collect, probe]\n", self.jobs["publish"])

    def test_probe_job_has_neither_secrets_nor_a_write_token(self):
        probe = self.jobs["probe"]
        self.assertIn("permissions:\n  contents: read\n", self.text.split("\njobs:\n")[0])
        for forbidden in ("secrets.", "permissions:", "contents: write", "github.token", "GITHUB_TOKEN"):
            self.assertNotIn(forbidden, probe)
        self.assertIn("persist-credentials: false", probe)
        self.assertIn("python -m gate_us_lite probe", probe)

    def test_only_publish_holds_write_access_and_publishing_secrets(self):
        for name in ("collect", "probe"):
            for forbidden in ("contents: write", "DIST_REPO_TOKEN", "ABUSEIPDB_API_KEY", "PROXYCHECK_API_KEY"):
                self.assertNotIn(forbidden, self.jobs[name], name)
        publish = self.jobs["publish"]
        for required in ("permissions:\n      contents: write\n", "DIST_REPO_TOKEN", "ABUSEIPDB_API_KEY", "PROXYCHECK_API_KEY"):
            self.assertIn(required, publish)
        self.assertIn("PUBLICVPNLIST_API_KEY", self.jobs["collect"])
        self.assertNotIn("PUBLICVPNLIST_API_KEY", publish)

    def test_every_job_has_a_timeout(self):
        for name, body in self.jobs.items():
            with self.subTest(name):
                self.assertRegex(body, r"(?m)^    timeout-minutes: \d+$")

    def test_third_party_actions_are_pinned_to_one_full_commit_sha_each(self):
        pins = re.findall(r"(?m)^ +uses: (?!\./)(.+)$", self.text)
        shas_by_action: dict[str, set[str]] = {}
        for pin in pins:
            self.assertRegex(pin, r"^[\w.-]+/[\w./-]+@[0-9a-f]{40} # v\d+\.\d+\.\d+$")
            action, sha = pin.split(" # ")[0].split("@")
            shas_by_action.setdefault(action, set()).add(sha)
        self.assertEqual(set(shas_by_action), {
            "actions/checkout", "actions/setup-python", "actions/cache/restore", "actions/cache/save",
            "actions/upload-artifact", "actions/download-artifact",
        })
        for action, shas in shas_by_action.items():
            self.assertEqual(len(shas), 1, action)
        self.assertIn("uses: ./.github/actions/install-mihomo", self.text)

    def test_collect_job_tests_the_code_before_it_touches_the_network_sources(self):
        assert_in_order(
            self, self.jobs["collect"],
            "name: Install pinned Mihomo", "name: Run tests", "name: Restore selector state",
            "name: Collect candidates", "name: Fingerprint handoff files", "name: Upload candidate pool",
            "name: Upload selector state",
        )

    def test_publish_job_verifies_trusted_artifacts_before_fetching_the_untrusted_one(self):
        publish = self.jobs["publish"]
        assert_in_order(
            self, publish,
            "name: Download candidate pool", "name: Download selector state", "name: Verify handoff integrity",
            "name: Download tunnel verdicts", "name: Generate mihomo.yaml",
        )
        for output in ("needs.collect.outputs.candidates_sha256", "needs.collect.outputs.state_sha256"):
            self.assertIn(output, publish)
        self.assertIn("sha256sum --check --strict", publish)

    def test_publish_job_publishes_only_validated_output(self):
        assert_in_order(
            self, self.jobs["publish"],
            "name: Generate mihomo.yaml", "name: Save selector state", "name: Validate with Mihomo binary",
            "name: Commit generated YAML", "name: Verify DIST_REPO_TOKEN", "name: Publish generated YAML",
        )
        self.assertIn("python -m gate_us_lite finish", self.jobs["publish"])
        self.assertIn("$MIHOMO_BIN -t -f mihomo.yaml", self.jobs["publish"])

    def test_state_is_saved_after_a_failed_generation_but_never_without_the_integrity_check(self):
        publish = self.jobs["publish"]
        save = publish.split("name: Save selector state", 1)[1].split("      - name:", 1)[0]
        self.assertIn("if: ${{ !cancelled() && steps.generate.conclusion != 'skipped' }}", save)
        self.assertIn("continue-on-error: true", save)
        self.assertIn("id: generate", publish.split("name: Generate mihomo.yaml", 1)[1].split("      - name:", 1)[0])

    def test_handoff_artifacts_are_short_lived_and_required(self):
        uploads = re.findall(r"(?s)uses: actions/upload-artifact@\S+ # \S+\n(.*?)(?=\n      - name:|\Z)", self.text)
        self.assertEqual(len(uploads), 3)
        for upload in uploads:
            self.assertIn("retention-days: 1", upload)
            self.assertIn("if-no-files-found: error", upload)
            self.assertIn("overwrite: true", upload)

    def test_schedule_and_concurrency(self):
        self.assertIn('cron: "7 3 */2 * *"', self.text)
        self.assertIn("cancel-in-progress: false", self.text)
        self.assertIn("MIHOMO_BIN: /tmp/mihomo", self.text)


class TestInstallMihomoAction(unittest.TestCase):
    def test_release_is_pinned_and_verified_before_it_is_installed(self):
        text = INSTALL_ACTION.read_text(encoding="utf-8")
        for required in (
            "MIHOMO_VERSION: v1.19.31",
            "mihomo-linux-amd64-v1-${MIHOMO_VERSION}.gz",
            "MIHOMO_SHA256: d4304c546c3cddcb6fafd4b4fddb0ba1a95ffa36606fda56d75db2e59ad24114",
        ):
            self.assertIn(required, text)
        assert_in_order(self, text, "curl --fail", "sha256sum --check --strict", 'gzip -dc /tmp/mihomo.gz > "$MIHOMO_BIN"')


class TestCiBudget(unittest.TestCase):
    def test_intel_defaults_fit_the_job_budget(self):
        general = DEFAULTS["general"]
        self.assertLessEqual(general["intel_request_timeout_seconds"], 6)
        self.assertEqual(general["intel_request_retries"], 0)
        self.assertGreaterEqual(general["intel_workers"], 6)


if __name__ == "__main__":
    unittest.main()
