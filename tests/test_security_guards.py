import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
GUARD_SCRIPT = REPO_ROOT / "tools" / "security_guards.py"

sys.path.insert(0, str(REPO_ROOT / "tools"))
import security_guards  # noqa: E402  (imported for its allowlist constants)


def run_guards(root: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(root / "tools" / "security_guards.py")],
        capture_output=True,
        text=True,
    )


class GuardRepoFixture(unittest.TestCase):
    """Builds a minimal repo tree the guards pass on, then breaks one thing per test.

    The guard script resolves the repo root from its own location, so each test
    copies it into a temp tree and runs it as a subprocess - the same way CI
    invokes it - asserting on real exit codes and messages.
    """

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)

        (self.root / "tools").mkdir()
        shutil.copy(GUARD_SCRIPT, self.root / "tools" / "security_guards.py")

        self.config = self.root / "opencode.json"
        self.write_config(security_guards.ALLOWED_BASH_PERMISSIONS)

        self.gitignore = self.root / ".gitignore"
        self.write_gitignore(security_guards.REQUIRED_IGNORE_RULES)

        self.manifest = self.root / ".agents" / "skills" / "example-search" / "cli" / "package.json"
        self.manifest.parent.mkdir(parents=True)
        self.write_manifest({"name": "example-cli", "scripts": {"start": "bun run src/cli.ts"}})

    def write_config(self, allow, extra=None, plugins=None):
        bash = {"*": "ask"}
        bash.update({pattern: "allow" for pattern in sorted(allow)})
        if extra:
            bash.update(extra)
        data = {"permission": {"bash": bash}}
        if plugins is not None:
            data["plugin"] = plugins
        self.config.write_text(json.dumps(data))

    def write_gitignore(self, rules):
        self.gitignore.write_text("\n".join(rules) + "\n")

    def write_manifest(self, data, path=None):
        (path or self.manifest).write_text(json.dumps(data))


class CleanTreeTests(GuardRepoFixture):
    def test_clean_tree_passes(self):
        result = run_guards(self.root)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("security_guards: OK", result.stdout)


class PermissionGuardTests(GuardRepoFixture):
    def test_catch_all_allow_fails(self):
        self.write_config(security_guards.ALLOWED_BASH_PERMISSIONS, extra={"*": "allow"})
        result = run_guards(self.root)
        self.assertEqual(result.returncode, 1)
        self.assertIn("must not be", result.stdout)

    def test_unallowlisted_bash_pattern_fails(self):
        self.write_config(security_guards.ALLOWED_BASH_PERMISSIONS, extra={"curl*": "allow"})
        result = run_guards(self.root)
        self.assertEqual(result.returncode, 1)
        self.assertIn("not in the reviewed allowlist", result.stdout)
        self.assertIn("curl*", result.stdout)

    def test_unallowlisted_blanket_bun_run_fails(self):
        self.write_config(security_guards.ALLOWED_BASH_PERMISSIONS, extra={"bun run*": "allow"})
        result = run_guards(self.root)
        self.assertEqual(result.returncode, 1)
        self.assertIn("not in the reviewed allowlist", result.stdout)

    def test_dropped_allowlisted_pattern_still_passes(self):
        # Removing a shipped permission narrows exposure; the guard only
        # rejects additions, it must not force entries to exist.
        allow = sorted(security_guards.ALLOWED_BASH_PERMISSIONS)[:-1]
        self.write_config(allow)
        result = run_guards(self.root)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_invalid_config_json_fails(self):
        self.config.write_text("{not json")
        result = run_guards(self.root)
        self.assertEqual(result.returncode, 1)
        self.assertIn("invalid JSON", result.stdout)

    def test_malformed_config_shape_fails_cleanly(self):
        for data, message in [
            ([], "top-level JSON value must be an object"),
            ({"permission": []}, "permission must be an object"),
            ({"permission": {"bash": []}}, "permission.bash must be an object"),
        ]:
            with self.subTest(data=data):
                self.config.write_text(json.dumps(data))
                result = run_guards(self.root)
                self.assertEqual(result.returncode, 1)
                self.assertIn(message, result.stdout)
                self.assertNotIn("Traceback", result.stderr)


class PluginGuardTests(GuardRepoFixture):
    """A plugin is loaded and executed at opencode startup with no prompt.

    A plugin runs unconditionally when the session starts, so it is strictly
    more dangerous than a pre-approved permission. This is the class of vector
    the Shai-Hulud worm used in its August 2026 wave, planting a startup hook
    that executed on session start, per
    https://research.jfrog.com/post/shai-hulud-is-back-august/
    """

    def test_unallowlisted_plugin_fails(self):
        self.write_config(
            security_guards.ALLOWED_BASH_PERMISSIONS, plugins=["math-init-plugin"]
        )
        result = run_guards(self.root)
        self.assertEqual(result.returncode, 1)
        self.assertIn("plugin not in the reviewed allowlist", result.stdout)
        self.assertIn("math-init-plugin", result.stdout)

    def test_tuple_form_plugin_is_checked(self):
        self.write_config(
            security_guards.ALLOWED_BASH_PERMISSIONS, plugins=[["evil-plugin", {"x": 1}]]
        )
        result = run_guards(self.root)
        self.assertEqual(result.returncode, 1)
        self.assertIn("evil-plugin", result.stdout)

    def test_plugin_is_caught_even_when_permission_block_is_malformed(self):
        # The permission shape guards return early. A file pairing a broken
        # permission block with a live plugin must not slip through that return.
        self.config.write_text(
            json.dumps(
                {
                    "permission": {"bash": "not-an-object"},
                    "plugin": ["curl-evil-plugin"],
                }
            )
        )
        result = run_guards(self.root)
        self.assertEqual(result.returncode, 1)
        self.assertIn("plugin not in the reviewed allowlist", result.stdout)

    def test_non_array_plugin_fails_cleanly(self):
        self.config.write_text(
            json.dumps(
                {
                    "permission": {"bash": {"*": "ask"}},
                    "plugin": "just-a-string",
                }
            )
        )
        result = run_guards(self.root)
        self.assertEqual(result.returncode, 1)
        self.assertIn("plugin must be an array", result.stdout)
        self.assertNotIn("Traceback", result.stderr)

    def test_absent_or_empty_plugins_pass(self):
        for plugins in [None, []]:
            with self.subTest(plugins=plugins):
                self.write_config(security_guards.ALLOWED_BASH_PERMISSIONS, plugins=plugins)
                result = run_guards(self.root)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_allowlisted_plugin_passes(self):
        spec = "opencode-reviewed-plugin"
        guard = self.root / "tools" / "security_guards.py"
        guard.write_text(
            guard.read_text(encoding="utf-8").replace(
                "ALLOWED_PLUGINS: set[str] = set()",
                f"ALLOWED_PLUGINS: set[str] = {{{spec!r}}}",
            ),
            encoding="utf-8",
        )
        self.write_config(security_guards.ALLOWED_BASH_PERMISSIONS, plugins=[spec])
        result = run_guards(self.root)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class GitignoreGuardTests(GuardRepoFixture):
    def test_each_missing_personal_data_rule_fails(self):
        for rule in security_guards.REQUIRED_IGNORE_RULES:
            with self.subTest(rule=rule):
                remaining = [r for r in security_guards.REQUIRED_IGNORE_RULES if r != rule]
                self.write_gitignore(remaining)
                result = run_guards(self.root)
                self.assertEqual(result.returncode, 1)
                self.assertIn("required personal-data rule missing", result.stdout)
                self.assertIn(rule, result.stdout)
        self.write_gitignore(security_guards.REQUIRED_IGNORE_RULES)

    def test_extra_rules_are_allowed(self):
        self.write_gitignore(list(security_guards.REQUIRED_IGNORE_RULES) + ["*.bak", "scratch/"])
        result = run_guards(self.root)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_generated_report_rules_are_required(self):
        # Reports are generated from the user's tracker and application archive,
        # so losing these ignore rules can expose personal job-search history.
        sensitive_outputs = ["reports/", "upskill/*.md", "**/upskill/report-*.md"]
        remaining = [
            rule
            for rule in security_guards.REQUIRED_IGNORE_RULES
            if rule not in sensitive_outputs
        ]
        self.write_gitignore(remaining)

        result = run_guards(self.root)

        self.assertEqual(result.returncode, 1)
        self.assertIn("reports/", result.stdout)
        self.assertIn("upskill/*.md", result.stdout)
        self.assertIn("**/upskill/report-*.md", result.stdout)


class GitignorePatternBehaviorTests(unittest.TestCase):
    """Pin the match semantics of the shipped .gitignore, not just rule presence.

    The guard checks that a rule exists; it never checks what the rule matches.
    These cases run real `git check-ignore` over the shipped file, for paths the
    framework actually writes.
    """

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        subprocess.run(
            ["git", "init", "-q", str(self.root)], check=True, capture_output=True
        )
        shutil.copy(REPO_ROOT / ".gitignore", self.root / ".gitignore")

    def test_upskill_reports_ignored_at_depth_but_skill_md_stays_tracked(self):
        # The upskill skill resolves `upskill/` relative to its own directory
        # (the same observed behavior the **/job_scraper rules exist for), so a
        # report must be ignored at that depth too. The skill's own SKILL.md
        # lives in a directory that shares the `upskill` name, so a broad
        # `**/upskill/*.md` would ignore the template's own skill file - this
        # pins that it stays tracked.
        cases = {
            "upskill/report-2026-08-11.md": True,
            ".opencode/skills/upskill/upskill/report-2026-08-11.md": True,
            ".opencode/skills/upskill/upskill/report-2026-08-11-acme-engineer.md": True,
            ".opencode/skills/upskill/SKILL.md": False,
        }
        for path, expect_ignored in cases.items():
            with self.subTest(path=path):
                result = subprocess.run(
                    ["git", "-C", str(self.root), "check-ignore", "-q", path],
                    capture_output=True,
                )
                self.assertEqual(
                    result.returncode == 0,
                    expect_ignored,
                    f"{path}: expected ignored={expect_ignored}",
                )

    def test_interview_prep_pack_is_ignored_at_the_path_the_command_writes(self):
        # Derived, never copied: a hardcoded prep-pack path pins only that
        # documents/applications/** still matches that shape - which the
        # presence guard already catches - and stays green if /interview moves
        # its output, leaving .gitignore's comment stale exactly the way #336
        # found it. Reading the path back from the command spec is what makes
        # the move fail here instead.
        # Two fragments, not one literal: #329 split the path across Step 1
        # (which derives the archive folder) and Step 3 (which names the file),
        # so either half can move independently and each must be pinned.
        folder = "documents/applications/<company>_<role>/"
        filename = "interview_prep_<stage>.md"
        spec = (REPO_ROOT / ".opencode" / "command" / "interview.md").read_text(encoding="utf-8")
        for fragment in (folder, filename):
            # assertTrue, not assertIn: the haystack is the whole command spec,
            # and dumping it buries the one sentence explaining the failure.
            self.assertTrue(
                fragment in spec,
                f"/interview no longer writes {fragment}; .gitignore's comment is now stale",
            )

        path = folder.replace("<company>_<role>", "acme_data_scientist") + filename.replace(
            "<stage>", "technical"
        )
        result = subprocess.run(
            ["git", "-C", str(self.root), "check-ignore", "-v", path],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, f"{path}: not ignored by the shipped .gitignore")
        self.assertIn("documents/applications/**", result.stdout)


class GitignoreNegationTests(GuardRepoFixture):
    def test_negation_reincluding_personal_data_fails(self):
        # .gitignore is order-sensitive: `!salary_data.json` after the
        # `salary_data.json` rule re-includes the file, so the required rule is
        # still present but no longer takes effect. Set membership on the
        # required rules cannot see this, so the negation must be rejected.
        self.write_gitignore(list(security_guards.REQUIRED_IGNORE_RULES) + ["!salary_data.json"])
        result = run_guards(self.root)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("negation rule not in the reviewed allowlist", result.stdout)
        self.assertIn("!salary_data.json", result.stdout)

    def test_allowlisted_negations_pass(self):
        # The template's own benign negations (example CV/cover letter, fonts,
        # .gitkeep placeholders) must keep passing.
        self.write_gitignore(
            list(security_guards.REQUIRED_IGNORE_RULES)
            + sorted(security_guards.ALLOWED_IGNORE_NEGATIONS)
        )
        result = run_guards(self.root)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class ManifestGuardTests(GuardRepoFixture):
    def test_each_lifecycle_script_fails(self):
        for script in sorted(security_guards.FORBIDDEN_SCRIPTS):
            with self.subTest(script=script):
                # The guard flags the script KEY; the value is never inspected,
                # so it must stay benign: attack-shaped values (curl-pipe-to-sh
                # etc.) written to disk trip AV heuristics - Windows Defender
                # quarantines the fixture mid-test and the suite goes flaky.
                self.write_manifest(
                    {"name": "example-cli", "scripts": {script: "echo test"}}
                )
                result = run_guards(self.root)
                self.assertEqual(result.returncode, 1)
                self.assertIn("lifecycle script", result.stdout)
                self.assertIn(script, result.stdout)
        self.write_manifest({"name": "example-cli", "scripts": {}})

    def test_trusted_dependencies_fails(self):
        self.write_manifest({"name": "example-cli", "trustedDependencies": ["left-pad"]})
        result = run_guards(self.root)
        self.assertEqual(result.returncode, 1)
        self.assertIn("trustedDependencies", result.stdout)

    def test_malformed_manifest_shape_fails_cleanly(self):
        for data, message in [
            ([], "top-level JSON value must be an object"),
            ({"name": "example-cli", "scripts": []}, "scripts must be an object"),
        ]:
            with self.subTest(data=data):
                self.write_manifest(data)
                result = run_guards(self.root)
                self.assertEqual(result.returncode, 1)
                self.assertIn(message, result.stdout)
                self.assertNotIn("Traceback", result.stderr)

    def test_benign_scripts_pass(self):
        self.write_manifest(
            {"name": "example-cli", "scripts": {"start": "bun run src/cli.ts", "test": "bun test", "typecheck": "tsc --noEmit"}}
        )
        result = run_guards(self.root)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_node_modules_manifests_are_ignored(self):
        # Installed dependencies are not repo-tracked code; a hostile manifest
        # inside node_modules must not fail the guard (and bun blocks its
        # lifecycle scripts anyway).
        nm = self.manifest.parent / "node_modules" / "some-dep" / "package.json"
        nm.parent.mkdir(parents=True)
        self.write_manifest({"name": "some-dep", "scripts": {"postinstall": "echo test"}}, path=nm)
        result = run_guards(self.root)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_no_manifests_at_all_fails(self):
        self.manifest.unlink()
        result = run_guards(self.root)
        self.assertEqual(result.returncode, 1)
        self.assertIn("no package.json files found", result.stdout)


class RealRepoTests(unittest.TestCase):
    def test_guards_pass_on_this_repo(self):
        # The live check CI runs: the actual repo tree must satisfy its own guards.
        result = run_guards(REPO_ROOT)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
