import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
LINTER_SCRIPT = REPO_ROOT / "tools" / "lint_skills.py"


def run_linter(root: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(root / "tools" / "lint_skills.py")],
        capture_output=True,
        text=True,
    )


class LinterRepoFixture(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)

        tools = self.root / "tools"
        tools.mkdir()
        shutil.copy(LINTER_SCRIPT, tools / "lint_skills.py")
        # The Python-test CI job does not install PyYAML; the separate lint job
        # does. These config-focused tests only need a valid frontmatter map.
        # The stub parses simple "key: value" lines, enough for the flat
        # frontmatter these fixtures write, so the checks under test see the
        # actual file content instead of a canned mapping.
        (tools / "yaml.py").write_text(
            "class YAMLError(Exception):\n"
            "    pass\n\n"
            "def safe_load(text):\n"
            "    result = {}\n"
            "    for line in (text or '').splitlines():\n"
            "        if ':' in line:\n"
            "            key, _, value = line.partition(':')\n"
            "            result[key.strip()] = value.strip()\n"
            "    return result\n",
            encoding="utf-8",
        )

        command = self.root / ".opencode" / "command" / "setup.md"
        command.parent.mkdir(parents=True)
        command.write_text("# /setup - Test setup command\n", encoding="utf-8")

        skill = self.root / ".opencode" / "skills" / "example" / "SKILL.md"
        skill.parent.mkdir(parents=True)
        skill.write_text(
            "---\nname: example\ndescription: Example skill\n---\n",
            encoding="utf-8",
        )

        self.config = self.root / "opencode.json"
        self.write_config({"permission": {"bash": {"*": "ask"}}})

    def write_config(self, data):
        self.config.write_text(json.dumps(data), encoding="utf-8")


class ConfigShapeTests(LinterRepoFixture):
    def test_valid_config_passes(self):
        result = run_linter(self.root)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("lint_skills: OK", result.stdout)

    def test_invalid_json_fails_cleanly(self):
        self.config.write_text("{not json", encoding="utf-8")

        result = run_linter(self.root)

        self.assertEqual(result.returncode, 1)
        self.assertIn("opencode.json", result.stdout)
        self.assertNotIn("Traceback", result.stderr)

    def test_non_object_root_fails_cleanly(self):
        for data in ([], "config", 1, None):
            with self.subTest(data=data):
                self.write_config(data)

                result = run_linter(self.root)

                self.assertEqual(result.returncode, 1)
                self.assertIn("top-level JSON value to be an object", result.stdout)
                self.assertNotIn("Traceback", result.stderr)

    def test_non_object_permission_fails_cleanly(self):
        for permission in ([], "permission", 1, None):
            with self.subTest(permission=permission):
                self.write_config({"permission": permission})

                result = run_linter(self.root)

                self.assertEqual(result.returncode, 1)
                self.assertIn("expected permission to be an object", result.stdout)
                self.assertNotIn("Traceback", result.stderr)

    def test_non_object_bash_permission_fails_cleanly(self):
        for bash in ([], "bash", 1, None):
            with self.subTest(bash=bash):
                self.write_config({"permission": {"bash": bash}})

                result = run_linter(self.root)

                self.assertEqual(result.returncode, 1)
                self.assertIn("expected permission.bash to be an object", result.stdout)
                self.assertNotIn("Traceback", result.stderr)


class SkillAndCommandCheckTests(LinterRepoFixture):
    """check_skill()/check_command() are the linter's main job and were
    previously untested - only the config check had coverage, so deleting
    e.g. the missing-allowed-tools error survived the whole suite (review
    finding F23, 2026-08-19)."""

    def write_skill(self, frontmatter: str):
        skill = self.root / ".opencode" / "skills" / "example" / "SKILL.md"
        skill.write_text(frontmatter, encoding="utf-8")

    def test_allowed_tools_referencing_a_missing_file_fails(self):
        self.write_skill(
            "---\n"
            "name: example\n"
            "description: Example skill\n"
            "allowed-tools: Bash(bun run .opencode/skills/example/DOES_NOT_EXIST.ts *)\n"
            "---\n"
        )

        result = run_linter(self.root)

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("allowed-tools references a missing file", result.stdout)
        self.assertIn("DOES_NOT_EXIST.ts", result.stdout)

    def test_allowed_tools_referencing_an_existing_file_passes(self):
        target = self.root / ".opencode" / "skills" / "example" / "cli.ts"
        target.write_text("// present\n", encoding="utf-8")
        self.write_skill(
            "---\n"
            "name: example\n"
            "description: Example skill\n"
            "allowed-tools: Bash(bun run .opencode/skills/example/cli.ts *)\n"
            "---\n"
        )

        result = run_linter(self.root)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_frontmatter_missing_description_fails(self):
        self.write_skill("---\nname: example\ndescription:\n---\n")

        result = run_linter(self.root)

        self.assertEqual(result.returncode, 1)
        self.assertIn("missing required key 'description'", result.stdout)

    def test_command_without_slash_title_fails(self):
        command = self.root / ".opencode" / "command" / "setup.md"
        command.write_text("# setup - missing the slash\n", encoding="utf-8")

        result = run_linter(self.root)

        self.assertEqual(result.returncode, 1)
        self.assertIn("must carry a '# /<name>' title", result.stdout)

    def test_command_with_frontmatter_then_slash_title_passes(self):
        command = self.root / ".opencode" / "command" / "setup.md"
        command.write_text(
            "---\ndescription: Setup command\n---\n\n# /setup - Onboarding\n\nBody.\n",
            encoding="utf-8",
        )

        result = run_linter(self.root)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
