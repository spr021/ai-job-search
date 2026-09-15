#!/usr/bin/env python3
"""Supply-chain guards for the template's riskiest surfaces.

Run from anywhere: python tools/security_guards.py

This repo ships pre-approved opencode bash permissions and CLI code that every
fork user executes. These guards make the dangerous changes LOUD, not
impossible: a PR that intentionally needs one of them must update the
allowlists in this file in the same diff, so the change is explicit and
reviewable rather than buried.

Checks:
1. opencode.json - every permission.bash entry set to "allow" must be in the
   exact allowlist below, and the catch-all "*" must never be set to "allow".
   Catches permission widening (e.g. "*": "allow", "curl*": "allow"), which
   would auto-approve commands on every fork. The same file's `plugin` key is
   held to an allowlist too: a plugin is code loaded automatically at startup
   with no prompt, so it is strictly more dangerous than a pre-approved
   permission.
2. .gitignore - the personal-data ignore rules must all still be present,
   and no un-allowlisted negation (!pattern) may re-include them. Catches
   weakening that would make future users silently commit their tracker,
   profile exports, or application archives.
3. .agents/**/package.json - no npm/bun lifecycle scripts (preinstall,
   install, postinstall, prepare, prepack) and no trustedDependencies.
   Catches code execution smuggled into `bun install`.

Stdlib only. Exit 0 on success, 1 with a failure list otherwise.
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
errors: list[str] = []

# The exact bash permission patterns the template ships, each mapped to "allow"
# in opencode.json. A PR that adds or changes an entry must add it here too -
# that is the point: the diff shows both.
ALLOWED_BASH_PERMISSIONS = {
    # Narrowed from a blanket "bun run*", which would pre-approve
    # `bun run <any file>`. One entry per shipped portal CLI, matching what
    # each portal SKILL.md already declares. A portal added by /add-portal
    # needs its own entry here and in opencode.json - that review step is the
    # point.
    "bun --version",
    "bun run .agents/skills/*/cli/src/cli.ts*",
    "bun install*",
    "bun test*",
    "bun run typecheck*",
    "python salary_lookup.py*",
    "python3 salary_lookup.py*",
    "python tools/rank_state.py*",
    "python3 tools/rank_state.py*",
    "python tools/job_key.py*",
    "python3 tools/job_key.py*",
    "python tools/verify_pdf.py*",
    "python3 tools/verify_pdf.py*",
    "python tools/verify_layout.py*",
    "python3 tools/verify_layout.py*",
    "python tools/lint_skills.py*",
    "python3 tools/lint_skills.py*",
    "python tools/robots_check.py*",
    "python3 tools/robots_check.py*",
    "pdftotext*",
    "lualatex*",
    "xelatex*",
    "latexmk*",
}

# Plugins the template legitimately ships, as npm specs / paths. Empty by
# design - the template ships no plugins at all.
#
# A plugin is strictly more dangerous than a permission.bash entry. A permission
# pre-approves something the agent may choose to run; a plugin is loaded and
# executed automatically at opencode startup, with no prompt and no model
# decision in between. Cloning a repo and opening it is enough. This is the
# class of vector the Shai-Hulud worm used in its August 2026 wave, planting a
# startup hook in a config file that executed on session start:
# https://research.jfrog.com/post/shai-hulud-is-back-august/
ALLOWED_PLUGINS: set[str] = set()

# Personal-data ignore rules that must never disappear from .gitignore.
REQUIRED_IGNORE_RULES = [
    "salary_data.json",
    # Depth-independent: the job-scraper skill resolves `job_scraper/` relative
    # to its own directory, so the state file lands under .opencode/skills/... and
    # a repo-rooted rule silently fails to match it.
    "**/job_scraper/seen_jobs.json",
    "**/job_scraper/notion_sync.json",
    "**/job_scraper/*.md",
    "*_BehavioralReport.pdf",
    "linkedin_Profile.pdf",
    "cv/main_*.*",
    "!cv/main_example.tex",
    # ATS text extractions (/apply step 5d) carry the CV's full text.
    "cv/*.txt",
    "cover_letters/cover_*.*",
    # /apply also recognizes the uppercase Cover_* naming variant.
    "cover_letters/Cover_*.*",
    "documents/cv/**",
    "documents/linkedin/**",
    "documents/diplomas/**",
    "documents/references/**",
    "documents/applications/**",
    "documents/postings/**",
    # Belt-and-braces, not the primary guard: nothing writes here.
    # /interview's prep packs land under documents/applications/**, above.
    "documents/interview/**",
    "job_search_tracker.csv",
    "gmail_sync/",
    "reports/",
    "upskill/*.md",
    # Depth-independent twin of the rule above. The upskill *skill* resolves
    # `upskill/` relative to its own directory - the same observed behavior
    # the **/job_scraper rules exist for - so reports can land at
    # .opencode/skills/upskill/upskill/*.md where the rooted rule cannot see
    # them. `**/upskill/*.md` would also ignore the skill's own SKILL.md
    # (the directory shares the name), so the report-file prefix is pinned.
    "**/upskill/report-*.md",
    # Not personal data but the same failure mode: /add-portal can generate a
    # skill for a portal that only returns usable content through a paid
    # fetching service, and that skill reads an API token from the environment.
    ".env",
    ".env.*",
    # Company research cache (/apply Step 3, /interview Step 2). Referenced
    # from commands, not a skill, so a plain rooted rule is correct here -
    # unlike the **/-prefixed job_scraper/upskill rules above.
    "company_research/*.json",
]

# Negation (re-include) rules the template legitimately ships. .gitignore is
# order-sensitive: a later `!pattern` re-includes a path an earlier rule
# excluded, so a rule can be physically present in REQUIRED_IGNORE_RULES yet
# no longer ignored (e.g. adding `!salary_data.json`). Set membership on the
# required rules cannot see that. Any negation outside this allowlist is a
# failure - add an intentional one here in the same PR, exactly as with
# ALLOWED_PERMISSIONS, so the widening is explicit and reviewable.
ALLOWED_IGNORE_NEGATIONS = {
    "!cover_letters/OpenFonts/fonts/**",
    "!cv/main_example.tex",
    "!cover_letters/cover_example.tex",
    "!documents/**/.gitkeep",
}

FORBIDDEN_SCRIPTS = {"preinstall", "install", "postinstall", "prepare", "prepack"}


def check_config() -> None:
    path = ROOT / "opencode.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"opencode.json: unreadable or invalid JSON: {exc}")
        return
    if not isinstance(data, dict):
        errors.append("opencode.json: top-level JSON value must be an object")
        return

    # Checked before the permission shape guards below, so a file that pairs a
    # malformed permission block with a plugin cannot return early and skip this.
    plugins = data.get("plugin", [])
    if plugins:
        if not isinstance(plugins, list):
            errors.append("opencode.json: plugin must be an array")
        else:
            for entry in plugins:
                spec = entry[0] if isinstance(entry, list) and entry else entry
                if not isinstance(spec, str) or spec not in ALLOWED_PLUGINS:
                    errors.append(
                        f"opencode.json: plugin not in the reviewed allowlist: {entry!r}. A plugin "
                        "is loaded and executed automatically at opencode startup - it is never "
                        "gated by the permission prompt, so it runs on every fork without the user "
                        "agreeing to anything. If this plugin is intentional, add it to "
                        "ALLOWED_PLUGINS in tools/security_guards.py in the same PR so the "
                        "addition is explicit and reviewable."
                    )

    permission = data.get("permission", {})
    if not isinstance(permission, dict):
        errors.append("opencode.json: permission must be an object")
        return
    bash = permission.get("bash", {})
    if not isinstance(bash, dict):
        errors.append("opencode.json: permission.bash must be an object")
        return
    if bash.get("*") == "allow":
        errors.append(
            'opencode.json: permission.bash["*"] must not be "allow". A catch-all allow '
            "pre-approves every shell command on every fork. Keep it as \"ask\" and add the "
            "specific patterns the workflow needs."
        )
    for pattern, action in bash.items():
        if action != "allow":
            continue
        if pattern not in ALLOWED_BASH_PERMISSIONS:
            errors.append(
                f"opencode.json: permission.bash[{pattern!r}] = 'allow' is not in the reviewed "
                "allowlist. Pre-approved commands run without prompting on every fork. If this "
                "entry is intentional, add it to ALLOWED_BASH_PERMISSIONS in "
                "tools/security_guards.py in the same PR so the widening is explicit and "
                "reviewable."
            )
    for pattern in ALLOWED_BASH_PERMISSIONS - set(bash):
        # Not an error: the config may legitimately drop an entry. But an
        # allowlist entry that no longer exists should be pruned.
        print(f"note: allowlisted bash pattern not present in opencode.json: {pattern!r}")


def check_gitignore() -> None:
    path = ROOT / ".gitignore"
    try:
        lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines()]
    except OSError as exc:
        errors.append(f".gitignore: unreadable: {exc}")
        return
    rules = set(lines)
    for rule in REQUIRED_IGNORE_RULES:
        if rule not in rules:
            errors.append(
                f".gitignore: required personal-data rule missing: {rule!r}. "
                "These rules keep fork users from committing personal data. If the rule moved "
                "or was renamed intentionally, update REQUIRED_IGNORE_RULES in "
                "tools/security_guards.py in the same PR."
            )
    for line in lines:
        if line.startswith("!") and line not in ALLOWED_IGNORE_NEGATIONS:
            errors.append(
                f".gitignore: negation rule not in the reviewed allowlist: {line!r}. "
                "A negation re-includes a path an earlier rule excluded and can silently "
                "re-expose personal data (a required ignore rule stays present but stops "
                "taking effect). If this negation is intentional, add it to "
                "ALLOWED_IGNORE_NEGATIONS in tools/security_guards.py in the same PR."
            )


def check_package_manifests() -> None:
    manifests = [
        p for p in ROOT.glob(".agents/**/package.json") if "node_modules" not in p.parts
    ]
    if not manifests:
        errors.append(".agents: no package.json files found - glob roots are wrong or the tree moved")
    for manifest in manifests:
        relpath = manifest.relative_to(ROOT)
        try:
            data = json.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"{relpath}: unreadable or invalid JSON: {exc}")
            continue
        if not isinstance(data, dict):
            errors.append(f"{relpath}: top-level JSON value must be an object")
            continue
        scripts = data.get("scripts", {})
        if not isinstance(scripts, dict):
            errors.append(f"{relpath}: scripts must be an object")
            continue
        bad = FORBIDDEN_SCRIPTS & set(scripts)
        if bad:
            errors.append(
                f"{relpath}: lifecycle script(s) {sorted(bad)} are forbidden - they execute "
                "arbitrary code during `bun install` on every fork user's machine."
            )
        if "trustedDependencies" in data:
            errors.append(
                f"{relpath}: trustedDependencies is forbidden - it re-enables dependency "
                "lifecycle scripts that bun blocks by default."
            )


def main() -> int:
    check_config()
    check_gitignore()
    check_package_manifests()
    if errors:
        print(f"security_guards: {len(errors)} failure(s)")
        for err in errors:
            print(f"  - {err}")
        return 1
    print(
        "security_guards: OK (bash permission allowlist, plugin allowlist, gitignore rules, "
        "package manifests)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
