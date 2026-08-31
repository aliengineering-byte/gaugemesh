#!/usr/bin/env python3
"""Fail unless active main-branch and v* tag rules match the release contract."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import urllib.request


REQUIRED_CHECKS = {
    "address-sanitizer",
    "archive (macos-15, aarch64-apple-darwin)",
    "archive (macos-15-intel, x86_64-apple-darwin)",
    "archive (ubuntu-24.04, x86_64-unknown-linux-gnu)",
    "archive (ubuntu-24.04-arm, aarch64-unknown-linux-gnu)",
    "archive (windows-2025, x86_64-pc-windows-msvc)",
    "container-smoke",
    "fuzz-smoke",
    "hygiene",
    "linux-measurements",
    "macos-15 / stable",
    "miri",
    "mutation-critical",
    "openai-sdk",
    "pages-build",
    "resilireplay",
    "server (2025-11-25)",
    "server (2026-07-28)",
    "source-sbom",
    "supply-chain",
    "ubuntu-latest / stable",
    "ubuntu-latest / 1.88.0",
    "windows-latest / stable",
    "windows-latest / 1.88.0",
}


def github_json(url: str, token: str) -> object:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        return json.load(response)


def load_rulesets(repository: str, fixture: Path | None) -> list[dict[str, object]]:
    if fixture is not None:
        value = json.loads(fixture.read_text(encoding="utf-8"))
        if not isinstance(value, list):
            raise SystemExit("rules fixture must contain a JSON array")
        return value
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise SystemExit("GITHUB_TOKEN is required without --fixture")
    base = f"https://api.github.com/repos/{repository}/rulesets"
    summaries = github_json(f"{base}?per_page=100", token)
    if not isinstance(summaries, list):
        raise SystemExit("unexpected rulesets response")
    return [github_json(f"{base}/{item['id']}", token) for item in summaries]


def includes(ruleset: dict[str, object], ref: str) -> bool:
    conditions = ruleset.get("conditions", {})
    if not isinstance(conditions, dict):
        return False
    names = conditions.get("ref_name", {})
    if not isinstance(names, dict):
        return False
    values = names.get("include", [])
    return isinstance(values, list) and ref in values


def rule_map(ruleset: dict[str, object]) -> dict[str, dict[str, object]]:
    rules = ruleset.get("rules", [])
    if not isinstance(rules, list):
        return {}
    return {
        rule["type"]: rule
        for rule in rules
        if isinstance(rule, dict) and isinstance(rule.get("type"), str)
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", ""))
    parser.add_argument("--fixture", type=Path)
    args = parser.parse_args()
    if "/" not in args.repository:
        raise SystemExit("repository must be OWNER/NAME")

    rulesets = [
        ruleset
        for ruleset in load_rulesets(args.repository, args.fixture)
        if ruleset.get("enforcement") == "active"
        and ruleset.get("bypass_actors", []) == []
    ]
    branch = next(
        (
            ruleset
            for ruleset in rulesets
            if ruleset.get("target") == "branch"
            and (includes(ruleset, "refs/heads/main") or includes(ruleset, "~DEFAULT_BRANCH"))
        ),
        None,
    )
    if branch is None:
        raise SystemExit("no active, bypass-free main ruleset")
    branch_rules = rule_map(branch)
    required_branch_rules = {"deletion", "non_fast_forward", "pull_request", "required_status_checks"}
    missing = required_branch_rules - branch_rules.keys()
    if missing:
        raise SystemExit(f"main ruleset is missing: {sorted(missing)}")

    pull_request = branch_rules["pull_request"].get("parameters", {})
    if not isinstance(pull_request, dict):
        raise SystemExit("main pull-request rule has no parameters")
    if pull_request.get("dismiss_stale_reviews_on_push") is not True:
        raise SystemExit("main must dismiss stale reviews")
    if pull_request.get("required_review_thread_resolution") is not True:
        raise SystemExit("main must require review-thread resolution")

    status = branch_rules["required_status_checks"].get("parameters", {})
    contexts = status.get("required_status_checks", []) if isinstance(status, dict) else []
    actual_checks = {
        item.get("context")
        for item in contexts
        if isinstance(item, dict) and isinstance(item.get("context"), str)
    }
    missing_checks = REQUIRED_CHECKS - actual_checks
    if missing_checks:
        raise SystemExit(f"main required checks are missing: {sorted(missing_checks)}")

    tags = next(
        (
            ruleset
            for ruleset in rulesets
            if ruleset.get("target") == "tag" and includes(ruleset, "refs/tags/v*")
        ),
        None,
    )
    if tags is None:
        raise SystemExit("no active, bypass-free v* tag ruleset")
    missing_tag_rules = {"deletion", "non_fast_forward"} - rule_map(tags).keys()
    if missing_tag_rules:
        raise SystemExit(f"v* ruleset is missing: {sorted(missing_tag_rules)}")

    print(f"PASS repository-rules repository={args.repository}")


if __name__ == "__main__":
    main()
