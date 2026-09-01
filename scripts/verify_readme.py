#!/usr/bin/env python3
"""Verify that the README demo transcript is byte-for-text from the binary."""

from __future__ import annotations

import argparse
from pathlib import Path
import subprocess


MARKER = "Actual output from the `0.1.0` release binary:\n\n```text\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--readme", default="README.md", type=Path)
    args = parser.parse_args()

    readme = args.readme.read_text(encoding="utf-8").replace("\r\n", "\n")
    if readme.count(MARKER) != 1:
        raise SystemExit("README must contain exactly one marked release transcript")
    transcript = readme.split(MARKER, 1)[1].split("\n```", 1)[0] + "\n"
    completed = subprocess.run(
        [str(args.binary), "demo"],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    actual = completed.stdout.replace("\r\n", "\n")
    if completed.stderr:
        raise SystemExit(f"demo wrote unexpected stderr: {completed.stderr}")
    if actual != transcript:
        raise SystemExit("README demo transcript differs from the release binary")
    print("PASS README demo transcript")


if __name__ == "__main__":
    main()
