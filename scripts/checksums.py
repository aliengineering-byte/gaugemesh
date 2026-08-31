#!/usr/bin/env python3
"""Write stable SHA-256 sums for regular release files."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", default="dist", type=Path)
    parser.add_argument("--output", default="SHA256SUMS")
    args = parser.parse_args()

    if not args.directory.is_dir():
        raise SystemExit(f"missing release directory: {args.directory}")
    output = args.directory / args.output
    files = sorted(
        path
        for path in args.directory.iterdir()
        if path.is_file() and not path.is_symlink() and path != output
    )
    if not files:
        raise SystemExit("no release files to checksum")
    lines = [
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
        for path in files
    ]
    output.write_text("".join(lines), encoding="utf-8", newline="\n")
    print(output)


if __name__ == "__main__":
    main()
