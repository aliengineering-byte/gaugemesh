#!/usr/bin/env python3
"""Create a deterministic-layout GaugeMesh release ZIP."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import zipfile


VERSION_RE = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
)
TARGET_RE = re.compile(r"[a-zA-Z0-9_.-]+")
SHA_RE = re.compile(r"[0-9a-f]{40}")
FIXED_TIMESTAMP = (1980, 1, 1, 0, 0, 0)


def add_bytes(
    archive: zipfile.ZipFile, name: str, payload: bytes, *, executable: bool = False
) -> None:
    info = zipfile.ZipInfo(name, FIXED_TIMESTAMP)
    info.create_system = 3
    mode = 0o755 if executable else 0o644
    info.external_attr = (stat.S_IFREG | mode) << 16
    info.compress_type = zipfile.ZIP_DEFLATED
    archive.writestr(info, payload)


def add_file(
    archive: zipfile.ZipFile, source: Path, name: str, *, executable: bool = False
) -> None:
    if not source.is_file():
        raise SystemExit(f"missing package input: {source}")
    add_bytes(archive, name, source.read_bytes(), executable=executable)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--target", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--output", default="dist", type=Path)
    args = parser.parse_args()

    if not args.binary.is_file():
        raise SystemExit(f"missing binary: {args.binary}")
    if VERSION_RE.fullmatch(args.version) is None:
        raise SystemExit("version must be a plain semantic version")
    if TARGET_RE.fullmatch(args.target) is None:
        raise SystemExit("target contains an unsafe character")
    if SHA_RE.fullmatch(args.source_sha) is None:
        raise SystemExit("source SHA must be 40 lowercase hexadecimal characters")

    args.output.mkdir(parents=True, exist_ok=True)
    archive_path = args.output / f"gaugemesh-v{args.version}-{args.target}.zip"
    binary_name = "gaugemesh.exe" if args.binary.suffix.lower() == ".exe" else "gaugemesh"
    binary_bytes = args.binary.read_bytes()
    metadata = {
        "archiveFormat": "zip",
        "binary": binary_name,
        "binarySha256": hashlib.sha256(binary_bytes).hexdigest(),
        "license": "Apache-2.0",
        "minimumRustVersion": "1.88.0",
        "profile": "release",
        "sourceRepository": "https://github.com/aliengineering-byte/gaugemesh",
        "sourceSha": args.source_sha,
        "target": args.target,
        "version": args.version,
    }
    metadata_bytes = (json.dumps(metadata, indent=2, sort_keys=True) + "\n").encode()

    with zipfile.ZipFile(archive_path, "w", strict_timestamps=True) as archive:
        add_bytes(archive, binary_name, binary_bytes, executable=True)
        add_bytes(archive, "BUILD-METADATA.json", metadata_bytes)
        add_file(archive, Path("LICENSE"), "LICENSE")
        add_file(archive, Path("README.md"), "README.md")
        add_file(archive, Path("SECURITY.md"), "SECURITY.md")

    print(archive_path)


if __name__ == "__main__":
    main()
