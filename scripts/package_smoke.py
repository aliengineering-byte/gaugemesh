#!/usr/bin/env python3
"""Validate a release archive and execute its no-key acceptance paths."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import tempfile
import zipfile


def run(binary: Path, *arguments: str, cwd: Path) -> str:
    completed = subprocess.run(
        [str(binary), *arguments],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if completed.stderr:
        raise SystemExit(f"unexpected stderr from {' '.join(arguments)}: {completed.stderr}")
    return completed.stdout


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--target", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-sha", required=True)
    args = parser.parse_args()

    expected_binary = "gaugemesh.exe" if "windows" in args.target else "gaugemesh"
    expected_members = {
        expected_binary,
        "BUILD-METADATA.json",
        "LICENSE",
        "README.md",
        "SECURITY.md",
    }
    with tempfile.TemporaryDirectory(prefix="gaugemesh-package-") as root_text:
        root = Path(root_text)
        extracted = root / "archive"
        caller = root / "caller"
        extracted.mkdir()
        caller.mkdir()
        with zipfile.ZipFile(args.archive) as archive:
            names = archive.namelist()
            if set(names) != expected_members or len(names) != len(expected_members):
                raise SystemExit(f"unexpected archive members: {names}")
            for name in names:
                path = PurePosixPath(name)
                if path.is_absolute() or ".." in path.parts or len(path.parts) != 1:
                    raise SystemExit(f"unsafe archive member: {name}")
            archive.extractall(extracted)

        metadata = json.loads((extracted / "BUILD-METADATA.json").read_text())
        expected_metadata = {
            "archiveFormat": "zip",
            "binary": expected_binary,
            "license": "Apache-2.0",
            "minimumRustVersion": "1.88.0",
            "profile": "release",
            "sourceRepository": "https://github.com/aliengineering-byte/gaugemesh",
            "sourceSha": args.source_sha,
            "target": args.target,
            "version": args.version,
        }
        for key, expected in expected_metadata.items():
            if metadata.get(key) != expected:
                raise SystemExit(f"metadata mismatch for {key}: {metadata.get(key)!r}")

        binary = extracted / expected_binary
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        if metadata.get("binarySha256") != digest:
            raise SystemExit("binary digest does not match BUILD-METADATA.json")
        if os.name != "nt":
            binary.chmod(binary.stat().st_mode | stat.S_IXUSR)

        before = sorted(caller.iterdir())
        version = run(binary, "--version", cwd=caller).strip()
        if version != f"gaugemesh {args.version}":
            raise SystemExit(f"unexpected version output: {version}")
        demo = json.loads(run(binary, "demo", "--json", cwd=caller))
        required_demo = {
            "status": "PASS",
            "collisionIsolated": True,
            "duplicateEffects": 0,
            "invariantViolations": 0,
            "ownedChildrenRemaining": 0,
            "ownedListenersRemaining": 0,
            "retryBudgetBefore": 1,
            "retryBudgetAfter": 0,
            "semanticLossScore": 0,
        }
        for key, expected in required_demo.items():
            if demo.get(key) != expected:
                raise SystemExit(f"demo mismatch for {key}: {demo.get(key)!r}")

        route_a = run(binary, "route", "explain", cwd=caller)
        route_b = run(binary, "route", "explain", cwd=caller)
        if route_a != route_b:
            raise SystemExit("route explanation changed across identical processes")
        route = json.loads(route_a)
        if route.get("selected") != "local-a":
            raise SystemExit("unexpected deterministic route")
        for client in ("generic-mcp", "openai-compatible"):
            connection = json.loads(run(binary, "connect", client, cwd=caller))
            if connection.get("evidence") != "VERIFIED":
                raise SystemExit(f"connection evidence is not verified for {client}")
        if sorted(caller.iterdir()) != before:
            raise SystemExit("release binary wrote into the caller directory")

    print(f"PASS {args.archive.name} source={args.source_sha} target={args.target}")


if __name__ == "__main__":
    main()
