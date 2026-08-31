#!/usr/bin/env python3
"""Execute the README's clean local configuration journey."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import urllib.request


def invoke(binary: Path, *arguments: str, cwd: Path, timeout: int = 30) -> str:
    completed = subprocess.run(
        [str(binary), *arguments],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if completed.stderr:
        raise SystemExit(f"unexpected stderr from {' '.join(arguments)}: {completed.stderr}")
    return completed.stdout


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve()

    with tempfile.TemporaryDirectory(prefix="gaugemesh-readme-") as root_text:
        root = Path(root_text)
        config = root / "gaugemesh.yaml"
        invoke(binary, "init", str(config), cwd=root)
        for source, revision in (
            ("source-a", "2025-11-25"),
            ("source-b", "2026-07-28"),
        ):
            invoke(
                binary,
                "add",
                "mcp",
                source,
                "--config",
                str(config),
                "--command",
                str(binary),
                "--arg",
                "mcp-stdio",
                "--protocol-revision",
                revision,
                cwd=root,
            )
        invoke(binary, "doctor", "--config", str(config), cwd=root)
        listed = invoke(binary, "list", "--config", str(config), cwd=root)
        if "source-a" not in listed or "source-b" not in listed:
            raise SystemExit("reviewed MCP sources missing from list")

        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
        server = subprocess.Popen(
            [
                str(binary),
                "serve",
                "--config",
                str(config),
            ],
            cwd=root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            creationflags=creationflags,
        )
        try:
            for _ in range(100):
                try:
                    with urllib.request.urlopen(
                        "http://127.0.0.1:8092/healthz", timeout=0.2
                    ) as response:
                        if response.status == 200:
                            break
                except OSError:
                    time.sleep(0.05)
            else:
                raise SystemExit("README server did not become ready")

            invoke(
                binary,
                "add",
                "model",
                "local-provider",
                "--config",
                str(config),
                "--base-url",
                "http://127.0.0.1:8090/v1/",
                "--provider-model-id",
                "local",
                "--context-limit",
                "8192",
                "--max-output-tokens",
                "1024",
                "--cost-table-version",
                "local-2026-08-30",
                cwd=root,
            )
        finally:
            if server.poll() is None:
                if os.name == "nt":
                    server.send_signal(signal.CTRL_BREAK_EVENT)
                else:
                    server.send_signal(signal.SIGINT)
            try:
                stdout, stderr = server.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                server.kill()
                stdout, stderr = server.communicate(timeout=5)
                raise SystemExit("README server did not stop within its bound")
            if server.returncode != 0:
                raise SystemExit(
                    f"README server failed with {server.returncode}: {stdout}\n{stderr}"
                )

        listed = invoke(binary, "list", "--config", str(config), cwd=root)
        if "local-provider" not in listed:
            raise SystemExit("reviewed model route missing from list")

    print("PASS README local configuration journey")


if __name__ == "__main__":
    main()
