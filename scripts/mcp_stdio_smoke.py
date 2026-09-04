#!/usr/bin/env python3
"""Exercise initialize, tools/list, and one denied decision over MCP stdio."""

from __future__ import annotations

import argparse
import json
import subprocess
import threading
from queue import Empty, Queue


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        raise SystemExit("expected command after --")

    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    assert process.stdin is not None and process.stdout is not None
    responses: Queue[dict[str, object]] = Queue()

    def read_stdout() -> None:
        for line in process.stdout:
            try:
                responses.put(json.loads(line))
            except json.JSONDecodeError:
                continue

    threading.Thread(target=read_stdout, daemon=True).start()

    def request(identifier: int, method: str, params: dict[str, object] | None = None) -> dict[str, object]:
        message: dict[str, object] = {"jsonrpc": "2.0", "id": identifier, "method": method}
        if params is not None:
            message["params"] = params
        process.stdin.write(json.dumps(message, separators=(",", ":")) + "\n")
        process.stdin.flush()
        try:
            while True:
                response = responses.get(timeout=10)
                if response.get("id") == identifier:
                    if "error" in response:
                        raise SystemExit(f"MCP error: {response['error']}")
                    return response
        except Empty as error:
            raise SystemExit(f"timed out waiting for MCP response to {method}") from error

    initialized = request(1, "initialize", {
        "protocolVersion": "2025-11-25",
        "capabilities": {},
        "clientInfo": {"name": "gaugemesh-release-smoke", "version": "1"},
    })
    if initialized.get("result", {}).get("serverInfo", {}).get("name") != "gaugemesh":
        raise SystemExit("unexpected server identity")
    process.stdin.write('{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
    process.stdin.flush()
    listed = request(2, "tools/list", {})
    tools = listed.get("result", {}).get("tools", [])
    names = {tool.get("name") for tool in tools}
    if "gaugemesh_lease" not in names:
        raise SystemExit(f"missing lease tool: {sorted(names)}")
    denied = request(3, "tools/call", {"name": "gaugemesh_lease", "arguments": {}})
    if not denied.get("result", {}).get("isError"):
        raise SystemExit("empty selection request did not fail closed")
    process.stdin.close()
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
    print(json.dumps({"status": "PASS", "tools": sorted(names), "denied": True}))


if __name__ == "__main__":
    main()
