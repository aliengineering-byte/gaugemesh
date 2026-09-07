"""External live-wire Tasks qualification; accepts an installed public binary.

No internal imports, SQLite access, hidden GaugeMesh worker commands, or self-tests.
All input is original synthetic data. Retains raw JSON-RPC and independent counts.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import threading
import time

REVISION = "2026-07-28"
META = {"io.modelcontextprotocol/protocolVersion": REVISION,
        "io.modelcontextprotocol/clientInfo": {"name": "external-tasks-consumer", "version": "1.0.0"},
        "io.modelcontextprotocol/clientCapabilities": {"extensions": {"io.modelcontextprotocol/tasks": {}}}}


def digest(value):
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return "sha256:" + hashlib.sha256(data).hexdigest()


def read_events(root):
    events = []
    for path in root.glob("events*.jsonl"):
        # A trailing partial write is not an event until its newline is visible.
        text = path.read_text()
        events.extend(json.loads(line) for line in text.split("\n")[:-1] if line)
    return sorted(events, key=lambda event: event.get("timeNs", 0))


def wait_for(predicate, label, timeout=10):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        result = predicate()
        if result:
            return result
        time.sleep(0.01)
    raise AssertionError("Barrier not reached: " + label)


def verify_owned_stopped(root):
    """Inspect only PIDs recorded by this fixture; do not enumerate processes."""
    pids = {event["pid"] for event in read_events(root)}
    if sys.platform != "linux":
        return {"status": "NOT_EXERCISED", "reason": "independent PID liveness observation is Linux-only"}
    def inactive():
        live = []
        for pid in pids:
            try:
                state = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].strip().split()[0]
            except FileNotFoundError:
                continue
            if state != "Z": live.append(pid)
        return not live
    wait_for(inactive, "all fixture providers and workers stopped", timeout=12)
    return {"status": "PASS", "observedPids": len(pids), "liveFixtureProcesses": 0,
        "boundary": "absent or terminated zombie; no claim about unrelated host processes"}


class Client:
    def __init__(self, command, root):
        self.log = (root / "client-wire.jsonl").open("a", encoding="utf-8")
        self.error = (root / "client-stderr.txt").open("a", encoding="utf-8")
        self.proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=self.error, text=True, bufsize=1)
        self.responses = queue.Queue()
        self.sequence = 0
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def _read(self):
        for line in self.proc.stdout:
            self.responses.put(json.loads(line))

    def send(self, method, params=None, request_id=None):
        self.sequence += 1
        request_id = request_id or self.sequence
        request = {"jsonrpc": "2.0", "id": request_id, "method": method,
                   "params": {**(params or {}), "_meta": META}}
        self.log.write(json.dumps({"sent": request}) + "\n")
        self.log.flush()
        self.proc.stdin.write(json.dumps(request) + "\n")
        self.proc.stdin.flush()
        return request_id

    def receive(self, request_id, timeout=10):
        response = self.receive_any(timeout)
        assert response.get("id") == request_id, response
        return response

    def receive_any(self, timeout=10):
        response = self.responses.get(timeout=timeout)
        self.log.write(json.dumps({"received": response}) + "\n")
        self.log.flush()
        return response

    def rpc(self, method, params=None):
        response = self.receive(self.send(method, params))
        assert "error" not in response, response
        return response["result"]

    def tool(self, name, arguments):
        return self.rpc("tools/call", {"name": name, "arguments": arguments})

    def close(self):
        try:
            self.proc.stdin.close()
        except BrokenPipeError:
            pass
        try:
            self.proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            self.proc.terminate()
            self.proc.wait(timeout=5)
        self.reader.join(timeout=2)
        self.log.close()
        self.error.close()


def submission(client, key, arguments):
    alias = "neutral__normalize"
    description = client.tool("gaugemesh_describe", {"alias": alias})["structuredContent"]
    lease = client.tool("gaugemesh_lease", {"aliases": [alias], "ttlMs": 600000,
        "sideEffects": ["read_only", "idempotent_write", "non_idempotent_write"]})["structuredContent"]
    task = {"schemaVersion": "gaugemesh.task-submission/1", "logicalTaskId": key,
        "attemptId": key + "-attempt", "correlationId": key + "-correlation", "idempotencyKey": key,
        "inputSha256": digest(arguments), "acceptancePolicySha256": digest({"expected": arguments["value"]}),
        "artifactScopeSha256": digest({"scope": "owned-fixture"}),
        "providerInterfaceVersion": description["schemaDigest"], "deadlineUnixMs": int(time.time() * 1000) + 30000,
        "retentionMs": 60000, "limits": {"maxRuntimeMs": 30000, "maxOutputBytes": 65536,
        "maxArtifactBytes": 1048576, "maxAttempts": 1}, "permittedEffect": "non_idempotent_write", "cleanupRequired": True}
    return {"leaseId": lease["leaseId"], "alias": alias, "arguments": arguments, "task": task}


def finish(client, handle):
    def poll():
        result = client.rpc("tasks/get", {"taskId": handle["taskId"]})
        return result if result["status"] in ("completed", "failed", "cancelled") else None
    return wait_for(poll, "terminal task")


def setup(binary, root):
    root.mkdir(parents=True, exist_ok=False)
    worker_root = root / "worker"
    worker_root.mkdir()
    config = root / "gateway.yaml"
    subprocess.run([binary, "init", str(config)], check=True, capture_output=True, text=True)
    original = config.read_text()
    config.write_text(original.replace("mode: memory", "mode: sqlite\n  database: " + json.dumps(str(root / "tasks.sqlite3"))))
    subprocess.run([binary, "add", "mcp", "neutral", "--config", str(config), "--command", sys.executable,
        "--arg", str(Path(__file__).with_name("worker.py")), "--arg=--root", "--arg", str(worker_root)],
        check=True, capture_output=True, text=True)
    return config, worker_root


def qualify(binary, root, require_late_recovery=False):
    config, worker_root = setup(binary, root)
    client = Client([sys.executable, str(Path(__file__).with_name("proxy.py")), "--binary", binary,
        "--config", str(config), "--evidence", str(root)], root)
    results = {}
    try:
        discovery = client.rpc("server/discover")
        assert "io.modelcontextprotocol/tasks" in discovery["capabilities"]["extensions"]
        request = submission(client, "ordinary", {"value": 7})
        if require_late_recovery:
            request["task"]["deadlineUnixMs"] = int(time.time() * 1000) + 1500
        handle = client.tool("gaugemesh_submit", request)
        terminal = finish(client, handle)
        assert terminal["status"] == "completed", terminal
        assert terminal["result"]["structuredContent"]["normalized"] == 7
        assert client.tool("gaugemesh_submit", request)["taskId"] == handle["taskId"]
        if require_late_recovery:
            wait_for(lambda: int(time.time() * 1000) > request["task"]["deadlineUnixMs"], "execution deadline elapsed")
            assert client.tool("gaugemesh_submit", request)["taskId"] == handle["taskId"]
            expired_new = json.loads(json.dumps(request))
            expired_new["task"]["idempotencyKey"] = "expired-never-accepted"
            refused = client.receive(client.send("tools/call", {"name": "gaugemesh_submit", "arguments": expired_new}))
            assert "GM_TASK_DEADLINE_INVALID" in json.dumps(refused), refused
            results["lateRecovery"] = "PASS: retained identity recovered after execution deadline; expired new identity rejected"
        changed = json.loads(json.dumps(request))
        changed["arguments"]["value"] = 8
        changed["task"]["inputSha256"] = digest(changed["arguments"])
        conflict = client.receive(client.send("tools/call", {"name": "gaugemesh_submit", "arguments": changed}))
        assert "GM_TASK_IDEMPOTENCY_CONFLICT" in json.dumps(conflict), conflict
        results["A1"] = {"status": "PASS_WITH_SURFACE_LIMITATION", "publicTaskId": handle["taskId"],
            "otherCaller": "NOT_EXERCISED: local stdio and loopback use one local principal; distinct authenticated callers require an approved remote TLS/OIDC setup"}

        lost = submission(client, "lost", {"value": 11})
        client.send("tools/call", {"name": "gaugemesh_submit", "arguments": lost}, "lost-ack")
        wait_for(lambda: (root / "withheld-response.json").exists(), "actual response withheld")
        try:
            unexpected = client.responses.get(timeout=0.1)
        except queue.Empty:
            client.log.write(json.dumps({"requestId": "lost-ack", "observation": "response-timeout", "timeoutMs": 100}) + "\n")
            client.log.flush()
        else:
            raise AssertionError(f"Lost response reached external caller: {unexpected}")
        accepted = [event for event in read_events(worker_root) if event["kind"] == "provider-accepted" and event["binding"]["submission"]["task"]["idempotencyKey"] == "lost"]
        assert len(accepted) == 1
        retried = client.tool("gaugemesh_submit", lost)
        withheld = json.loads((root / "withheld-response.json").read_text())
        assert retried["taskId"] == withheld["result"]["taskId"]
        assert finish(client, retried)["result"]["structuredContent"]["normalized"] == 11
        observed = read_events(worker_root)
        counts = {kind: sum(e["kind"] == kind and e.get("task") == accepted[0]["task"] for e in observed)
                  for kind in ("provider-accepted", "worker-start", "worker-effect")}
        assert list(counts.values()) == [1, 1, 1], counts
        results["A2"] = {"status": "PASS", "fault": "separate stdio relay withheld the actual gateway acknowledgement from external caller", "counts": counts}

        held = submission(client, "session", {"value": 13, "hold": True})
        old = client.tool("gaugemesh_submit", held)
        accepted = [event for event in read_events(worker_root) if event["kind"] == "provider-accepted" and event["binding"]["submission"]["task"]["idempotencyKey"] == "session"][0]
        wait_for(lambda: any(e["kind"] == "worker-start" and e["task"] == accepted["task"] for e in read_events(worker_root)), "worker accepted and running")
        old_session = accepted["session"]
        client.close()
        client = Client([binary, "mcp-stdio", "--config", str(config)], root)
        client.rpc("server/discover")
        sessions = [e["session"] for e in read_events(worker_root) if e["kind"] == "provider-start"]
        assert sessions[-1] != old_session
        status = client.rpc("tasks/get", {"taskId": old["taskId"]})
        cancellation = client.receive(client.send("tasks/cancel", {"taskId": old["taskId"]}))
        assert status["_meta"]["dev.gaugemesh/taskRoute"]["reconciliationRequired"]
        incoming = [e for e in read_events(worker_root) if e["kind"] == "provider-received" and e["session"] == sessions[-1]]
        stale = [e for e in incoming if e["request"]["method"] in ("tasks/get", "tasks/cancel")]
        assert not stale, stale
        results["A3"] = {"status": "PASS", "sessionChanged": True, "staleLifecycleRequestsForwarded": 0,
            "publicOutcome": "RECONCILIATION_REQUIRED", "cancelResponse": cancellation}
    finally:
        client.close()
    results["cleanup"] = verify_owned_stopped(worker_root)
    results["binaryVersion"] = subprocess.check_output([binary, "--version"], text=True).strip()
    results["binarySha256"] = hashlib.sha256(Path(binary).read_bytes()).hexdigest()
    results["suite"] = "external-live-wire-tasks/1"
    results["historicalRecoveryMatrix"] = "UNCHANGED: separate 3 PASS / 10 FAIL / 13 PARTIAL suite"
    (root / "result.json").write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--require-late-recovery", action="store_true")
    options = parser.parse_args()
    qualify(str(options.binary.resolve(strict=True)), options.output.resolve(), options.require_late_recovery)
