"""Original neutral MCP provider and bounded child worker for public qualification.

Python standard library only. It serves synthetic inputs, never arbitrary commands.
The event log is independent of GaugeMesh's task records and responses.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import signal
import sys
import time
import uuid

REVISION = "2026-07-28"
EXECUTION = "dev.gaugemesh/taskExecution"
SCHEMA = {"type": "object", "properties": {
    "value": {"type": "integer"}, "hold": {"type": "boolean"},
    "invalid": {"type": "boolean"}, "fail": {"type": "boolean"},
    "withholdAcceptance": {"type": "boolean"}, "asyncCancel": {"type": "boolean"},
    "paddingBytes": {"type": "integer", "minimum": 0, "maximum": 24576}}, "required": ["value"],
    "additionalProperties": False}
TOOL = {"name": "normalize", "description": "Normalize one synthetic integer to JSON",
        "inputSchema": SCHEMA, "annotations": {"readOnlyHint": False,
        "destructiveHint": False, "idempotentHint": False, "openWorldHint": False}}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(value):
    return "sha256:" + hashlib.sha256(canonical(value).encode()).hexdigest()


def event(root, kind, **data):
    # One writer per file: shared append is not atomic on every mounted filesystem.
    with (root / f"events-{os.getpid()}.jsonl").open("a", encoding="utf-8") as stream:
        stream.write(canonical({"kind": kind, "pid": os.getpid(), "timeNs": time.time_ns(), **data}) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def child(root, task_id):
    def terminate(_signal, _frame):
        event(root, "worker-signal-terminated", task=task_id)
        raise SystemExit(4)
    signal.signal(signal.SIGTERM, terminate)
    job = json.loads(sys.stdin.readline())
    event(root, "worker-start", task=task_id)
    end = time.monotonic() + 30
    while job["arguments"].get("hold", False) and not (root / (task_id + ".release")).exists():
        if time.monotonic() >= end:
            event(root, "worker-runtime-bound", task=task_id)
            return 3
        time.sleep(0.01)
    if job["arguments"].get("fail"):
        event(root, "worker-failed", task=task_id)
        return 2
    if int(time.time() * 1000) >= job["binding"]["submission"]["task"]["deadlineUnixMs"]:
        event(root, "worker-deadline-before-effect", task=task_id)
        return 3
    value = job["arguments"]["value"]
    result = {"normalized": value + int(job["arguments"].get("invalid", False)),
              "binding": job["binding"]}
    if job["arguments"].get("paddingBytes"):
        result["padding"] = "x" * job["arguments"]["paddingBytes"]
    path = root / (task_id + ".result.json")
    with path.open("x", encoding="utf-8") as stream:
        stream.write(canonical(result))
        stream.flush()
        os.fsync(stream.fileno())
    event(root, "worker-effect", task=task_id, resultSha256=digest(result))
    return 0


def provider(root):
    def terminate(_signal, _frame):
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, terminate)
    session = str(uuid.uuid4())
    event(root, "provider-start", session=session)
    tasks = {}
    info = {"io.modelcontextprotocol/serverInfo": {"name": "neutral-public-worker", "version": "1.0.0"}}

    def reply(request, value=None, error=None):
        response = {"jsonrpc": "2.0", "id": request["id"]}
        if error:
            response["error"] = {"code": -32602, "message": error}
        else:
            value.setdefault("_meta", {}).update(info)
            response["result"] = value
        event(root, "provider-emitted", session=session, response=response)
        print(canonical(response), flush=True)

    try:
        for line in sys.stdin:
            request = json.loads(line)
            event(root, "provider-received", session=session, request=request)
            if "id" not in request:
                continue
            method = request["method"]
            params = request.get("params", {})
            if method == "server/discover":
                reply(request, {"resultType": "complete", "supportedVersions": [REVISION],
                    "capabilities": {"tools": {}, "extensions": {"io.modelcontextprotocol/tasks": {}}},
                    "ttlMs": 0, "cacheScope": "private"})
            elif method == "initialize":
                reply(request, {"protocolVersion": REVISION, "serverInfo": info["io.modelcontextprotocol/serverInfo"],
                    "capabilities": {"tools": {}, "extensions": {"io.modelcontextprotocol/tasks": {}}}})
            elif method == "tools/list":
                reply(request, {"resultType": "complete", "tools": [TOOL], "ttlMs": 0, "cacheScope": "private"})
            elif method == "tools/call":
                args = params.get("arguments", {})
                binding = params.get("_meta", {}).get(EXECUTION)
                if params.get("name") != "normalize" or not binding or type(args.get("value")) is not int:
                    reply(request, error="NEUTRAL_REQUEST_INVALID")
                    continue
                task_id = "worker-" + str(uuid.uuid4())
                with (root / (task_id + ".stderr.log")).open("x") as errors:
                    proc = subprocess.Popen([sys.executable, __file__, "--root", str(root), "--child", task_id],
                        stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=errors, text=True)
                proc.stdin.write(canonical({"arguments": args, "binding": binding}) + "\n")
                proc.stdin.close()
                now = datetime.datetime.now(datetime.timezone.utc).isoformat()
                task = {"taskId": task_id, "status": "working", "createdAt": now,
                    "lastUpdatedAt": now, "ttlMs": 60000, "pollIntervalMs": 10}
                if args.get("asyncCancel"):
                    task["asyncCancel"] = True
                tasks[task_id] = (task, binding, proc)
                event(root, "provider-accepted", session=session, task=task_id, binding=binding)
                if args.get("withholdAcceptance"):
                    event(root, "provider-withholding-acceptance", task=task_id, session=session)
                    until = time.monotonic() + 10
                    while not (root / (task_id + ".ack-release")).exists() and time.monotonic() < until:
                        time.sleep(0.01)
                visible_task = {key: value for key, value in task.items() if key != "asyncCancel"}
                reply(request, {**visible_task, "resultType": "task", "_meta": {EXECUTION: binding}})
            elif method in ("tasks/get", "tasks/cancel"):
                task_id = params.get("taskId")
                if task_id not in tasks:
                    reply(request, error="NEUTRAL_UNKNOWN_TASK")
                    continue
                task, binding, proc = tasks[task_id]
                if method == "tasks/cancel":
                    if task.get("asyncCancel"):
                        task.setdefault("cancelAfter", time.monotonic() + 0.2)
                        reply(request, {"resultType": "complete"})
                        continue
                    if proc.poll() is None:
                        proc.terminate()
                        proc.wait(timeout=5)
                        task["status"] = "cancelled"
                        event(root, "worker-terminated", task=task_id, session=session)
                    reply(request, {"resultType": "complete"})
                    continue
                if task.get("cancelAfter", float("inf")) <= time.monotonic() and proc.poll() is None:
                    proc.terminate()
                    proc.wait(timeout=5)
                    task["status"] = "cancelled"
                    event(root, "worker-terminated", task=task_id, session=session)
                value = {key: value for key, value in task.items() if key not in ("asyncCancel", "cancelAfter")}
                value.update({"resultType": "complete", "_meta": {EXECUTION: binding}})
                if proc.poll() is not None and task["status"] != "cancelled":
                    if proc.returncode == 0:
                        task["status"] = value["status"] = "completed"
                        result = json.loads((root / (task_id + ".result.json")).read_text())
                        result["artifact"] = {"path": task_id + ".result.json",
                            "sha256": "sha256:" + hashlib.sha256((root / (task_id + ".result.json")).read_bytes()).hexdigest()}
                        value["result"] = {"content": [], "structuredContent": result, "isError": False,
                            "resultType": "complete", "_meta": {EXECUTION: binding, **info}}
                    else:
                        task["status"] = value["status"] = "failed"
                        value["error"] = {"code": -32001, "message": "NEUTRAL_WORKER_FAILED"}
                reply(request, value)
            elif method == "ping":
                reply(request, {"resultType": "complete"})
            else:
                reply(request, error="NEUTRAL_UNSUPPORTED")
    finally:
        for task, binding, proc in tasks.values():
            if proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=5)
                event(root, "worker-cleanup-terminated", task=task["taskId"], session=session)
        event(root, "provider-exit", session=session)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--child")
    options = parser.parse_args()
    if not options.root.is_dir() or options.root.is_symlink():
        raise SystemExit("Owned existing fixture root required")
    raise SystemExit(child(options.root, options.child) if options.child else provider(options.root))
