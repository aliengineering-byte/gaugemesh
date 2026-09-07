"""Optional stdlib MCP worker. Domain code stays outside the gateway's dependencies."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "public_tasks"))
from worker import canonical, digest, event, EXECUTION, REVISION
from mechanics import normalize, solve, strict_json, ReviewStop, VERSION
from oracle import verify_outcome, compare_demand

STAGES = {"input": "", "calculate": "input.json", "synthetic": "calculate.json", "verify": "synthetic.json"}
TOOL = {"name": "section", "description": "Educational original section mechanics; no authorized standards rules",
    "inputSchema": {"type": "object", "properties": {
        "stage": {"type": "string", "enum": list(STAGES)},
        "requestJson": {"type": "string", "maxLength": 6500},
        "predecessor": {"type": "string", "enum": list(STAGES.values())},
        "producerSha256": {"type": "string", "minLength": 71, "maxLength": 71}},
        "required": ["stage", "requestJson", "predecessor", "producerSha256"], "additionalProperties": False},
    "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False}}


def producer_digest():
    paths = [Path(__file__).with_name(name) for name in ("mechanics.py", "oracle.py", "beam_worker.py", "reporting.py", "review.py", "catalog.json")]
    return digest({path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in paths})


def read_stage(root, stage, binding, producer, request_digest):
    path = root / (stage + ".json")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as stream:
        raw = stream.read(32769)
    if len(raw) > 32768:
        raise ValueError("PREDECESSOR_TOO_LARGE")
    value = strict_json(raw.decode())
    old_task, new_task = value["binding"]["submission"]["task"], binding["submission"]["task"]
    if (old_task["correlationId"] != new_task["correlationId"] or
        old_task["logicalTaskId"] != new_task["correlationId"] + "/" + stage or
        value["producerSha256"] != producer or value["requestSha256"] != request_digest or
        value["stage"] != stage or not value["stageDone"]):
        raise ValueError("PREDECESSOR_BINDING_MISMATCH")
    return value


def execute_stage(root, args, binding):
    stage, producer = args["stage"], producer_digest()
    if args["producerSha256"] != producer or args["predecessor"] != STAGES[stage]:
        raise ValueError("FROZEN_PRODUCER_OR_PREDECESSOR_CHANGED")
    request = strict_json(args["requestJson"])
    request_digest = digest(request)
    base = {"schemaVersion": "gaugemesh.concrete-step/1", "stage": stage, "stageDone": True,
        "handoff": stage + ".json", "producerSha256": producer, "producerVersion": VERSION,
        "requestSha256": request_digest, "binding": binding}
    if stage == "input":
        return {**base, "normalized": normalize(request), "status": "INPUT_ACCEPTED"}
    previous = read_stage(root, STAGES[stage][:-5], binding, producer, request_digest)
    normalized = read_stage(root, "input", binding, producer, request_digest)["normalized"]
    if stage == "calculate":
        try:
            calculation = solve(normalized)
        except ReviewStop as stop:
            calculation = {"status": stop.status, "field": stop.field, "reason": stop.reason, "details": stop.details}
        return {**base, "calculation": calculation}
    calculation = read_stage(root, "calculate", binding, producer, request_digest)["calculation"]
    if stage == "synthetic":
        policy = request["rules"]["syntheticPolicy"]
        checked = calculation.get("status") == "MECHANICS_ONLY" and policy is not None
        result = {"label": "SYNTHETIC", "ruleSet": policy, "standardRules": "SOURCE_AUTHORIZATION_REQUIRED",
            "implementedStandardRules": [], "status": "CHECKED_SYNTHETIC_ONLY" if checked else "NOT_EVALUATED",
            "locator": "original:SYNTHETIC_MODEL_DEMAND_MARGIN/1", "implementationVersion": VERSION,
            "applicability": "declared original model response and caller-supplied dimensionless threshold",
            "units": "dimensionless ratio; moments normalized to N*mm",
            "comparison": compare_demand(normalized, calculation, float(policy["maximumRatio"])) if checked else None}
        return {**base, "ruleResult": result}
    consistent, verification = verify_outcome(normalized, calculation, request["rules"]["syntheticPolicy"], previous["ruleResult"])
    return {**base, "evidenceConsistent": consistent, "verification": verification,
        "domainStatus": "MECHANICS_ONLY" if consistent and verification["state"] == "VERIFIED" else "HUMAN_REVIEW_REQUIRED",
        "humanReviewRequired": True, "authorizedStandardRules": "SOURCE_AUTHORIZATION_REQUIRED"}


def child(root, task_id):
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(4))
    job = strict_json(sys.stdin.readline())
    event(root, "worker-start", task=task_id, stage=job["arguments"]["stage"])
    value = execute_stage(root, job["arguments"], job["binding"])
    if int(time.time()*1000) >= job["binding"]["submission"]["task"]["deadlineUnixMs"]:
        raise ValueError("DEADLINE_BEFORE_EFFECT")
    raw = canonical(value).encode()
    if len(raw) > 28000:
        raise ValueError("BOUNDED_RESULT_TOO_LARGE")
    with (root / value["handoff"]).open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    event(root, "worker-effect", task=task_id, stage=value["stage"], resultSha256="sha256:" + hashlib.sha256(raw).hexdigest())


def provider(root):
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    session, tasks = str(uuid.uuid4()), {}
    info = {"io.modelcontextprotocol/serverInfo": {"name": "optional-concrete-mechanics-consumer", "version": VERSION}}
    event(root, "provider-start", session=session)
    def reply(request, result=None, error=None):
        response = {"jsonrpc": "2.0", "id": request["id"]}
        if error:
            response["error"] = {"code": -32602, "message": error}
        else:
            result.setdefault("_meta", {}).update(info)
            response["result"] = result
        event(root, "provider-emitted", session=session, response=response)
        print(canonical(response), flush=True)
    try:
        for line in sys.stdin:
            request = strict_json(line)
            event(root, "provider-received", session=session, request=request)
            if "id" not in request:
                continue
            method, params = request["method"], request.get("params", {})
            capabilities = {"tools": {}, "extensions": {"io.modelcontextprotocol/tasks": {}}}
            if method == "server/discover":
                reply(request, {"resultType": "complete", "supportedVersions": [REVISION], "capabilities": capabilities, "ttlMs": 0, "cacheScope": "private"})
            elif method == "initialize":
                reply(request, {"protocolVersion": REVISION, "serverInfo": info["io.modelcontextprotocol/serverInfo"], "capabilities": capabilities})
            elif method == "tools/list":
                reply(request, {"resultType": "complete", "tools": [TOOL], "ttlMs": 0, "cacheScope": "private"})
            elif method == "tools/call":
                args, binding = params.get("arguments", {}), params.get("_meta", {}).get(EXECUTION)
                if params.get("name") != "section" or not binding or set(args) != {"stage", "requestJson", "predecessor", "producerSha256"} or args.get("stage") not in STAGES:
                    reply(request, error="CONCRETE_REQUEST_INVALID")
                    continue
                task_id = "beam-" + str(uuid.uuid4())
                with (root / (task_id + ".stderr.log")).open("x") as errors:
                    proc = subprocess.Popen([sys.executable, __file__, "--root", str(root), "--child", task_id], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=errors, text=True)
                proc.stdin.write(canonical({"arguments": args, "binding": binding}) + "\n")
                proc.stdin.close()
                now = datetime.datetime.now(datetime.timezone.utc).isoformat()
                task = {"taskId": task_id, "status": "working", "createdAt": now, "lastUpdatedAt": now, "ttlMs": 3600000, "pollIntervalMs": 20}
                tasks[task_id] = (task, binding, proc, args["stage"])
                event(root, "provider-accepted", session=session, task=task_id, binding=binding, stage=args["stage"])
                reply(request, {**task, "resultType": "task", "_meta": {EXECUTION: binding}})
            elif method in ("tasks/get", "tasks/cancel"):
                record = tasks.get(params.get("taskId"))
                if record is None:
                    reply(request, error="CONCRETE_UNKNOWN_TASK")
                    continue
                task, binding, proc, stage = record
                if method == "tasks/cancel":
                    if proc.poll() is None:
                        proc.terminate()
                        proc.wait(timeout=5)
                        task["status"] = "cancelled"
                    reply(request, {"resultType": "complete"})
                    continue
                value = {**task, "resultType": "complete", "_meta": {EXECUTION: binding}}
                if proc.poll() is not None and task["status"] != "cancelled":
                    value["status"] = "completed" if proc.returncode == 0 else "failed"
                    if proc.returncode == 0:
                        raw = (root / (stage + ".json")).read_bytes()
                        result = strict_json(raw.decode())
                        result["artifact"] = {"path": stage + ".json", "sha256": "sha256:" + hashlib.sha256(raw).hexdigest()}
                        value["result"] = {"content": [], "structuredContent": result, "isError": False, "resultType": "complete", "_meta": {EXECUTION: binding, **info}}
                    else:
                        value["error"] = {"code": -32001, "message": "CONCRETE_WORKER_FAILED"}
                reply(request, value)
            elif method == "ping":
                reply(request, {"resultType": "complete"})
            else:
                reply(request, error="CONCRETE_METHOD_UNSUPPORTED")
    finally:
        for task, binding, proc, stage in tasks.values():
            if proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=5)
        event(root, "provider-exit", session=session)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--child")
    args = parser.parse_args()
    if not args.root.is_dir() or args.root.is_symlink():
        raise SystemExit("Existing owned non-symlink root required")
    child(args.root, args.child) if args.child else provider(args.root)
