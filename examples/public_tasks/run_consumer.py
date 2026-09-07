"""Public Run qualification: installed binary, independent Python client/worker, raw wire evidence.

No Rust imports, private dispatch commands, or database reads/writes. All mutable
files belong to the fresh synthetic fixture directory created by this invocation.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

from consumer import Client, digest, read_events, setup, wait_for, verify_owned_stopped


class Harness:
    def __init__(self, binary, root):
        self.binary, self.root = binary, root
        self.config, self.worker = setup(binary, root)
        self.start()

    def start(self):
        self.client = Client([self.binary, "mcp-stdio", "--config", str(self.config)], self.root)
        self.client.rpc("server/discover")
        self.description = self.client.tool("gaugemesh_describe", {"alias": "neutral__normalize"})["structuredContent"]
        self.lease = self.client.tool("gaugemesh_lease", {"aliases": ["neutral__normalize"], "ttlMs": 600000,
            "sideEffects": ["read_only", "idempotent_write", "non_idempotent_write"]})["structuredContent"]["leaseId"]

    def run(self, action, run_id=None, plan=None, expect_error=None):
        arguments = {"action": action, "leaseId": self.lease}
        if run_id:
            arguments["runId"] = run_id
        if plan:
            arguments["plan"] = plan
        result = self.client.tool("gaugemesh_run", arguments)
        if expect_error:
            assert result.get("isError") and expect_error in json.dumps(result), result
            return result
        assert not result.get("isError"), result
        return result["structuredContent"]

    def step(self, name, dependencies=(), value=7, reference=None, **worker_args):
        arguments = {"value": {"kind": "predecessor", "step": reference, "pointer": "/normalized"}
                     if reference else {"kind": "literal", "value": value}}
        arguments.update({name: {"kind": "literal", "value": value} for name, value in worker_args.items()})
        policy = {"schemaVersion": "gaugemesh.json-artifact-policy/1", "checks": [
            {"pointer": "/normalized", "expected": value, "required": True},
            {"pointer": "/optionalUnprovided", "expected": True, "required": False}]}
        return {"id": name, "dependsOn": list(dependencies), "alias": "neutral__normalize",
            "capabilityId": self.description["capabilityId"], "providerInterfaceVersion": self.description["schemaDigest"],
            "arguments": arguments, "inputsSha256": digest(arguments), "policy": policy, "policySha256": digest(policy),
            "permittedEffect": "non_idempotent_write", "maxRuntimeMs": 30000, "maxArtifactBytes": 1048576}

    def plan(self, key, steps, concurrency=2, deadline_ms=120000):
        return {"schemaVersion": "gaugemesh.run-plan/1", "runKey": key,
            "deadlineUnixMs": int(time.time() * 1000) + deadline_ms, "maxConcurrency": concurrency,
            "maxAttempts": 1, "failurePolicy": "fail_fast_account_inflight", "uncertaintyPolicy": "stop_no_replay",
            "cancellationPolicy": "intent_then_poll", "artifactRoot": str(self.worker), "steps": steps}

    def finish(self, run_id, status="verified", timeout=15):
        def drive():
            result = self.run("resume", run_id)
            return result if result["status"] not in ("ready", "in_progress") else None
        result = wait_for(drive, "run reaches bounded outcome", timeout=timeout)
        assert result["status"] == status, result
        return result

    def accepted(self, run_id):
        return [e for e in read_events(self.worker) if e["kind"] == "provider-accepted"
            and e["binding"]["submission"]["task"]["correlationId"] == run_id]

    def starts(self, run_id):
        ids = {e["task"] for e in self.accepted(run_id)}
        return [e for e in read_events(self.worker) if e["kind"] == "worker-start" and e["task"] in ids]


def qualify(binary, root):
    h = Harness(binary, root)
    results = {}
    try:
        plan = h.plan("chain-restart", [h.step("a"), h.step("b", ["a"], reference="a"), h.step("c", ["b"], reference="b")])
        accepted = h.run("submit", plan=plan)
        run_id = accepted["runId"]
        assert not h.accepted(run_id), "Admission dispatched work"
        assert h.run("submit", plan=plan)["runId"] == run_id
        changed = copy.deepcopy(plan)
        changed["maxConcurrency"] = 1
        h.run("submit", plan=changed, expect_error="GM_RUN_IDEMPOTENCY_CONFLICT")
        def checkpoint():
            state = h.run("resume", run_id)
            return state if state["steps"]["a"]["phase"] == "verified" else None
        checkpoint = wait_for(checkpoint, "A durably verified before B dispatch")
        assert checkpoint["steps"]["b"]["phase"] == "pending"
        before_pid = h.client.proc.pid
        h.client.close()
        h.start()
        assert h.client.proc.pid != before_pid
        completed = h.finish(run_id)
        assert len(h.starts(run_id)) == 3
        assert all(s["verification"]["checks"][1]["passed"] is False for s in completed["steps"].values())
        export = h.run("export", run_id)
        export_path = root / "chain-export.json"
        export_path.write_text(json.dumps(export, indent=2) + "\n")
        offline = subprocess.run([binary, "run-verify", "--evidence", str(export_path)], capture_output=True, text=True, check=True)
        assert json.loads(offline.stdout)["complete"]
        h.client.close()
        h.start()
        assert h.run("status", run_id)["status"] == "verified"
        assert h.run("verify", run_id)["complete"]
        assert len(h.starts(run_id)) == 3
        results["chainRestartDuplicateOffline"] = {"status": "PASS", "runId": run_id, "starts": 3, "actualGatewayRestart": True}

        # Two simultaneously held roots force the concurrency limit to be observable.
        diamond = h.plan("diamond", [h.step("a", hold=True), h.step("b", hold=True),
            h.step("c", ["a"], reference="a"), h.step("d", ["b", "c"], reference="c")])
        diamond_id = h.run("submit", plan=diamond)["runId"]
        h.run("resume", diamond_id)
        wait_for(lambda: len(h.starts(diamond_id)) == 2, "two concurrent children")
        for _ in range(3):
            state = h.run("resume", diamond_id)
            assert len(h.starts(diamond_id)) == 2
            assert state["steps"]["c"]["phase"] == "pending"
        for accepted_task in h.accepted(diamond_id):
            (h.worker / (accepted_task["task"] + ".release")).touch(exist_ok=False)
        h.finish(diamond_id)
        assert len(h.starts(diamond_id)) == 4
        results["dagAndConcurrency"] = {"status": "PASS", "runId": diamond_id, "observedSimultaneousHeldWorkers": 2, "starts": 4}

        concurrent_id = h.run("submit", plan=h.plan("concurrent-resumes", [h.step("a", hold=True)]))["runId"]
        request_ids = {h.client.send("tools/call", {"name": "gaugemesh_run", "arguments": {
            "action": "resume", "runId": concurrent_id, "leaseId": h.lease}}) for _ in range(2)}
        responses = [h.client.receive_any() for _ in range(2)]
        assert {r["id"] for r in responses} == request_ids
        assert all("error" not in r and not r["result"].get("isError") for r in responses), responses
        wait_for(lambda: len(h.starts(concurrent_id)) == 1, "concurrent resumes shared one task")
        only_task = h.accepted(concurrent_id)[0]["task"]
        (h.worker / (only_task + ".release")).touch(exist_ok=False)
        h.finish(concurrent_id)
        assert len(h.starts(concurrent_id)) == 1
        results["concurrentResumes"] = {"status": "PASS", "simultaneousRequests": 2, "starts": 1}

        # Exercise the maximum step count with near-limit outputs, not just schemas.
        bounded_id = h.run("submit", plan=h.plan("aggregate-evidence-bound", [h.step(f"s{i}", paddingBytes=24576)
            for i in range(16)], concurrency=4))["runId"]
        h.finish(bounded_id, timeout=60)
        bounded_export = h.run("export", bounded_id)
        bounded_bytes = len(json.dumps(bounded_export["data"], separators=(",", ":")).encode())
        assert bounded_bytes < 2 * 1024 * 1024
        assert len(h.starts(bounded_id)) == 16
        results["aggregateEvidenceBound"] = {"status": "PASS", "steps": 16, "payloadBytesPerStep": 24576,
            "durableDataBytes": bounded_bytes}

        unclobbered_id = h.run("submit", plan=h.plan("no-clobber", [h.step("a", hold=True)]))["runId"]
        h.run("resume", unclobbered_id)
        wait_for(lambda: len(h.starts(unclobbered_id)) == 1, "exclusive-write fixture held")
        only_task = h.accepted(unclobbered_id)[0]["task"]
        target = h.worker / (only_task + ".result.json")
        with target.open("x") as stream: stream.write("owned sentinel")
        (h.worker / (only_task + ".release")).touch(exist_ok=False)
        h.finish(unclobbered_id, "failed")
        assert target.read_text() == "owned sentinel"
        results["noClobber"] = {"status": "PASS", "sentinelPreserved": True}

        expired_id = h.run("submit", plan=h.plan("expired-lease", [h.step("a")]))["runId"]
        previous_lease = h.lease
        h.lease = h.client.tool("gaugemesh_lease", {"aliases": ["neutral__normalize"], "ttlMs": 1,
            "sideEffects": ["read_only", "idempotent_write", "non_idempotent_write"]})["structuredContent"]["leaseId"]
        time.sleep(0.02)
        h.run("resume", expired_id, expect_error="GM_LEASE_EXPIRED")
        assert not h.accepted(expired_id)
        h.run("cancel", expired_id)
        h.finish(expired_id, "cancelled_or_stopped")
        h.lease = previous_lease
        results["expiredLease"] = {"status": "PASS", "starts": 0}

        for mode in ("fail", "invalid"):
            bad_plan = h.plan(mode, [h.step("a", **{mode: True}), h.step("b", ["a"], reference="a")])
            bad_id = h.run("submit", plan=bad_plan)["runId"]
            failed = h.finish(bad_id, "failed")
            assert failed["steps"]["b"]["phase"] == "skipped"
            assert len(h.starts(bad_id)) == 1
            results[mode] = {"status": "PASS", "successorStarts": 0, "result": failed}

        held_id = h.run("submit", plan=h.plan("cancel", [h.step("a", hold=True, asyncCancel=True), h.step("b", ["a"], reference="a")]))["runId"]
        h.run("resume", held_id)
        wait_for(lambda: len(h.starts(held_id)) == 1, "cancel child started")
        h.client.tool("gaugemesh_release", {"leaseId": h.lease})
        h.run("resume", held_id, expect_error="GM_RUN_LEASE_REVOKED_OR_UNKNOWN")
        intent = h.run("cancel", held_id)
        assert intent["cancelRequested"]
        task = h.accepted(held_id)[0]["task"]
        time.sleep(0.1)
        assert not any(e["kind"] == "worker-terminated" and e.get("task") == task for e in read_events(h.worker))
        cancelled = h.finish(held_id, "cancelled_or_stopped")
        assert cancelled["steps"]["a"]["phase"] == "cancelled"
        assert len(h.starts(held_id)) == 1
        results["cancellationRevocationNoPoll"] = {"status": "PASS", "intentDidNotTerminateChild": True, "result": cancelled}
        # Renew only the lease; the immutable plan remains unchanged.
        h.lease = h.client.tool("gaugemesh_lease", {"aliases": ["neutral__normalize"], "ttlMs": 600000,
            "sideEffects": ["read_only", "idempotent_write", "non_idempotent_write"]})["structuredContent"]["leaseId"]

        deadline_plan = h.plan("deadline", [h.step("a", hold=True)], deadline_ms=2000)
        deadline_id = h.run("submit", plan=deadline_plan)["runId"]
        h.run("resume", deadline_id)
        task = h.accepted(deadline_id)[0]["task"]
        wait_for(lambda: int(time.time() * 1000) > deadline_plan["deadlineUnixMs"], "deadline without driver")
        assert not any(e["kind"] == "worker-terminated" and e.get("task") == task for e in read_events(h.worker))
        deadline = h.finish(deadline_id, "deadline_exceeded")
        results["deadlineNoPoll"] = {"status": "PASS", "result": deadline}

        before = len([e for e in read_events(h.worker) if e["kind"] == "worker-start"])
        invalid_cases = {}
        for mode in ("cycle", "missing", "duplicate", "bounds", "schema", "path", "wrong_type", "missing_input", "pointer", "policy"):
            candidate = h.plan("reject-" + mode, [h.step("a"), h.step("b", ["a"], reference="a")])
            expected = "GM_RUN_"
            if mode == "cycle": candidate["steps"][0]["dependsOn"] = ["b"]
            if mode == "missing": candidate["steps"][0]["dependsOn"] = ["absent"]
            if mode == "duplicate": candidate["steps"][1]["id"] = "a"
            if mode == "bounds": candidate["maxConcurrency"] = 5
            if mode == "schema": candidate["schemaVersion"] = "unsupported"
            if mode == "path": candidate["artifactRoot"] = "relative-root"
            if mode == "wrong_type": candidate["steps"][0]["arguments"]["value"]["value"] = "not-an-integer"
            if mode == "missing_input": del candidate["steps"][0]["arguments"]["value"]
            if mode == "pointer": candidate["steps"][1]["arguments"]["value"]["pointer"] = "/~bad"
            if mode == "policy": candidate["steps"][0]["policySha256"] = digest({"wrong": True})
            for step in candidate["steps"]: step["inputsSha256"] = digest(step["arguments"])
            invalid_cases[mode] = h.run("submit", plan=candidate, expect_error=expected)
        assert before == len([e for e in read_events(h.worker) if e["kind"] == "worker-start"])
        results["preAdmissionRefusals"] = {"status": "PASS", "newWorkerStarts": 0, "cases": invalid_cases}

        # Offline corruption checks never launch the gateway/provider and cannot run commands.
        artifact_path = h.worker / export["data"]["steps"]["a"]["terminal"]["result"]["structuredContent"]["artifact"]["path"]
        original = artifact_path.read_bytes()
        original_evidence = export_path.read_bytes()
        negative_results = {}
        for mode in ("missing", "truncated", "swapped", "tampered_evidence", "wrong_policy", "symlink"):
            saved = artifact_path.with_suffix(".saved")
            try:
                if mode in ("missing", "symlink"):
                    artifact_path.rename(saved)
                    if mode == "symlink": artifact_path.symlink_to(saved)
                if mode == "truncated": artifact_path.write_bytes(b"{")
                if mode == "swapped":
                    other_path = h.worker / export["data"]["steps"]["b"]["terminal"]["result"]["structuredContent"]["artifact"]["path"]
                    artifact_path.write_bytes(other_path.read_bytes())
                if mode in ("tampered_evidence", "wrong_policy"):
                    forged = copy.deepcopy(export)
                    if mode == "tampered_evidence": forged["data"]["steps"]["a"]["verifiedArtifact"]["normalized"] = 999
                    else: forged["data"]["plan"]["steps"][0]["policy"]["checks"][0]["expected"] = 999
                    export_path.write_text(json.dumps(forged))
                check = subprocess.run([binary, "run-verify", "--evidence", str(export_path)], capture_output=True, text=True)
                assert check.returncode != 0, mode
                negative_results[mode] = check.stderr.strip()
            finally:
                if artifact_path.is_symlink(): artifact_path.unlink()
                if saved.exists(): saved.rename(artifact_path)
                artifact_path.write_bytes(original)
                export_path.write_bytes(original_evidence)
        results["artifactAndEvidenceRefusals"] = {"status": "PASS", "cases": negative_results}

        uncertain_id = h.run("submit", plan=h.plan("uncertain-session", [h.step("a", hold=True), h.step("b", ["a"], reference="a")]))["runId"]
        h.run("resume", uncertain_id)
        wait_for(lambda: len(h.starts(uncertain_id)) == 1, "uncertain worker started")
        h.client.close()
        h.start()
        uncertain = h.finish(uncertain_id, "reconciliation_required")
        assert h.run("resume", uncertain_id)["status"] == "reconciliation_required"
        assert len(h.starts(uncertain_id)) == 1
        results["ambiguousSessionNoReplay"] = {"status": "PASS", "starts": 1, "result": uncertain}

        # Real process death after independent provider acceptance/effect but before
        # either acknowledgement can reach the Run driver. No database manipulation.
        crash_id = h.run("submit", plan=h.plan("accepted-before-id-crash", [h.step("a", withholdAcceptance=True),
            h.step("b", ["a"], reference="a")]))["runId"]
        request_id = h.client.send("tools/call", {"name": "gaugemesh_run", "arguments": {
            "action": "resume", "runId": crash_id, "leaseId": h.lease}})
        accepted_task = wait_for(lambda: h.accepted(crash_id), "actual provider acceptance before acknowledgement")[0]
        wait_for(lambda: any(e["kind"] == "worker-effect" and e.get("task") == accepted_task["task"]
            for e in read_events(h.worker)), "independent side effect before gateway crash")
        assert h.client.responses.empty(), "Blocked acceptance unexpectedly reached Run caller"
        killed_pid = h.client.proc.pid
        h.client.proc.kill()
        h.client.proc.wait(timeout=5)
        h.client.close()
        (h.worker / (accepted_task["task"] + ".ack-release")).touch(exist_ok=False)
        h.start()
        before_recovery = h.run("status", crash_id)
        assert before_recovery["steps"]["a"]["phase"] == "submitting"
        assert before_recovery["steps"]["a"]["taskId"] is None
        crash = h.finish(crash_id, "reconciliation_required")
        assert crash["steps"]["a"]["taskId"] == accepted_task["binding"]["publicTaskId"]
        assert len(h.starts(crash_id)) == 1
        results["acceptedBeforeIdRealCrash"] = {"status": "PASS", "killedGatewayPid": killed_pid,
            "interruptedRequestId": request_id, "starts": 1, "effects": 1,
            "guarantee": "same public Task recovered; outcome remains unknown after session change; no replay", "result": crash}
    finally:
        h.client.close()
    results["cleanup"] = verify_owned_stopped(h.worker)
    results["binaryVersion"] = subprocess.check_output([binary, "--version"], text=True).strip()
    results["binarySha256"] = hashlib.sha256(Path(binary).read_bytes()).hexdigest()
    results["suite"] = "external-public-runs/1"
    (root / "result.json").write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps({key: value.get("status", value) if isinstance(value, dict) else value for key, value in results.items()}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()
    qualify(str(options.binary.resolve(strict=True)), options.output.resolve())
