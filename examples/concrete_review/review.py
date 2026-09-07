"""First-use local consumer of the released GaugeMesh Run interface. No Rust imports."""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "public_tasks"))
from consumer import Client, digest, read_events, verify_owned_stopped
from mechanics import normalize, strict_json, ReviewStop, EXCLUSIONS, VERSION
from oracle import verify_outcome, compare_demand
from reporting import exclusive_json, render, documents
from beam_worker import producer_digest, STAGES


def bounded_json(path, maximum=1048576):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
        raise ValueError("Bounded regular input file required: " + str(path))
    return strict_json(path.read_text(encoding="utf-8"))


def catalog():
    return bounded_json(Path(__file__).with_name("catalog.json"))


def check_frozen(frozen, root):
    if frozen["producerSha256"] != producer_digest() or frozen["requestSha256"] != digest(frozen["request"]) or frozen["planSha256"] != digest(frozen["plan"]):
        raise ValueError("FROZEN_INPUT_PLAN_OR_PRODUCER_CHANGED")
    expected = json.dumps(frozen["request"], sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    if frozen["plan"]["artifactRoot"] != str(root / "worker") or any(
        step["arguments"]["requestJson"] != {"kind": "literal", "value": expected} or
        step["arguments"]["producerSha256"] != {"kind": "literal", "value": producer_digest()}
        for step in frozen["plan"]["steps"]):
        raise ValueError("FROZEN_REQUEST_PLAN_BINDING_CHANGED")


def admission(request, accepted):
    if not accepted:
        raise ReviewStop("NEEDS_INPUT", "assumption approval", "Review the explicit model and pass --accept-assumptions; no defaults or consent inferred")
    if isinstance(request, dict) and isinstance(request.get("rules"), dict):
        selected = request["rules"].get("standard")
        if selected is not None and selected not in [entry["id"] for entry in catalog()["entries"]]:
            raise ReviewStop("OUT_OF_SCOPE", "rules.standard", "UNSUPPORTED_STANDARD_EDITION: no edition fallback or mixing")
    return normalize(request)


def call(client, name, arguments):
    result = client.tool(name, arguments)
    if result.get("isError"):
        raise ValueError(json.dumps(result))
    return result["structuredContent"]


def create_plan(client, root, request):
    description = call(client, "gaugemesh_describe", {"alias": "concrete__section"})
    producer = producer_digest()
    request_json = json.dumps(request, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    if len(request_json.encode()) > 6500:
        raise ReviewStop("NEEDS_INPUT", "request", "request exceeds the bounded public input contract")
    steps, previous = [], None
    for stage in STAGES:
        args = {"stage": {"kind": "literal", "value": stage}, "requestJson": {"kind": "literal", "value": request_json},
            "producerSha256": {"kind": "literal", "value": producer},
            "predecessor": {"kind": "predecessor", "step": previous, "pointer": "/handoff"} if previous else {"kind": "literal", "value": ""}}
        checks = [{"pointer": "/stageDone", "expected": True, "required": True},
            {"pointer": "/handoff", "expected": stage + ".json", "required": True},
            {"pointer": "/producerSha256", "expected": producer, "required": True},
            {"pointer": "/requestSha256", "expected": digest(request), "required": True}]
        if stage == "verify":
            checks.append({"pointer": "/evidenceConsistent", "expected": True, "required": True})
        policy = {"schemaVersion": "gaugemesh.json-artifact-policy/1", "checks": checks}
        steps.append({"id": stage, "dependsOn": [previous] if previous else [], "alias": "concrete__section",
            "capabilityId": description["capabilityId"], "providerInterfaceVersion": description["schemaDigest"],
            "arguments": args, "inputsSha256": digest(args), "policy": policy, "policySha256": digest(policy),
            "permittedEffect": "non_idempotent_write", "maxRuntimeMs": 30000, "maxArtifactBytes": 1048576})
        previous = stage
    return {"schemaVersion": "gaugemesh.run-plan/1", "runKey": "concrete-" + digest(request)[7:39],
        "deadlineUnixMs": int(time.time()*1000) + 600000, "artifactRoot": str(root / "worker"),
        "maxConcurrency": 1, "maxAttempts": 1, "failurePolicy": "fail_fast_account_inflight",
        "uncertaintyPolicy": "stop_no_replay", "cancellationPolicy": "intent_then_poll", "steps": steps}


def setup(binary, root):
    worker = root / "worker"
    worker.mkdir()
    config = root / "gateway.yaml"
    subprocess.run([binary, "init", str(config)], check=True, capture_output=True)
    text = config.read_text()
    config.write_text(text.replace("mode: memory", "mode: sqlite\n  database: " + json.dumps(str(root / "runs.sqlite3"))))
    subprocess.run([binary, "add", "mcp", "concrete", "--config", str(config), "--command", sys.executable,
        "--arg", str(Path(__file__).with_name("beam_worker.py")), "--arg=--root", "--arg", str(worker)], check=True, capture_output=True)
    return config


def report_base(request, binary, root):
    fields = request if isinstance(request, dict) else {}
    return {"schemaVersion": "gaugemesh.concrete-review-result/1", "producerVersion": VERSION,
        "producerSha256": producer_digest(), "originalRequest": request,
        "scopeAndAssumptions": {"scope": fields.get("scope"), "model": fields.get("model"), "profile": fields.get("profile")},
        "humanReviewRequired": True, "coverage": {key: "NOT_EVALUATED" for key in EXCLUSIONS + ["concrete_crushing", "material_model_applicability", "code_capacity", "code_compliance", "load_derivation"]},
        "standardCatalog": catalog(), "sourceStatus": "SOURCE_AUTHORIZATION_REQUIRED",
        "verificationCommand": f"python3 {shlex.quote(str(Path(__file__).resolve()))} verify --binary {shlex.quote(binary)} --output {shlex.quote(str(root))}"}


def drive(binary, root, new_request=None, pause=False):
    if new_request is None and (root / "report-manifest.json").exists():
        return verify(binary, root)
    if subprocess.check_output([binary, "--version"], text=True).strip() != "gaugemesh 0.4.1":
        raise ValueError("This consumer requires GaugeMesh 0.4.1; 0.4.0 has a finite-numeric evidence round-trip defect")
    config = setup(binary, root) if new_request is not None else root / "gateway.yaml"
    if new_request is None:
        frozen = bounded_json(root / "frozen.json")
        check_frozen(frozen, root)
        admission(frozen["request"], frozen["assumptionsAccepted"])
    client = Client([binary, "mcp-stdio", "--config", str(config)], root)
    try:
        client.rpc("server/discover")
        lease = call(client, "gaugemesh_lease", {"aliases": ["concrete__section"], "ttlMs": 600000,
            "sideEffects": ["read_only", "idempotent_write", "non_idempotent_write"]})["leaseId"]
        if new_request is not None:
            plan = create_plan(client, root, new_request)
            frozen = {"schemaVersion": "gaugemesh.concrete-frozen/1", "request": new_request, "requestSha256": digest(new_request),
                "producerSha256": producer_digest(), "assumptionsAccepted": True, "plan": plan, "planSha256": digest(plan)}
            exclusive_json(root / "frozen.json", frozen)
        result = call(client, "gaugemesh_run", {"action": "submit", "plan": frozen["plan"], "leaseId": lease})
        run_id = result["runId"]
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            result = call(client, "gaugemesh_run", {"action": "resume", "runId": run_id, "leaseId": lease})
            if pause and result["steps"]["input"]["phase"] == "verified":
                assert result["steps"]["calculate"]["phase"] == "pending"
                break
            if result["status"] not in ("ready", "in_progress"):
                break
            time.sleep(0.01)
        else:
            raise ValueError("DRIVER_OBSERVATION_TIMEOUT: use resume on this same frozen plan, never create a replay")
        evidence = call(client, "gaugemesh_run", {"action": "export", "runId": run_id})
    finally:
        client.close()
    cleanup = verify_owned_stopped(root / "worker")
    request = frozen["request"]
    base = report_base(request, binary, root)
    states = {key: step["phase"] for key, step in result["steps"].items()}
    base.update({"runId": run_id, "runPlanSha256": frozen["planSha256"], "runState": result["status"],
        "stepStates": states, "cleanup": cleanup, "executionState": "PAUSED" if pause else result["status"],
        "verificationState": "NOT_EVALUATED", "domainStatus": "HUMAN_REVIEW_REQUIRED"})
    base["normalized"] = normalize(request)
    if pause:
        base["diagnostic"] = "Input step durably verified; gateway stopped before calculation. Resume the same output directory."
        exclusive_json(root / "paused-export.json", evidence)
        render(root, base, "report-paused")
        return base
    if (root / "report-manifest.json").exists():
        return verify(binary, root)
    exclusive_json(root / "run-export.json", evidence)
    if result["status"] == "verified":
        accepted = evidence["data"]["steps"]
        base["calculation"] = accepted["calculate"]["verifiedArtifact"]["calculation"]
        base["syntheticRule"] = accepted["synthetic"]["verifiedArtifact"]["ruleResult"]
        base["independentVerification"] = accepted["verify"]["verifiedArtifact"]["verification"]
        base["verificationState"] = base["independentVerification"]["state"]
        base["domainStatus"] = accepted["verify"]["verifiedArtifact"]["domainStatus"]
        if base["verificationState"] == "VERIFIED":
            base["comparison"] = compare_demand(base["normalized"], base["calculation"])
            base["coverage"]["declared_section_equilibrium"] = "CHECKED_WITHIN_DECLARED_SCOPE"
        else:
            base["diagnostic"] = base["calculation"].get("reason", "No converged calculation")
    else:
        base["diagnostic"] = "Run not verified. Preserve evidence; unknown execution must not be replayed."
    base["workerStarts"] = len([item for item in read_events(root / "worker") if item["kind"] == "worker-start"])
    hashes = render(root, base)
    exclusive_json(root / "report-manifest.json", {"files": hashes, "runExportSha256": hashlib.sha256((root / "run-export.json").read_bytes()).hexdigest(),
        "trustBoundary": "recomputable integrity hashes, not signatures; retain a trusted original"})
    if result["status"] == "verified":
        verify(binary, root)
    return base


def verify(binary, root):
    frozen = bounded_json(root / "frozen.json")
    check_frozen(frozen, root)
    evidence = bounded_json(root / "run-export.json", 3*1024*1024)
    if evidence["data"]["plan"] != frozen["plan"]:
        raise ValueError("FROZEN_PLAN_EXPORT_MISMATCH")
    offline = json.loads(subprocess.check_output([binary, "run-verify", "--evidence", str(root / "run-export.json")], text=True))
    if not offline["complete"]:
        raise ValueError("RUN_NOT_COMPLETE")
    manifest = bounded_json(root / "report-manifest.json")
    if set(manifest["files"]) != {"report.json", "report.md", "report.html"}:
        raise ValueError("UNEXPECTED_REPORT_FILES")
    for name, expected in {**manifest["files"], "run-export.json": manifest["runExportSha256"]}.items():
        path = root / name
        if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError("REPORT_OR_EVIDENCE_CHANGED")
    accepted = evidence["data"]["steps"]
    normalized = normalize(frozen["request"])
    if accepted["input"]["verifiedArtifact"]["normalized"] != normalized:
        raise ValueError("INPUT_NORMALIZATION_CHANGED")
    calculation = accepted["calculate"]["verifiedArtifact"]["calculation"]
    consistent, independent = verify_outcome(normalized, calculation, frozen["request"]["rules"]["syntheticPolicy"], accepted["synthetic"]["verifiedArtifact"]["ruleResult"])
    if not consistent or independent != accepted["verify"]["verifiedArtifact"]["verification"]:
        raise ValueError("INDEPENDENT_VERIFICATION_FAILED")
    report = bounded_json(root / "report.json")
    expected = report_base(frozen["request"], binary, root)
    for key in ("schemaVersion", "originalRequest", "scopeAndAssumptions", "humanReviewRequired", "standardCatalog", "sourceStatus", "producerSha256", "producerVersion", "verificationCommand"):
        if report.get(key) != expected[key]:
            raise ValueError("REPORT_SOURCE_BINDING_CHANGED: " + key)
    expected_verification = accepted["verify"]["verifiedArtifact"]["verification"]
    expected_domain = "MECHANICS_ONLY" if independent["state"] == "VERIFIED" else "HUMAN_REVIEW_REQUIRED"
    if accepted["verify"]["verifiedArtifact"]["domainStatus"] != expected_domain:
        raise ValueError("DOMAIN_OUTCOME_BINDING_CHANGED")
    expected_coverage = expected["coverage"]
    if independent["state"] == "VERIFIED":
        expected_coverage["declared_section_equilibrium"] = "CHECKED_WITHIN_DECLARED_SCOPE"
    required = {"calculation": calculation, "normalized": normalized,
        "syntheticRule": accepted["synthetic"]["verifiedArtifact"]["ruleResult"],
        "independentVerification": expected_verification, "verificationState": independent["state"],
        "executionState": "verified", "runState": "verified", "domainStatus": expected_domain, "coverage": expected_coverage,
        "workerStarts": len(accepted),
        "runId": evidence["runId"], "runPlanSha256": frozen["planSha256"]}
    if independent["state"] == "VERIFIED":
        required["comparison"] = compare_demand(normalized, calculation)
        if "diagnostic" in report:
            raise ValueError("UNEXPECTED_REPORT_DIAGNOSTIC")
    else:
        required["diagnostic"] = calculation["reason"]
    if any(report.get(key) != value for key, value in required.items()):
        raise ValueError("REPORT_COMPUTATION_BINDING_CHANGED")
    expected_html, expected_markdown = documents(report)
    if (root / "report.html").read_text(encoding="utf-8") != expected_html or (root / "report.md").read_text(encoding="utf-8") != expected_markdown:
        raise ValueError("REPORT_RENDERING_CHANGED")
    return {"schemaVersion": "gaugemesh.concrete-offline-verification/1", "runId": evidence["runId"],
        "executionPerformed": False, "runIntegrity": offline["integrity"], "calculationVerification": independent["state"],
        "reportIntegrity": "verified", "authorizedRules": "SOURCE_AUTHORIZATION_REQUIRED"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["run", "resume", "verify", "catalog"])
    parser.add_argument("--binary")
    parser.add_argument("--request", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--accept-assumptions", action="store_true")
    parser.add_argument("--pause-after-input", action="store_true")
    options = parser.parse_args()
    if options.action == "catalog":
        print(json.dumps(catalog(), indent=2))
        return 0
    if options.binary is None or options.output is None:
        parser.error("--binary and --output are required")
    binary, root = str(Path(options.binary).resolve()), options.output.absolute()
    if options.action == "run":
        if options.request is None:
            parser.error("--request is required for run")
        root.mkdir(parents=True, exist_ok=False)
        request = {}
        try:
            request = bounded_json(options.request, 16384)
            if not isinstance(request, dict):
                raise ReviewStop("NEEDS_INPUT", "request", "JSON object required")
            admission(request, options.accept_assumptions)
        except (ReviewStop, json.JSONDecodeError) as stop:
            status = getattr(stop, "status", "NEEDS_INPUT")
            base = report_base(request, binary, root)
            base.update({"executionState": "NOT_STARTED", "verificationState": "NOT_EVALUATED",
                "domainStatus": status, "diagnostic": str(stop), "verificationCommand": "No accepted Run exists; correct the explicit request and use a new output directory."})
            render(root, base)
            print(json.dumps({"domainStatus": status, "executionState": "NOT_STARTED", "report": str(root / "report.html")}, indent=2))
            return 0
        result = drive(binary, root, request, options.pause_after_input)
    elif options.action == "resume":
        result = drive(binary, root)
    else:
        result = verify(binary, root)
    print(json.dumps({key: value for key, value in result.items() if key in ("runId", "executionState", "domainStatus", "verificationState",
        "executionPerformed", "calculationVerification", "reportIntegrity", "workerStarts", "diagnostic", "cleanup")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
