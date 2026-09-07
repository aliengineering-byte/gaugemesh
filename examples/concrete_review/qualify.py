"""External consumer acceptance with an installed public binary; no Rust or database access."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "public_tasks"))
from consumer import read_events
from mechanics import strict_json
from reporting import exclusive_json


def qualify(binary, root):
    root.mkdir(parents=True, exist_ok=False)
    source = Path(__file__).with_name("review.py")
    original = strict_json(Path(__file__).with_name("educational.json").read_text())
    def invoke(name, action, args=(), ok=True):
        command = [sys.executable, str(source), action, "--binary", binary, *args]
        result = subprocess.run(command, capture_output=True, text=True)
        exclusive_json(root / (name + "-command.json"), {"command": command, "exitCode": result.returncode, "stdout": result.stdout, "stderr": result.stderr})
        assert (result.returncode == 0) == ok, result.stderr
        return json.loads(result.stdout) if ok else result.stderr
    def run(name, request, pause=False, accepted=True):
        path, output = root / (name + "-request.json"), root / name
        exclusive_json(path, request)
        args = ["--request", str(path), "--output", str(output)]
        if accepted: args.append("--accept-assumptions")
        if pause: args.append("--pause-after-input")
        result = invoke(name, "run", args)
        return output, result
    results = {}
    full, result = run("full", original)
    assert result["executionState"] == "verified" and result["verificationState"] == "VERIFIED" and result["workerStarts"] == 4
    report = strict_json((full / "report.json").read_text())
    assert abs(report["calculation"]["modelMoment_Nmm"] - 320000000) < 0.01
    assert report["syntheticRule"]["label"] == "SYNTHETIC"
    assert report["sourceStatus"] == "SOURCE_AUTHORIZATION_REQUIRED"
    assert report["coverage"]["shear"] == "NOT_EVALUATED" and report["coverage"]["code_compliance"] == "NOT_EVALUATED"
    before = read_events(full / "worker")
    invoke("full-offline", "verify", ["--output", str(full)])
    invoke("full-repeated-resume", "resume", ["--output", str(full)])
    assert read_events(full / "worker") == before, "Offline/repeated completion launched a provider or worker"
    results["publicFourStep"] = {"status": "PASS", "starts": 4, "effects": len([item for item in before if item["kind"] == "worker-effect"]), "runId": result["runId"]}
    paused, initial = run("interrupted", original, pause=True)
    assert initial["executionState"] == "PAUSED"
    input_bytes = (paused / "worker" / "input.json").read_bytes()
    started = [item for item in read_events(paused / "worker") if item["kind"] == "worker-start"]
    assert len(started) == 1 and started[0]["stage"] == "input"
    resumed = invoke("interrupted-resume", "resume", ["--output", str(paused)])
    assert resumed["runId"] == initial["runId"] and resumed["workerStarts"] == 4 and resumed["verificationState"] == "VERIFIED"
    assert (paused / "worker" / "input.json").read_bytes() == input_bytes
    assert len([item for item in read_events(paused / "worker") if item["kind"] == "worker-start" and item["stage"] == "input"]) == 1
    results["realGatewayInterruptionResume"] = {"status": "PASS", "runId": initial["runId"], "totalStarts": 4, "inputStarts": 1, "acceptedArtifactUnchanged": True}
    value = copy.deepcopy(original)
    value["solver"]["maxIterations"] = 1
    stopped, result = run("nonconvergence", value)
    assert result["executionState"] == "verified" and result["verificationState"] == "NOT_EVALUATED" and result["domainStatus"] == "HUMAN_REVIEW_REQUIRED"
    assert "NONCONVERGENCE" in result["diagnostic"]
    invoke("nonconvergence-offline", "verify", ["--output", str(stopped)])
    results["validRunCannotConclude"] = {"status": "PASS", "numericalVerification": "NOT_EVALUATED", "reason": "NONCONVERGENCE"}
    refusals = {}
    for name, expected in (("missing", "NEEDS_INPUT"), ("rights", "SOURCE_AUTHORIZATION_REQUIRED"), ("edition", "OUT_OF_SCOPE"), ("axial", "OUT_OF_SCOPE"), ("no-approval", "NEEDS_INPUT")):
        value = copy.deepcopy(original)
        if name == "missing": del value["geometry"]["height"]
        if name == "rights":
            value["mode"] = "AUTHORIZED_RULE_CHECKS"
            value["rules"]["standard"] = "ACI CODE-318-25"
        if name == "edition": value["rules"]["standard"] = "ACI CODE-318-2099"
        if name == "axial": value["scope"]["axialForce"]["value"] = "1"
        output, result = run(name, value, accepted=name != "no-approval")
        assert result["domainStatus"] == expected and result["executionState"] == "NOT_STARTED"
        assert not (output / "worker").exists()
        refusals[name] = expected
    results["preExecutionRefusals"] = {"status": "PASS", "newWorkers": 0, "cases": refusals}
    value = copy.deepcopy(original)
    value["profile"]["confirmationSource"] = '<script>alert("inert data")</script> ```'
    escaped, _ = run("escaped-report", value)
    html = (escaped / "report.html").read_text()
    assert "<script>" not in html and "&lt;script&gt;" in html
    assert '<script src=' not in html and '@import' not in html and '<link' not in html
    results["offlineReportEscaping"] = {"status": "PASS", "networkResources": 0}
    negative = {}
    originals = {name: (full / name).read_bytes() for name in ("worker/calculate.json", "report.json", "report.html", "report-manifest.json", "frozen.json")}
    try:
        for mode in ("artifact", "report_values_with_rehashed_manifest", "report_command_with_rehashed_manifest", "html_with_rehashed_manifest", "frozen_input"):
            for name, raw in originals.items(): (full / name).write_bytes(raw)
            if mode == "artifact":
                (full / "worker/calculate.json").write_bytes(b"{}")
            if mode.startswith("report_values"):
                changed = json.loads(originals["report.json"])
                changed["calculation"]["modelMoment_Nmm"] = 1
                (full / "report.json").write_text(json.dumps(changed))
            if mode.startswith("report_command"):
                changed = json.loads(originals["report.json"])
                changed["verificationCommand"] = "untrusted altered command"
                (full / "report.json").write_text(json.dumps(changed))
            if mode.startswith("html"):
                (full / "report.html").write_text("<h1>Unverified altered result</h1>")
            if "manifest" in mode:
                changed = json.loads(originals["report-manifest.json"])
                for name in changed["files"]: changed["files"][name] = hashlib.sha256((full / name).read_bytes()).hexdigest()
                (full / "report-manifest.json").write_text(json.dumps(changed))
            if mode == "frozen_input":
                changed = json.loads(originals["frozen.json"])
                changed["request"]["demand"]["moment"]["value"] = "1"
                (full / "frozen.json").write_text(json.dumps(changed))
            negative[mode] = invoke("reject-" + mode, "verify", ["--output", str(full)], ok=False)
    finally:
        for name, raw in originals.items(): (full / name).write_bytes(raw)
    invoke("restored-offline", "verify", ["--output", str(full)])
    results["tamperRefusals"] = {"status": "PASS", "cases": list(negative), "originalsRestored": True}
    results["binarySha256"] = hashlib.sha256(Path(binary).read_bytes()).hexdigest()
    results["status"] = "PASS"
    exclusive_json(root / "result.json", results)
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--output", required=True, type=Path)
    options = parser.parse_args()
    print(json.dumps(qualify(str(Path(options.binary).resolve()), options.output.absolute()), indent=2))
