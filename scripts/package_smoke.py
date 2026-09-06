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
        timeout=60,
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
        durable = json.loads(run(binary, "verify", "--durable-tasks", cwd=caller))
        expected_result_identity = {
            "schemaVersion": "gaugemesh.durable-tasks-qualification-result/1",
            "status": "PASS",
        }
        for key, expected in expected_result_identity.items():
            if durable.get(key) != expected:
                raise SystemExit(
                    f"durable Tasks result mismatch for {key}: {durable.get(key)!r}"
                )
        evidence = durable.get("evidence", {})
        expected_evidence_identity = {
            "schemaVersion": "gaugemesh.durable-tasks-qualification/1",
            "status": "PASS",
        }
        for key, expected in expected_evidence_identity.items():
            if evidence.get(key) != expected:
                raise SystemExit(
                    f"durable Tasks evidence mismatch for {key}: {evidence.get(key)!r}"
                )
        canonical_evidence = json.dumps(
            evidence, ensure_ascii=False, separators=(",", ":"), sort_keys=True
        ).encode()
        expected_evidence_digest = "sha256:" + hashlib.sha256(canonical_evidence).hexdigest()
        if durable.get("evidenceSha256") != expected_evidence_digest:
            raise SystemExit("durable Tasks evidence digest does not match its JSON payload")
        execution = evidence.get("execution", {})
        required_execution = {
            "upstreamMcpTransport": "stdio",
            "callerRouterHarnessTransport": "in-process-duplex",
            "selfSpawnedUpstreamBinary": True,
            "selfSpawnedWorkerBinary": True,
            "sqliteRouterReopened": True,
            "callerDiscardedAcknowledgement": True,
            "ownedTemporaryWorkspaceRemoved": True,
            "publicTaskIdentityPreserved": True,
            "upstreamSubmissions": 1,
            "workerProcessStarts": 1,
            "workerEffects": 1,
            "duplicateEffects": 0,
            "primaryTerminalStatus": "completed",
        }
        for key, expected in required_execution.items():
            if execution.get(key) != expected:
                raise SystemExit(
                    f"durable Tasks execution mismatch for {key}: {execution.get(key)!r}"
                )
        expected_broker_outcome = {
            "executionState": "upstream_reported",
            "policyAcceptance": "not_evaluated_by_gaugemesh",
            "verificationStatus": "not_performed",
        }
        if execution.get("primaryBrokerOutcome") != expected_broker_outcome:
            raise SystemExit(
                "durable Tasks broker outcome boundary mismatch: "
                f"{execution.get('primaryBrokerOutcome')!r}"
            )
        expected_rejections = {
            "changedInput": {
                "accepted": False,
                "code": "GM_TASK_IDEMPOTENCY_CONFLICT",
            },
            "tasksUpdate": {
                "forwarded": False,
                "code": "GM_TASK_UPDATE_UNSUPPORTED_DURABLE",
            },
        }
        for case, expected in expected_rejections.items():
            if execution.get(case) != expected:
                raise SystemExit(
                    f"durable Tasks rejection mismatch for {case}: {execution.get(case)!r}"
                )
        artifact = evidence.get("artifactVerification", {})
        if artifact.get("validArtifacts") != "VERIFIED":
            raise SystemExit("durable Tasks valid artifacts were not verified")
        for case in ("exitZeroInvalid", "missing", "truncated", "swapped"):
            if artifact.get(case, {}).get("accepted") is not False:
                raise SystemExit(f"durable Tasks verifier accepted {case} artifacts")
        if artifact.get("exitZeroInvalid", {}).get("processExitSuccess") is not True:
            raise SystemExit("invalid-output worker did not exit successfully")
        expected_mutations = {
            "missing": "manifest-removed",
            "truncated": "result-truncated",
            "swapped": "result-swapped",
        }
        for case, mutation in expected_mutations.items():
            result = artifact.get(case, {})
            if result.get("fixtureProcessExitSuccess") is not True:
                raise SystemExit(f"artifact fixture process failed for {case}")
            if result.get("postExecutionMutation") != mutation:
                raise SystemExit(
                    f"artifact mutation mismatch for {case}: "
                    f"{result.get('postExecutionMutation')!r}"
                )
        expected_artifact_codes = {
            "exitZeroInvalid": "NEUTRAL_VERIFY_IDENTITY_OR_CONTENT_MISMATCH",
            "missing": "NEUTRAL_VERIFY_ARTIFACT_MISSING",
            "truncated": "NEUTRAL_VERIFY_RESULT_INVALID",
            "swapped": "NEUTRAL_VERIFY_IDENTITY_OR_CONTENT_MISMATCH",
        }
        for case, expected_code in expected_artifact_codes.items():
            if artifact.get(case, {}).get("code") != expected_code:
                raise SystemExit(
                    f"artifact rejection code mismatch for {case}: "
                    f"{artifact.get(case, {}).get('code')!r}"
                )
        cancellation = evidence.get("cancellation", {})
        required_cancellation = {
            "deadlineEnforcement": "poll-driven",
            "backgroundScheduler": False,
            "pollsBetweenSubmissionAndDeadline": 0,
            "acknowledgementsBeforePoll": 0,
            "terminationsBeforePoll": 0,
            "effectsBeforePoll": 0,
            "triggerPollStatus": "working",
            "triggerPollStatusMessage": "GM_TASK_RUNTIME_BOUND_REACHED",
            "persistedIntentAfterTriggerPoll": "cancel_requested",
            "terminalStatus": "cancelled",
            "effectsAfterTermination": 0,
        }
        for key, expected in required_cancellation.items():
            if cancellation.get(key) != expected:
                raise SystemExit(
                    f"durable Tasks cancellation mismatch for {key}: "
                    f"{cancellation.get(key)!r}"
                )
        if cancellation.get("acknowledgementsAfterPoll", 0) < 1:
            raise SystemExit("durable Tasks cancellation was not acknowledged after polling")
        if cancellation.get("workerTerminationsAfterPoll", 0) < 1:
            raise SystemExit("durable Tasks worker termination was not observed after polling")
        expected_guarantee_boundary = {
            "exactlyOnceClaimed": False,
            "durableTaskUpdateSupported": False,
        }
        if evidence.get("guaranteeBoundary") != expected_guarantee_boundary:
            raise SystemExit(
                "durable Tasks guarantee boundary mismatch: "
                f"{evidence.get('guaranteeBoundary')!r}"
            )
        if sorted(caller.iterdir()) != before:
            raise SystemExit("release binary wrote into the caller directory")

    print(f"PASS {args.archive.name} source={args.source_sha} target={args.target}")


if __name__ == "__main__":
    main()
