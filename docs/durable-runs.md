# Bounded durable Runs

This source tree adds an application-level Run to GaugeMesh's existing durable
Tasks. A Run is an immutable, caller-authored DAG, not an agent planner or a
background job service. Work still enters the existing Task submission route.

## Public interface

Connect to `gaugemesh mcp-stdio --config gateway.yaml` with MCP 2026-07-28 and
the Tasks extension. Configure SQLite and a reviewed, pinned Task-capable
provider using the existing `init` and `add mcp` commands. `tools/list` exposes
`gaugemesh_run` only when this runtime is available. Every request must carry
the protocol/client metadata required by that MCP revision.

Call `tools/call` with name `gaugemesh_run` and these arguments:

| action | arguments | behavior |
| --- | --- | --- |
| submit | plan, leaseId | Validate the whole immutable plan and persist acceptance; no dispatch. |
| status | runId | Read the durable snapshot; no poll, dispatch, or deadline enforcement. |
| resume | runId, leaseId | One bounded driver sweep: recover, poll, verify, or dispatch ready steps. |
| cancel | runId | Persist cancellation intent; a later resume drives cancellation and observation. |
| export | runId | Return the versioned plan, states, and integrity journal as JSON. |
| verify | runId | Recheck journal, plan bindings and accepted files without executing work. |

Save the export with the caller's normal exclusive-file output handling, then
verify without starting the gateway or any provider:

```sh
gaugemesh run-verify --evidence run-export.json
```

The verifier never executes embedded commands. Exports contain input/output
evidence: treat them according to the sensitivity of your own data. Integrity
hashes are recomputable, not signatures or proof of provenance. Retain a trusted
original export. Offline verification uses the absolute artifact root bound by
the plan and does not silently relocate or rewrite it.

## Plan contract

`gaugemesh.run-plan/1` binds `runKey`, `deadlineUnixMs`, `artifactRoot`, all steps,
`maxConcurrency` (1–4), `maxAttempts` (exactly 1), and these supported policies:

- `failurePolicy: fail_fast_account_inflight`
- `uncertaintyPolicy: stop_no_replay`
- `cancellationPolicy: intent_then_poll`

A plan has 1–16 steps, at most eight incoming/outgoing edges per step, an absolute
deadline within one hour of acceptance, and at most 256 KiB of plan JSON.
The same local-caller run key and canonical plan return the same public Run ID;
changed plans conflict. Retained Run identities do not expire implicitly. The
existing database has a fixed capacity of 128 Run records; exhaustion refuses
new Runs rather than silently removing evidence.

Each step binds `id`, `dependsOn`, `alias`, the described `capabilityId` and
`providerInterfaceVersion` (schema digest), `arguments`, `inputsSha256`,
`policy`, `policySha256`, `permittedEffect`, `maxRuntimeMs`, and
`maxArtifactBytes`. Step IDs are bounded to 64 ASCII identifier characters.
All external Tasks conservatively require `non_idempotent_write` authority.
Runtime is bounded to 30 seconds per step, resolved input to 8 KiB, Task output
to 32 KiB, and artifact reads to 1 MiB. These small aggregate limits leave room
for the plan, inputs, duplicated verification evidence, and journal within the
2-MiB snapshot bound. The journal allows at most 512 atomic state transitions.

Arguments use explicit forms, without defaults or interpolation:

```json
{
  "value": {"kind": "literal", "value": 7},
  "other": {"kind": "predecessor", "step": "first", "pointer": "/normalized"}
}
```

A reference must name a direct predecessor and an exact required policy check
in that predecessor. Its declared expected value is checked against the target
input schema before acceptance, and the actual verified value is checked again
before dispatch. References to binding/descriptor metadata are unsupported.

The policy version is `gaugemesh.json-artifact-policy/1`, with 1–16
`{pointer, expected, required}` checks. At least one check must be required.
Required failures block successors; optional failures remain visible without
changing required acceptance. Digests use SHA-256 of compact recursively
key-sorted JSON, encoded as `sha256:` followed by lowercase hexadecimal.

Admission supports a deliberately bounded JSON Schema subset: explicit object,
array, string, boolean, integer, number or null types; closed object properties;
required fields; items; enum/const; numeric minimum/maximum; and string/array
length bounds. Unknown schema validation keywords fail closed. Schemas must
use JSON Schema 2020-12 when an explicit dialect is provided; unknown dialects
and malformed keyword values are refused, including unused properties. Numeric
inputs are limited to finite safe-range values. No arbitrary executable validator,
dynamic graph, implicit retry, rollback or compensation is accepted.

## Worker and verification contract

Use the existing `gaugemesh.task-submission/1` and exact
`dev.gaugemesh/taskExecution` acknowledgement contract. A completed tool result's
`structuredContent` contains its JSON output, `binding` equal to that execution
envelope, and `artifact: {path, sha256}`. The path is relative to the explicitly
permitted root. The artifact JSON must equal structured content with only the
descriptor removed. The worker must create its own output exclusively and
respect the declared bounds and cleanup contract; this example is not an OS
sandbox for an untrusted worker.

GaugeMesh reads regular files using descriptor-relative, no-symlink traversal,
including root ancestors. It verifies bytes, task/attempt/input/provider/policy
bindings, and required content checks before recording a step as verified.
Every resume reverifies accepted predecessor files. No exit-zero result alone
is accepted. Missing, truncated, substituted, stale or modified files fail.

## Recovery and authority boundaries

The supported Run surface is local, single-process driving with SQLite CAS
fencing stale snapshots. Unix artifact verification is implemented; Windows
Runs refuse with `GM_RUN_PLATFORM_UNSUPPORTED`. Remote Runs currently refuse
with `GM_RUN_REMOTE_NOT_QUALIFIED`. Local stdio/loopback uses one fixed caller
identity; it is not a test of two authenticated remote principals. Existing
remote Tasks keep their OIDC/lease boundaries; remote identities cannot claim
the reserved local tuple, and current token effect scopes are rechecked.

Run state and journal advance atomically. A persisted submitting step reuses its
stable Task key if acknowledgement is lost. Accepted predecessors are never
rerun. After an upstream session changes, old private Task IDs are not forwarded;
an ambiguous effect remains reconciliation-required, not fabricated success or
an automatic retry. An expired retained Task can be recovered read-only, while
a never-accepted expired request cannot start work.

The driver checks current leases before new dispatch. Revoking or expiring a
lease blocks new work, not already-started effects. Owner cancellation can still
be requested without a live execution lease. Ordinary resume currently requires
a live lease even when it only polls existing work; cancel followed by resume
allows cancellation accounting without that execution grant. Cancellation intent, a returned
cancellation call, the broker's acknowledgement, and an upstream-reported
terminal state are distinct. None independently proves prevention or reversal
of a side effect. There is no autonomous watchdog: without resume/poll activity,
Run deadlines do not terminate workers. Fail-fast stops unsent steps while
continuing to account for existing in-flight work.

## External qualification

Use the scripts from the exact public source tag with an installed binary; no
Rust toolchain, internal import, SQLite write, or private dispatch command is
needed. Output directories must be new and on a drive with sufficient space.

```sh
python examples/public_tasks/consumer.py --binary /absolute/path/gaugemesh --output /new/tasks-evidence --require-late-recovery
python examples/public_tasks/run_consumer.py --binary /absolute/path/gaugemesh --output /new/run-evidence
node examples/public_tasks/second_consumer.mjs /absolute/path/gaugemesh /new/javascript-evidence
```

These original synthetic fixtures retain raw JSON-RPC, a genuinely withheld
acknowledgement, process restart/kill observations, independent worker-start and
effect records, artifacts, and offline exports. Python and JavaScript callers
and workers use only their respective standard libraries. No paid model or
domain asset is involved. Source-built checks are not evidence of public
delivery: the release gate reruns them against a freshly downloaded, attested,
checksummed public archive and uploads their raw evidence.

The historical ResiliReplay 0.7.0 result stays separate: **3 PASS / 10 FAIL / 13,
PARTIAL**. Its post-response trace mutations are not live-wire recovery proof.
Neither suite is a benchmark, safety certification, or exactly-once guarantee.
