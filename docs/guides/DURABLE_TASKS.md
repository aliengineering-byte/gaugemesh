# Durable MCP Tasks routing

Status: bounded infrastructure in current source. This is a routing and
recovery contract, not a scheduler or general job-execution platform.

## Problem and qualification quickstart

This route is for an MCP caller that needs to submit one bounded operation,
survive a lost response or local coordinator restart, and recover the same
logical task without silently issuing a second upstream operation.

From a source checkout with Rust 1.88 or newer, run the domain-neutral path:

```console
cargo test --locked -p gaugemesh outbound::tests::neutral_process_task_survives_lost_ack_and_router_restart_without_duplicate_effects -- --exact --nocapture
```

The named test reports one pass and the Cargo command exits zero. The test
starts a real local worker process, reopens SQLite, and independently checks its temporary result and
manifest. It also expects explicit refusals for changed-input key reuse,
unsupported schema/provider versions, missing capability/lease authority,
effect mismatch, traversal/symlink output paths, and an exit-zero worker with
invalid output. A failure is a nonzero Cargo exit; it is not converted into a
green report. The worker and artifacts are synthetic test fixtures, not a
production executor.

The caller obtains a lease containing the selected capability's descriptive
effect plus the conservative task ceiling, submits through `gaugemesh_submit`,
and then uses standard MCP `tasks/get` or `tasks/cancel` with the returned
GaugeMesh public task ID. `tasks/update` is a documented refusal in this bounded
route. File a reproducible
bug through the repository's existing issue tracker; no task telemetry is sent
to project maintainers or another remote service by this route.

## Availability and negotiation

GaugeMesh advertises the MCP `io.modelcontextprotocol/tasks` extension only
when runtime state uses SQLite and at least one reviewed, capability-pinned
upstream negotiated 2026-07-28 and advertised Tasks. A source whose optional
persisted capability digest is absent remains available to compatible ordinary
calls but is ineligible for durable task routing because its first-start view
was not owner-pinned. A downstream caller can use the route only
when both of these conditions also hold:

- the downstream revision is 2026-07-28 and the caller declares Tasks support;
- `providerInterfaceVersion` exactly equals the selected capability's advertised
  schema digest, binding the caller to the discovered worker interface.

The extension is removed from 2025-11-25 initialization responses. Ordinary
tool calls do not gain task capability implicitly. A client uses the
`gaugemesh_submit` meta-tool after obtaining an exact capability lease, and the
selected upstream must itself support Tasks.

`gaugemesh init` writes a memory runtime, which deliberately cannot advertise
durable Tasks. Change that generated configuration to a durable database before
starting the server:

```yaml
runtime:
  mode: sqlite
  database: /absolute/path/to/gaugemesh-state.sqlite3
```

Call `gaugemesh_describe` for the selected alias and copy its `schemaDigest`
value exactly into `providerInterfaceVersion`.

## Submission binding

`gaugemesh_submit` accepts `gaugemesh.task-submission/1`. The submission names a
logical task, attempt, correlation, caller idempotency key, canonical input
digest, acceptance-policy digest, artifact-scope digest, provider interface
version, absolute deadline, retention, resource limits, permitted effect, and
required cleanup. The provider interface version is the exact selected
capability schema digest; it is not the MCP protocol revision.

GaugeMesh checks the input digest against the actual tool arguments and binds
the submission to the exact capability, schema, source configuration, and
discovered source snapshot. It persists the binding and its digest before
contacting the upstream. Raw tool arguments are not stored in the route record.
The policy and artifact-scope digests are caller-supplied identities: the router
does not evaluate the policy or verify artifacts.

The persisted and returned submission binding includes the logical-task,
attempt, correlation, and idempotency identifiers, and it is sent to the
selected upstream in the execution envelope. Do not put secrets in these
identifiers. Protect the SQLite database, logs, traces, and upstream as data
that can contain task metadata and a bounded terminal payload.

Idempotency is scoped to the authenticated principal and tenant. Reusing the
same key and immutable request binding during retention returns the existing
public task. Reusing it with changed input or any other changed binding fails
with `GM_TASK_IDEMPOTENCY_CONFLICT`. A task belonging to another caller is
indistinguishable from an unknown task.

Lease expiry is evaluated as an absolute Unix-millisecond deadline so a stored
lease cannot gain life when the process restarts. The public field name is
retained for source and serialized-shape compatibility, but a legacy lease
whose manifest bound the former monotonic-time key fails closed and must be
reissued.

## Route state and identifiers

GaugeMesh issues a public task ID and keeps the provider's upstream task ID
inside the durable, caller-scoped record. Downstream get and cancel requests
use only the public ID. `tasks/update` is explicitly refused with
`GM_TASK_UPDATE_UNSUPPORTED_DURABLE`: this route schema does not persist an
input-response update intent and receipt, so it cannot safely distinguish an
unsent update from a lost acknowledgement.

| Durable phase | Meaning |
|---|---|
| `prepared` | Submission is durable; no upstream task ID has been accepted. |
| `dispatching` | Dispatch ownership was persisted for one coordinator instance; a different instance treats it as ambiguous after restart. |
| `routed` | One upstream task ID is bound write-once to the route. |
| `cancel_requested` | Cancellation intent was persisted before the upstream cancel request. |
| `reconciliation_required` | Execution outcome is unknown; poll when an upstream ID is known, but never resubmit automatically. |
| `terminal` | A bounded provider result or explicit broker rejection is cached durably. |

Each route is also integrity-bound to the exact upstream runtime connection
session used for dispatch. A reconnect or full GaugeMesh process restart creates
a new session and makes an old nonterminal route reconciliation-only; GaugeMesh
will not send its upstream task ID to the new session. The qualification below
restarts the SQLite-backed task router while deliberately retaining the same
live upstream runtime session. It does not claim transparent recovery across a
gateway or provider reconnect.

The only downstream request metadata preserved for the upstream is the
`dev.gaugemesh/taskExecution` envelope. GaugeMesh constructs its own upstream
client-capability metadata, including Tasks for this path. The provider must
echo the exact public ID, request digest, and submission binding.
A different task ID, missing echo, source/configuration drift, timeout,
transport error, or unexpected response enters reconciliation instead of being
reported as success. A known upstream ID can be polled after restart; an
unknown upstream ID stays explicitly unknown. No ambiguous request is
automatically submitted again.

Cancellation is also conservative. Intent is durable before forwarding. A
failed or ambiguous cancel remains `cancel_requested` and is reported as
requiring reconciliation; a later caller poll makes one bounded retry. A cancel
acknowledgement is not evidence that an external effect was prevented or
reversed.

## Bounds and authority

Admission requires exactly one attempt and `cleanupRequired: true`. Task input
and accepted task output are each limited to 64 KiB; declared runtime is at
most 30 seconds, declared artifacts at most 8 MiB, and retention at most one
hour. The deadline must be future, inside retention, and no later than one hour
from admission. Initial dispatch and caller-driven lifecycle requests are time
bounded. GaugeMesh is not an autonomous scheduler or worker watchdog: after an
upstream task acknowledgement, a remote worker must enforce its declared
runtime, artifact, and cleanup limits, and GaugeMesh sends deadline cancellation
only when a caller later polls. Expired routes are not readable. Submission
opportunistically removes at most 128 expired records, oldest first; retention
is an API/idempotency lifetime, not a promise of immediate physical deletion
when no later submissions occur. Storage admits at most 4,096 route records in
total and 256 unexpired routes per caller; further submissions fail closed with
`GM_TASK_ROUTE_CAPACITY` until bounded cleanup or expiry makes capacity
available.

The artifact byte limit and cleanup flag are part of the worker contract. A
remote worker must enforce them; GaugeMesh cannot inspect or contain its
filesystem through MCP.

A lease must include the descriptive effects of its selected capabilities.
For durable submission it must additionally include
`non_idempotent_write`, and `permittedEffect` must equal that conservative
class regardless of provider-supplied MCP annotation hints. For a remote
authenticated caller, idempotent writes require
`gaugemesh:effect:idempotent-write`, and non-idempotent writes require
`gaugemesh:effect:non-idempotent-write`. `permittedEffect` must equal the
task route's conservative effect. These checks constrain routing authority;
they do not make an upstream worker safe or an operation transactional.

## Neutral qualification

The task qualification is domain-independent and test-only. A real child
process validates and canonically normalizes a small JSON object, writes a
deterministic result and manifest below a temporary permitted output root, and
is checked by a separate verifier. The qualification covers:

- a simulated lost acknowledgement, SQLite router restart, reconciliation by
  the same idempotency key and public ID while retaining the live upstream
  session, and one observed worker effect;
- changed-input idempotency conflict plus schema, lease, capability, and effect
  refusal paths;
- bounded process execution and artifacts, traversal refusal, Unix symlink
  refusal, and cleanup of owned resources; and
- rejection by the independent verifier when a worker exits zero but changes a
  bound identity in its output.

This proves the tested infrastructure behavior for a harmless fixture. The
worker is not a shipped execution service, and the test is not evidence of
general hostile-process containment, a production-duration scheduler, or an
independently verified outcome from arbitrary providers.

## Deliberate non-claims

GaugeMesh does not claim exactly-once external effects. Persist-before-dispatch
and caller idempotency prevent GaugeMesh from automatically duplicating an
ambiguous submission, but they cannot establish what an upstream did before a
lost response. Provider completion is kept separate from policy acceptance,
transaction outcome, and independent verification in route metadata. Record
and binding digests are unsigned equality/integrity checks, not authentication
against a writer able to replace and re-digest state.
