# GaugeMesh threat model

Status: developer preview. The 0.1 baseline was reviewed 2026-08-30; the
durable task-routing addendum was reviewed 2026-09-05.

## Assets and boundaries

GaugeMesh protects downstream principal and tenant identity, delegated authority,
capability identity, credentials, request budgets, side-effect constraints, causal
evidence, and configuration integrity. Trust boundaries exist at every MCP or
OpenAI-compatible connection, child-process boundary, registry response, approval
channel, storage file, and reverse proxy.

The base deployment assumes the host account and executable are trusted. Upstream
servers, model providers, registry records, tool content, network responses,
forwarded headers, and client input are untrusted. Local unauthenticated mode is
valid only on loopback. Remote mode requires TLS, explicit origin and issuer data,
audience binding, a trusted-proxy allowlist, and default-deny policy.

## Principal threats and controls

| Threat                                                 | Required control                                          | 0.1 disposition                                                         |
| ------------------------------------------------------ | --------------------------------------------------------- | ----------------------------------------------------------------------- |
| Alias confused with authorization identity             | Authorize only stable `CapabilityId`                      | Implemented in the core                                                 |
| Principal or tenant changed by translation             | Typed context and conservation check                      | Implemented in the core                                                 |
| Scope, deadline, token, money, or retry growth         | Monotonic checks before execution                         | Implemented in the core                                                 |
| Confidential data downgraded                           | Classification may only stay equal or strengthen          | Implemented in the core                                                 |
| Tool/schema changed under a lease                      | Exact schema and manifest digest binding                  | Implemented in the core                                                 |
| One tenant monopolizes work                            | Per-tenant bounded queues and fair scheduling             | Implemented in the core                                                 |
| Circuit flapping                                       | Separate open and recovery thresholds                     | Implemented in the core                                                 |
| Unauthenticated remote exposure                        | Refuse non-loopback local mode                            | Implemented in config validation                                        |
| SSRF to metadata/private networks                      | Canonical URL policy plus DNS/redirect revalidation       | Static URL policy implemented; runtime DNS revalidation is release work |
| Bearer-token passthrough or cross-user token cache     | Separate downstream and upstream credential identities    | Designed; remote auth is release work                                   |
| Side-effect duplication after ambiguous timeout        | No retry without idempotency or compensation proof        | Designed; enforced at broker stage                                      |
| Raw prompt, arguments, results, or credentials in logs | Strict event allowlist                                    | Designed; server tracing is federation work                             |
| Stdio command injection and child leakage              | No shell, exact argv, pool partition key, bounded cleanup | Designed; process pool is federation work                               |
| Registry metadata treated as authority                 | Search, inspect, approve, then add pinned record          | Designed; registry workflow is release work                             |
| Tampered composite cursor or approval                  | Size-bound integrity protection and replay binding        | Designed; federation/release work                                       |

## Durable task-routing addendum

The current source can proxy the MCP Tasks extension only when the downstream
and a reviewed upstream negotiate 2026-07-28 Tasks and GaugeMesh has SQLite
task-route storage. Task execution remains an upstream responsibility.

| Threat | Control | Remaining boundary |
|---|---|---|
| Lost submission acknowledgement or coordinator restart causes a duplicate dispatch | Persist a caller-scoped `prepared` route and a coordinator-owned `dispatching` transition before the upstream call; return the existing public task for an identical idempotency binding | A `dispatching` route owned by a prior instance becomes `reconciliation_required`; GaugeMesh never automatically resubmits and cannot prove whether an unacknowledged external effect occurred |
| Idempotency key is reused for different work | Bind principal, tenant, capability, source snapshot, configuration, task identities, input digest, policy digest, artifact-scope digest, deadline, limits, effect, and cleanup requirement; reject a changed request digest | Idempotency is scoped to one principal and tenant and expires with the route retention window |
| Upstream task identifiers leak or collide across callers | Issue a GaugeMesh public task ID, keep the upstream ID in the caller-scoped route, and translate get and cancel operations | The upstream remains responsible for its native task identifier and task behavior |
| A different upstream, connection session, or changed configuration receives lifecycle traffic | Bind the exact runtime connection session, capability, source configuration digest, and discovered capability-snapshot digest; enter reconciliation instead of rerouting after drift | Reconnection is conservatively treated as loss of task continuity even when a provider persists task state; digests establish equality with reviewed bytes, not trustworthiness or correctness of the upstream implementation |
| A hand-authored source omits its persisted capability pin | Keep ordinary-call compatibility but make the source ineligible for durable Tasks; `add mcp` writes the full manifest pin | The optional field does not authenticate first-start discovery for ordinary calls |
| A provider returns a different task or result | Require an exact echo of the `dev.gaugemesh/taskExecution` binding and the expected upstream task ID; bound and durably cache accepted terminal state | Provider-reported completion is execution evidence, not independent outcome verification |
| Cancellation is lost between persistence and the upstream | Persist `cancel_requested` before sending cancel; retain a nonterminal or reconciliation state until a terminal result is observed | A successful cancel request is not proof that a remote effect stopped or was reversed |
| A provider uses optimistic MCP hints to reduce durable-task authority | Preserve pinned hints only for ordinary-call compatibility; independently require `non_idempotent_write` in the task lease and submission for every external task | The extra grant authorizes routing but does not prove the provider's annotation or implementation is truthful |
| A remote caller expands write authority | Require every selected capability's descriptive effect in the lease and the conservative `non_idempotent_write` ceiling for task submission; remote idempotent and non-idempotent writes require `gaugemesh:effect:idempotent-write` and `gaugemesh:effect:non-idempotent-write` respectively | A scope and lease authorize routing; they do not sandbox or make a worker's write safe |
| An input-response acknowledgement is lost | Refuse `tasks/update` with `GM_TASK_UPDATE_UNSUPPORTED_DURABLE` because this route schema has no persisted update intent and receipt | Providers that require interactive task input are not supported by the durable route |
| A local PROCESS worker escapes its output directory or emits plausible invalid output | Embedded qualification uses a temporary permitted root, rejects absolute/traversal and symlink paths, creates new files, bounds process time and bytes, and verifies result and manifest independently | This is explicit qualification evidence for a harmless worker, not a general OS sandbox, hostile-code boundary, child-tree containment guarantee, or supported production executor |

Task-route records carry an unsigned, recomputable integrity digest. It detects
partial corruption and inconsistent indexed fields, but a process able to
rewrite the database and recompute the record can forge it. Input, schema,
configuration, source-snapshot, policy, and artifact-scope digests are binding
identities only. In particular, GaugeMesh does not evaluate the acceptance
policy or independently inspect artifacts as part of routing.

## Deliberate non-claims

GaugeMesh does not claim exactly-once effects, hostile-process containment,
security certification, universal client compatibility, or protection from a
compromised host. A passing conservation report says that the checked adapter
preserved the declared fields; it is not a proof that an upstream server
behaved honestly. A terminal MCP task state likewise does not establish
independent verification of its claimed outcome.
