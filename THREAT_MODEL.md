# GaugeMesh threat model

Status: developer preview, reviewed 2026-08-30.

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

## Deliberate non-claims

GaugeMesh does not claim exactly-once effects, security certification, universal
client compatibility, or protection from a compromised host. A passing
conservation report says that the checked adapter preserved the declared fields;
it is not a proof that an upstream server behaved honestly.
