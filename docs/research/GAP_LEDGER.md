# Gap ledger

Reviewed 2026-08-30. Status vocabulary is fixed to the requested disposition
set. A test name denotes executable evidence; a document or manual gate is
identified explicitly. “Designed” never means shipped.

| ID | Source | Observed failure mode | GaugeMesh design | Implementation / evidence | Status | Residual risk |
|---:|---|---|---|---|---|---|
| 1 | Gateway survey | Generic positioning has no defensible wedge | Invariant-routing product contract | README and ADR 0001 | FIXED_IN_0_1 | Users may still compare feature breadth rather than guarantees |
| 2 | MCP lifecycle | One-way forwarding cannot represent server requests | Explicit compatibility handlers and MRTR boundary | `outbound::GatewayClient`; legacy sampling returns a stable error | DESIGNED_NOT_IMPLEMENTED | User-configurable MRTR relay policy is not wired |
| 3 | MCP lifecycle | Sampling/elicitation disappears | Decline, explicit unavailable error, or reviewed approval | silent-drop tests plus deny/static/local-CLI/signed-webhook approval backends | FIXED_IN_0_1 | User-configurable sampling relay remains unsupported |
| 4 | Gateway survey | Tools-only aggregation loses protocol surface | Federate tools, resources, templates and prompts | HTTP/stdio integration and official server suites | FIXED_IN_0_1 | Change-notification fan-out is deferred |
| 5 | Aggregators | Native resource URIs collide | Opaque virtual URI mapped to source/native identity | `tool_resource_and_prompt_collisions_remain_distinct` | FIXED_IN_0_1 | Persistent remapping across manual source deletion needs operator care |
| 6 | Aggregators | Prompt names collide | Source-bound prompt identity and readable alias | same collision test | FIXED_IN_0_1 | Client UI may truncate aliases |
| 7 | Authorization | Display name becomes authority | Authorize `CapabilityId` only | `alias_does_not_define_identity` | FIXED_IN_0_1 | External policy authors must use stable IDs |
| 8 | Prefix gateways | Prefix changes authorization meaning | Alias excluded from identity digest | alias/case/Unicode property tests | FIXED_IN_0_1 | Renamed source intentionally changes source identity |
| 9 | Policy engines | A rule reads data unavailable in its phase | Typed field/phase compiler | `body_field_at_discovery_fails_at_compile_time` | FIXED_IN_0_1 | Compiler implements a deliberately small rule language |
| 10 | Local gateways | Process per namespace wastes resources | Security-aware process key independent of namespace | `safe_namespaces_reuse_one_generation`; configured runtime pool | FIXED_IN_0_1 | Upstream process behavior still determines practical sharing efficiency |
| 11 | Process pools | Unsafe cross-user process sharing | Principal/tenant/credential/shareability partitions | process-pool isolation tests | FIXED_IN_0_1 | Upstream server may misdeclare itself shareable |
| 12 | OAuth caches | Token ownership not principal-bound | Cache key includes tenant/principal/upstream/audience/scope/source | typed security design and API-key ownership tests | DESIGNED_NOT_IMPLEMENTED | OAuth token cache/refresh is not shipped |
| 13 | Gateways | Downstream bearer token passed upstream | No passthrough path; distinct credential references | code review and config schema | FIXED_IN_0_1 | Native provider config remains limited |
| 14 | OAuth | Issuer/audience/resource confused | Exact triple validation | OIDC/JWKS listener tests including expiry, not-before, unknown key and rotation | FIXED_IN_0_1 | External authorization-server availability and policy remain external |
| 15 | Proxies | Forwarded headers redefine public origin | Explicit origin and trusted proxy list | remote middleware tests reject forged/untrusted forwarded headers | FIXED_IN_0_1 | Deployment proxy configuration can still be wrong |
| 16 | Security guidance | Metadata/upstream URL SSRF | Canonical URL, DNS class, peer IP and redirect checks | `loopback_metadata_and_cross_origin_redirects_are_denied` | FIXED_IN_0_1 | Filesystem/DNS TOCTOU cannot be eliminated completely |
| 17 | Registries | Discovery mutates execution immediately | Search/inspect/approve/add split | approval digest and tamper tests | FIXED_IN_0_1 | Registry is preview and record format may change |
| 18 | Registries | Search auto-installs unreviewed packages | Only approved HTTPS remote records can be added | `registry approve`; `--from-approved` | FIXED_IN_0_1 | Package/image digest approval is not implemented for command transports |
| 19 | Agents | Huge tool lists consume context | Five fixed lease meta-tools plus transparent mode | RMCP surface tests and demo lease | FIXED_IN_0_1 | No benchmark with weak production models |
| 20 | Agents | Weak models never call tool search | Transparent mode stays available | both surfaces listed in MCP compatibility doc | FIXED_IN_0_1 | Client behavior varies by model |
| 21 | Routers | LLM makes opaque infrastructure choices | Pure fixed-point planner | `reordering_does_not_change_route` | FIXED_IN_0_1 | Health inputs are fixture snapshots in 0.1 |
| 22 | Routers | Tie choice changes by iteration order | Canonical route ID tie break | route metamorphic test | FIXED_IN_0_1 | Cross-architecture CI is required for continuing evidence |
| 23 | Adapters | Translation creates budget | Non-increasing typed conservation | invariant property suite | FIXED_IN_0_1 | Provider usage reports can be incomplete |
| 24 | Adapters | Translation extends deadline | Monotonic deadline check | budget/conservation property suite | FIXED_IN_0_1 | Suspend/resume clock behavior differs by OS |
| 25 | Retries | Nested layers multiply attempts | Retry debit is conserved | `retry_amplification_is_rejected`; bounded route/provider fallback | FIXED_IN_0_1 | Provider-side retries remain outside GaugeMesh visibility |
| 26 | Effects | Ambiguous timeout duplicates writes | No retry without idempotency/compensation proof | read-only ResiliReplay path reports zero duplicates | DESIGNED_NOT_IMPLEMENTED | General write compensation is application-specific |
| 27 | Async I/O | Cancellation stops at one layer | Cancellation tokens and child `kill_on_drop` | HTTP/stdio cleanup integration tests | FIXED_IN_0_1 | Host-level process kill can still prevent graceful cleanup |
| 28 | Load | Queues grow without bound | Per-tenant bounded queues | admission middleware and `one_tenant_cannot_fill_an_unbounded_queue` | FIXED_IN_0_1 | Soak duration and tenant mix are bounded |
| 29 | Breakers | Threshold flapping | Separate open/recovery thresholds | `breaker_has_hysteresis` | FIXED_IN_0_1 | Tunings are static |
| 30 | Federation | One source hides healthy sources | Explicit strict/degraded result model | Core snapshot design | DESIGNED_NOT_IMPLEMENTED | Live aggregate degraded metadata is not wired |
| 31 | Federation | Tool schemas change under leases | Schema digest in identity and manifest | stale-schema lease test and startup capability-snapshot pin | FIXED_IN_0_1 | Intentional refresh requires a new reviewed runtime snapshot |
| 32 | Authorization | Cached decision survives policy change | Policy digest in context/model identity | digest-bound route and identity tests | FIXED_IN_0_1 | No distributed invalidation in single-node preview |
| 33 | Protocols | Revision inferred ambiguously | Explicit revision enum and lifecycle | protocol tests and separate official suites | FIXED_IN_0_1 | Future revisions require new adapter work |
| 34 | MCP 2026 | Routing headers lost | Official SDK emits/validates standard headers | conformance wire-schema inventory | FIXED_IN_0_1 | Proxy behavior outside GaugeMesh is external |
| 35 | MCP 2026 | Result/cache metadata disappears | Explicit result type, TTL and private scope | official 2026 suite: 117/117 scored checks | FIXED_IN_0_1 | Cache storage is SDK-managed/in-memory |
| 36 | MCP | Legacy/current conversions conflict | Separate 2025 initialize and 2026 discover paths | 2025: 70/70; 2026: 117/117 scored server checks | FIXED_IN_0_1 | Exact alpha runner remains required for the 2026 requirement set |
| 37 | MCP | MRTR absent | SDK types and explicit adapter boundary | RMCP 3.1.4 dependency; design docs | DESIGNED_NOT_IMPLEMENTED | No end-user configurable nested request workflow |
| 38 | Transports | No backpressure | Bounded bodies/frames/queues and Tokio flow control | body/queue constants and core tests | FIXED_IN_0_1 | High-load soak not performed |
| 39 | Streaming | SSE buffering grows | Two-event fixture stream and bounded body/output | streaming unit tests | FIXED_IN_0_1 | Provider streaming relay is not implemented |
| 40 | Telemetry | Raw prompt/body logs leak data | No body fields in tracing allowlist | source scan and threat model | FIXED_IN_0_1 | Operators can redirect upstream stderr independently |
| 41 | Metrics | User IDs create unbounded labels | Metrics disabled; documented bounded fields only | source review | DEFERRED_TO_0_2 | Prometheus/OTLP export not shipped |
| 42 | Evidence | Trace is not bound to route/capability | Digest-linked causal parent/child | model tool-loop test and causal graph test | FIXED_IN_0_1 | Cross-service propagation remains cooperative |
| 43 | Reliability | Failure result cannot be replayed | Deterministic fixtures plus external verifier | 13-scenario `gaugemesh verify --resilireplay` matrix | FIXED_IN_0_1 | Aggregate is honestly PARTIAL; ten scenarios do not recover |
| 44 | Deployment | External DB required | Memory default; SQLite WAL optional | storage tests and demo | FIXED_IN_0_1 | SQLite multi-writer throughput is bounded |
| 45 | Deployment | Docker/Kubernetes required | Native binary is primary | binary/package smoke | FIXED_IN_0_1 | Container is still supplied as optional packaging |
| 46 | Deployment | Hidden control plane | No network dependency for demo/runtime fixture | offline demo test | FIXED_IN_0_1 | Registry/model discovery naturally requires configured networks |
| 47 | Packaging | No clean install path | Release archives, checksums, SBOM and container workflow | release workflow/package smoke | FIXED_IN_0_1 | Artifacts exist only after the release workflow completes |
| 48 | Marketing | “All agents” claim lacks evidence | Evidence-level compatibility table | README/compatibility docs | FIXED_IN_0_1 | Client matrix is intentionally small |
| 49 | Registry | Gateway creates a rival marketplace | Read official/subregistry metadata only | official v0.1 API client | FIXED_IN_0_1 | Search is intentionally basic |
| 50 | Routing | No reproducible explanation | Scores, rejections and snapshot digest | `gaugemesh route explain` and deterministic tests | FIXED_IN_0_1 | Live metric capture is not in the preview |
