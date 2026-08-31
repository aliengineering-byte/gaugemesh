# Clean-room competitive observations

Observed 2026-08-30 from public documentation, repositories, issue trackers, and
release notes. This is a behavior survey, not a security audit. No competitor
source, configuration schema, prose, or UI was copied into GaugeMesh.

| Project | Observed behavior and deployment | MCP/model surface | Gap that informed GaugeMesh |
|---|---|---|---|
| [agentgateway](https://github.com/agentgateway/agentgateway) | Active Apache-2.0 Rust/Go gateway; standalone and Kubernetes paths; broad auth, CEL, telemetry, guardrails, A2A, and UI scope | MCP federation plus OpenAI-compatible and native provider routing | A mature broad gateway already exists. GaugeMesh must stay narrow: typed conservation, leases, and deterministic infrastructure routing. |
| [LiteLLM](https://docs.litellm.ai/) | Active Python proxy/SDK with a database-backed management path, virtual keys, spend tracking, callbacks, and a very broad provider matrix | Strong OpenAI-compatible model surface; MCP gateway features are secondary to the model proxy | Do not compete on provider count. Bind configured cost-table versions and distinguish estimated from observed cost. |
| [Docker MCP Gateway/Toolkit](https://docs.docker.com/ai/mcp-catalog-and-toolkit/mcp-gateway/) | Active Go gateway and Docker Desktop toolkit; catalog, profiles, secrets, container isolation, lifecycle management | MCP stdio and streaming transports; model routing is not its primary contract | Keep Docker optional, preserve exact capability identity independent of profile/display name, and provide a native one-binary path. |
| [Cloudflare MCP Server Portals](https://developers.cloudflare.com/cloudflare-one/access-controls/ai-controls/mcp-portals/) | Managed Cloudflare Access product; one HTTP portal for multiple remote servers and OAuth-backed policy | Stateless 2026-07-28 and earlier Streamable HTTP; remote HTTP servers rather than local stdio | Provide a local/self-hosted complement and never infer origin or trust forwarded headers. |
| [Amazon Bedrock AgentCore Gateway](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway.html) | Managed AWS gateway converting APIs/Lambda/services to tools, with ingress and egress authentication | Documents 2026-07-28, 2025-11-25, 2025-06-18, and 2025-03-26; also agent and model traffic | Avoid a hidden hosted control plane; make revision identity and translation loss explicit. |
| [IBM ContextForge](https://github.com/IBM/mcp-context-forge) | Active Apache-2.0 Python platform with registry, proxy, UI, plugins, REST/gRPC, A2A, Docker/Kubernetes and optional Redis federation | MCP plus agent/API gateway features and broad observability | Do not reproduce an all-in-one control plane. Keep the base runtime memory/SQLite-only and the policy language typed and small. |
| [MetaMCP](https://github.com/metatool-ai/metamcp) | MIT TypeScript MCP aggregator/middleware with UI and Docker-oriented deployment; maintenance notes point to a community fork | Aggregates stdio/SSE/Streamable HTTP and exposes selected or compact tools | Capability aliases and meta-tools must never become authorization identities; weak-client transparent mode remains necessary. |
| [Microsoft MCP Gateway](https://github.com/microsoft/mcp-gateway) | MIT C# reverse proxy and management plane oriented around Kubernetes/Azure, session affinity, lifecycle and telemetry | Streamable HTTP MCP routing and managed adapters | A local binary should not require Kubernetes, and process reuse must partition on credentials/principal rather than namespace. |
| [mcp-gateway fixed meta-surface](https://docs.rs/crate/mcp-gateway/latest/source/README.md) | Rust gateway exposing a compact search/describe/invoke-style surface to reduce context use | Fixed meta-tools over many backends | Lease mode is useful but models may fail to invoke discovery; retain directly exposed, reviewed aliases as an explicit alternative. |
| [Official MCP Registry](https://github.com/modelcontextprotocol/registry/blob/main/docs/reference/api/official-registry-api.md) | Preview official metadata service and a generic subregistry API; simple official search intentionally leaves richer search to subregistries | Discovery metadata, packages and remotes; not execution authority | Consume it through search/inspect/approve; never create a marketplace or execute mutable metadata automatically. |
| [Official MCP conformance framework](https://github.com/modelcontextprotocol/conformance) | Captures wire traffic, runs behavioral scenarios, validates revision JSON schemas, and treats baselined failures as failures | Separate client/server roles and requirement sets; active/draft/pending suites | Record package version, revision, role, scenarios and check inventory separately; never call this certification. |

## SDK and specification baseline

GaugeMesh exact-pins `rmcp` 3.1.4 from the official Tier-2 Rust SDK. The SDK
documents both 2025-11-25 and 2026-07-28, including stateless discovery,
standard routing headers, response cache hints and MRTR types. The TypeScript
and Python SDKs are Tier 1 references, not runtime dependencies. The 2026
specification changed lifecycle, routing headers, caching, authorization and
server-to-client request behavior, so the two revisions are tested and reported
separately.

## Independent wedge

The survey rejects “all-in-one AI gateway” positioning. GaugeMesh's independent
requirements are: stable authorization identity through representation changes;
machine-readable conservation reports; monotonically shrinking authority,
budgets and deadlines; bounded task leases; explicit handling of model and
elicitation requests; and deterministic fixed-point route explanations. These
requirements were derived from public behavior and failure classes, then
implemented with original Rust types and tests.

## Research limitations

Public documentation can lag deployed products, managed services cannot be
inspected internally, and release activity changes after the observation date.
Absence of a documented feature is not proof that a project lacks it. The table
does not rank overall product quality and makes no vulnerability claim.
