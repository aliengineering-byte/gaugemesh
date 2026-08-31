# MCP compatibility

GaugeMesh uses the official Rust MCP SDK `rmcp` 3.1.4. The dependency is exact-pinned in
`Cargo.toml`. GaugeMesh is both a downstream-facing MCP server and an upstream-facing MCP client.

| Revision | Lifecycle | stdio client/server | Streamable HTTP client/server | Tools | Resources/templates | Prompts | Cache/result metadata | MRTR |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| 2025-11-25 | `initialize` session | tested | tested | list/call | list/templates/read | list/get | TTL and private scope | SDK relay primitives |
| 2026-07-28 | `server/discover`, self-contained request metadata | tested | tested | list/call | list/templates/read | list/get | TTL, cache scope, result `_meta` | SDK relay primitives |

The 2026 path uses `server/discover` and supplies the protocol version and client capabilities on
each request. The 2025 path uses the legacy initialization session. GaugeMesh does not infer a
stateless request's revision from an earlier request. Its adapter rejects header/body disagreement.
The SDK validates current `MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name`, `_meta`, client/server
identity, capabilities, and response metadata rules.

The transport tests exercise a real RMCP client against GaugeMesh over Tokio duplex, a real TCP
Streamable HTTP listener, and an actual child process over stdio. They enumerate tools, resources,
resource templates, and prompts, and then cancel and join their owned transport.

Limitations for 0.1:

- The official conformance inventory is recorded in `CONFORMANCE.md`; an SDK claim is
  not a GaugeMesh conformance or certification claim.
- Upstream change notifications are represented by immutable capability revision and schema
  snapshots in the federation. Live notification fan-out is not yet implemented.
- Current MRTR wire handling comes from RMCP. Unsupported bridge requests return explicit errors
  in the model-broker layer rather than disappearing.
- `add mcp` performs live reviewed discovery, pins the complete capability-manifest digest, and
  writes configuration. `serve` loads configured sources transactionally into the bounded runtime;
  startup and restart reject identity drift.

## Federation modes

Transparent mode uses stable readable aliases such as `docs-a__search`; policy and leases always
authorize the full capability identity, never the alias. Compressed mode exposes only five fixed
meta-tools: search, describe, lease, invoke, and release. Discovery is deterministic lexical
ranking and does not require an embedding model or LLM. Neither mode is claimed to be universally
better; transparent mode remains the compatibility fallback for clients that do not reliably use
meta-tools.

Resources use `gaugemesh://resource/<source>/<opaque-id>` and retain an internal mapping to the
exact native URI. Composite cursors are HMAC-protected and bounded to 4 KiB. Prompts carry the same
source, schema, revision, and configuration identity as tools and resources.
