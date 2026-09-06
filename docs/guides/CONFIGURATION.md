# Configuration version 1

`schemas/gaugemesh-config-v1.schema.json` is generated from the Rust types and
checked byte-for-value in the test suite. Execution-affecting structures reject
unknown fields.

Version 1 has no predecessor and therefore no automatic migration. A future
version must keep the original file, validate the complete target document
before replacement, and reject security-sensitive fields it cannot represent.
GaugeMesh never treats an unknown version as the newest known version.

Credentials are references, not inline values. `credential_env` contains an
environment-variable name. Ordinary SQLite records do not store its value.

Local unauthenticated mode binds loopback only. Remote mode is operational but
intentionally strict: it requires PEM TLS certificate/key paths, an explicit
HTTPS public origin, OIDC issuer/JWKS URL, exact audience and resource values,
required scopes, bounded clock skew/JWKS cache TTL, a trusted-proxy allowlist,
and a non-empty default-deny policy. Startup fails closed if any boundary cannot
be loaded. The `0.1.0` listener is an OAuth resource server; it does not implement
an authorization server or an API-key administration endpoint.

Configured MCP sources are discovered before serving and loaded into a bounded,
security-partitioned runtime. `gaugemesh add mcp` writes a capability-manifest
pin. A compatible hand-authored source may omit that optional pin for ordinary
calls, but is then ineligible for durable Tasks because its first-start view is
not owner-pinned. Discovery page, item, cursor, and aggregate-byte limits fail
closed before a source enters the runtime. Provider annotations retain their existing descriptive classification
for ordinary-call compatibility, but they cannot reduce durable-task authority:
every configured external task requires an explicit `non_idempotent_write`
lease grant and matching submission effect. Durable task admission also requires
`providerInterfaceVersion` to equal the selected capability's schema digest,
which binds the discovered worker interface without conflating it with the MCP
revision. Configured model routes are likewise loaded into the broker after
URL, cost-table, context, token, credential-reference, and policy validation.
