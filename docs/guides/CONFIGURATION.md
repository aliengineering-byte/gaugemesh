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
security-partitioned runtime. Their capability snapshot and schema digests are
pinned. Configured model routes are likewise loaded into the broker after URL,
cost-table, context, token, credential-reference, and policy validation.
