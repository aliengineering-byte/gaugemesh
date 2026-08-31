# MCP conformance inventory

Observed 2026-08-30 against the local GaugeMesh 0.1.0 hardening candidate. The
runner was `@modelcontextprotocol/conformance@0.2.0-alpha.11`, published from
`modelcontextprotocol/conformance` commit
`c321dd32035556e6769d3724a8ee97d87c3faaac`. Both the package and repository
identity are pinned in the evidence. No expected-failure baseline was used.

| Revision | Role | Transport | Exact inventory | Scored result | Unscored visibility result |
|---|---|---|---|---|---|
| 2025-11-25 | downstream server | Streamable HTTP | 33 scenarios | 30 scenarios, 70/70 checks passed | 3 added/pending scenarios: 6 passed checks, 1 failed pending check |
| 2026-07-28 | downstream server | Streamable HTTP | 50 scenarios | 37 scenarios, 117/117 checks passed | 13 extension/pending scenarios: 28 passed checks, 36 failed checks |

Commands:

```sh
GAUGEMESH_CONFORMANCE_FIXTURE=1 gaugemesh serve \
  --data-address 127.0.0.1:18101 --admin-address 127.0.0.1:18103

npx -y @modelcontextprotocol/conformance@0.2.0-alpha.11 server \
  --url http://127.0.0.1:18101/mcp \
  --requirements 2025-11-25 --output-dir conformance-2025

npx -y @modelcontextprotocol/conformance@0.2.0-alpha.11 server \
  --url http://127.0.0.1:18101/mcp \
  --requirements 2026-07-28 --output-dir conformance-2026
```

The fixture environment exposes only the runner's documented synthetic tools,
resources, prompts, legacy logging, sampling, elicitation, progress, MRTR, and
subscription behavior. MRTR request state is integrity protected and input
requests are filtered against the client's declared capabilities. These
deprecated, interactive, and diagnostic fixtures are not enabled in normal
operation. Every scenario also includes the runner's instrumented wire-schema
check where applicable.

The official framework currently provides richer direct server coverage than a
ready-made GaugeMesh client target. Upstream-facing client behavior is therefore
covered by real RMCP HTTP and stdio integration tests for both revisions, not
reported as an official client-suite pass. Uninstrumented network/DNS behavior
and configured live pooling remain outside these counts.

The unscored failures are retained as limits, not expected-failure baselines.
GaugeMesh does not advertise the `io.modelcontextprotocol/tasks` extension, so
the ten task scenarios are visible but unsupported. The runner also marks JSON
Schema 2020-12 and custom-header scenarios as pending; those observed failures
are not claimed as passes. The exact requirements command exits successfully
only because every scored requirement passed.

Passing means this exact check inventory passed. It is not MCP certification,
security certification, or a universal-client compatibility statement.
