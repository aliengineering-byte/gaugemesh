# Client evidence levels

Observed 2026-08-30. `VERIFIED` means the exact interface was exercised by an
automated release gate; it does not imply the full product is supported.

| Client/interface | Level | Evidence / limitation |
|---|---|---|
| Official MCP conformance client, Streamable HTTP | VERIFIED | Exact `@modelcontextprotocol/conformance@0.2.0-alpha.11` runs connect to `/mcp` separately for both supported revisions. |
| GaugeMesh/RMCP upstream client, stdio and HTTP | VERIFIED | Real cross-process and HTTP integration tests cover lifecycle and tools/resources/prompts federation with RMCP 3.1.4. |
| OpenAI Python SDK 3.6.0 | VERIFIED | The release archive is started and the SDK calls models, chat completions, and Responses with a custom `base_url`. |
| Generic raw OpenAI-compatible HTTP | VERIFIED | Local HTTP tests cover models, chat completions, Responses, bounded JSON, and bounded SSE. |
| Product-specific MCP client installation | DOCUMENTED_ONLY | No product-specific installer or configuration is emitted. |
| ChatGPT remote MCP | UNSUPPORTED | The exact product path was not executed; no compatibility claim is made. |

`gaugemesh connect` accepts only `generic-mcp` and `openai-compatible` and emits
the corresponding endpoint shape. It does not prove product-specific setup by
itself; the automated evidence above supplies the `VERIFIED` labels.
