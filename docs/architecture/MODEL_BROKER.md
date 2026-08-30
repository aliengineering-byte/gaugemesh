# Bounded model broker

GaugeMesh exposes a deliberately small OpenAI-compatible surface:

- `GET /v1/models`
- `POST /v1/chat/completions`
- `POST /v1/responses`

The checked subset accepts string message content, `model`, output-token bounds, and `stream`.
Unknown request fields fail with `GM_OPENAI_UNSUPPORTED_OR_INVALID_FIELD`; this project does not
claim complete OpenAI API compatibility. Both non-streaming JSON and explicitly terminated SSE are
tested. The same `/v1/*` endpoint is the primary path for an MCP server or any other service that
needs model access—legacy MCP sampling is not the primary architecture.

The provider trait has two implementations in 0.1: an in-process deterministic no-key fixture and
an OpenAI-compatible HTTP adapter. The latter is tested against a real local TCP fixture and uses
an exact provider model ID. `gaugemesh add model` checks the upstream `/models` response before it
writes a reviewed configuration. Provider credentials are referenced by environment-variable name;
the downstream authorization header is never forwarded.

Model authorization identity includes provider, endpoint digest, native model ID, capabilities,
context limit, tool/structured-output/streaming support, cost-table version, and policy digest. The
friendly `local` name is presentation only.

## GaugeMesh request controls

GaugeMesh extensions are explicit HTTP headers; standard fields are not overloaded:

| Header | Meaning | Default |
|---|---|---|
| `x-gaugemesh-tool-mode` | `off`, `transparent`, or `lease` | `off` |
| `x-gaugemesh-max-tool-rounds` | bounded nested tool rounds | `1` |
| `x-gaugemesh-max-input-tokens` | input estimate ceiling | `4096` |
| `x-gaugemesh-max-output-tokens` | output ceiling | `1024` |
| `x-gaugemesh-money-budget-micros` | hard estimated-cost ceiling | `0` for the free fixture |
| `x-gaugemesh-deadline-ms` | remaining monotonic deadline | `30000` |
| `x-gaugemesh-retry-limit` | provider retry ceiling | `0` |

Hard provider/model, token, money, deadline, and tool-round checks run before provider execution.
Costs use an explicitly versioned table. `estimatedCostMicros` and `observedCostMicros` are separate
response metadata fields; absent provider billing data remains `null` and is never relabeled as an
observation.

Tool mode is off unless requested. The initial deterministic path permits one read-only tool at a
time, caps input at 16 KiB and result data at 64 KiB, issues and checks an exact capability lease in
lease mode, and records a causal-child digest. Tool results are structured data and are appended as
a tool-role message only after the lease and side-effect checks pass.

## Server-to-client compatibility behavior

RMCP supplies the current MRTR wire primitives. GaugeMesh does not advertise deprecated sampling.
If an upstream sends a sampling request anyway, `GatewayClient` returns
`GM_SAMPLING_COMPAT_DISABLED`; it never drops the request. Sampling enablement, model approval, and
nested tool use are intentionally unavailable in the developer preview. Elicitation uses `DENY` by
default and returns an explicit decline. Static policy, local CLI, and signed-webhook approval are
typed future modes, not implied current support.

## Limitations

- The in-process fixture uses a documented byte-based token estimate, not a provider tokenizer.
- The live server uses the fixture route in this PR; configured provider loading and failover remain
  release-hardening work. The southbound adapter itself is exercised over TCP.
- Streaming is buffered provider output emitted as valid SSE. Incremental remote-provider stream
  parsing and mid-stream fallback are not claimed.
- No paid-provider or universal-provider compatibility claim is made.
- The bounded tool fixture proves authorization and causality; general multi-round model-selected
  tool-call parsing is not claimed.
