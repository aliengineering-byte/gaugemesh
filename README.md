# GaugeMesh

One endpoint for MCP capabilities and model routes—without losing identity,
authority, budgets, deadlines, side-effect semantics, or causal evidence between
protocols.

GaugeMesh is a local-first Rust developer preview. It is deliberately narrower
than a general AI gateway: every adapter must preserve declared invariants or
reject the operation before a side effect. Route selection is fixed-point,
deterministic, and explainable. The base deployment is one binary with memory or
SQLite; it needs no hosted control plane, Redis, PostgreSQL, Docker, or
Kubernetes.

## Run the local proof

From a release archive:

```sh
gaugemesh demo
```

From source with Rust 1.88 or newer:

```sh
cargo run --locked --release -- demo
```

No account, credential, provider, network target, database, container, or
existing MCP server is used. The command writes no file to the caller directory.

Actual output from the `0.1.0` release binary:

```text
GaugeMesh demo

[ok] 2 MCP sources connected
[ok] 1 model route connected
[ok] colliding tool names isolated by capability identity: true
[ok] 2 capabilities leased
[ok] route selected under cost, deadline, and policy bounds
[ok] deterministic failure reproduced
[ok] recovery bounded to one attempt
[ok] duplicate effects: 0
[ok] invariants preserved or strengthened: 23/23
[ok] cleanup complete: no owned child or listener remains

Route: local-model -> docs-a__search
Decision: sha256:169a6315aa69eb7fa3e3b5aae70ede14d4c9ec71c0281d217fd84201414567f1
Evidence: sha256:beff1b394239b0993d0082e86f4acceb9726975a8cf07c8442c5a2fffdd269d5
```

## What the demo proves

- Two upstreams can expose the same native `search` name without sharing an
  authorization identity.
- A lease binds an exact principal, tenant, task, schema, capability set,
  expiry, scope, budgets, side-effect permission, and manifest digest.
- Hard route constraints run before an integer action score and stable tie
  breaker.
- One injected failure consumes the single retry budget; it cannot amplify.
- The checked translation preserved or strengthened 23 invariants with zero
  semantic loss.
- The read-only case observed zero duplicate effects and completed with no
  owned child process or listener.

The demo is deterministic fixture evidence, not a production-duration soak or
security certification.

## Architecture

```text
MCP clients --------------------+  /mcp
                                |
OpenAI-compatible clients ------+--> GaugeMesh --> invariant + policy boundary
                                |         |             before execution
MCP servers needing models -----+  /v1/*  +--> MCP stdio / Streamable HTTP
                                          +--> OpenAI-compatible providers
                                          +--> official/private registries

ResiliReplay ---------------------- verification only; never a production hop
```

GaugeMesh is an MCP server northbound and an MCP client southbound. It is an
OpenAI-compatible server northbound and a client of configured compatible model
providers southbound. Registry records are discovery metadata, not execution
authority.

## Add one MCP server

Create a strict loopback configuration:

```sh
gaugemesh init
```

Review and add a local stdio server. `--command` must resolve to an absolute
executable and is launched with an argument array, never through a shell:

```sh
gaugemesh add mcp docs \
  --command "$(command -v gaugemesh)" \
  --arg mcp-stdio \
  --protocol-revision 2025-11-25
```

`add` performs live discovery and writes the source only after tools, resources,
templates, prompts, server identity, and revision are readable. `serve` loads
reviewed sources into a bounded runtime, pins the capability snapshot, and
rejects schema drift. Tools, resources, and prompts keep source-bound opaque
identities even when readable aliases collide. Streamable HTTP sources use the
same command with a reviewed `--url`; Registry search/inspect/approve is a
separate trust path and never installs or executes a discovered package.

## Add one model

The provider must expose a compatible `/v1/models` endpoint. To exercise the
complete no-key setup, keep `gaugemesh serve` running in one terminal and add its
built-in local model route from another:

```sh
gaugemesh serve
```

```sh
gaugemesh add model local-provider \
  --base-url http://127.0.0.1:8090/v1/ \
  --provider-model-id local \
  --context-limit 8192 \
  --max-output-tokens 1024 \
  --cost-table-version local-2026-08-30
```

For a credentialed provider, pass the environment-variable name, not its value:

```sh
gaugemesh add model hosted \
  --base-url https://provider.example.test/v1/ \
  --provider-model-id reviewed-model \
  --credential-env PROVIDER_API_KEY \
  --cost-table-version contract-2026-08
```

Configured routes are checked against capability, context, deadline, token,
money, retry, data, and side-effect limits before selection. Cost tables are
version-bound; estimates are not presented as provider billing facts.

## Connect an MCP client

Start the data and separately bound health listeners:

```sh
gaugemesh doctor
gaugemesh list
gaugemesh serve
gaugemesh connect generic-mcp
```

Loopback defaults are `http://127.0.0.1:8090/mcp` for Streamable HTTP,
`http://127.0.0.1:8090/v1` for the model API, and
`http://127.0.0.1:8092/healthz` for health. The official MCP conformance client
connects to `/mcp` separately for both supported revisions. GaugeMesh also has
real RMCP integration tests as an upstream client over stdio and Streamable
HTTP. Product-specific client installers are not emitted without installation
evidence.

## Connect an OpenAI-compatible client

Point a client that supports a custom base URL at GaugeMesh:

```sh
gaugemesh connect openai-compatible
curl http://127.0.0.1:8090/v1/chat/completions \
  -H 'content-type: application/json' \
  -d '{"model":"local","messages":[{"role":"user","content":"hello"}]}'
```

The release gate also executes `openai-python==3.6.0` against that base URL for
model listing, chat completions, and Responses. The implemented surface is
`GET /models`, `POST /chat/completions`, and `POST /responses`, with bounded JSON
and SSE behavior. Unknown request fields are rejected. This is a verified subset,
not complete OpenAI API compatibility.

Tool execution is off unless a request explicitly selects a GaugeMesh mode and
bound:

```text
x-gaugemesh-tool-mode: lease
x-gaugemesh-max-tool-rounds: 1
x-gaugemesh-deadline-ms: 3000
```

These extension headers are not OpenAI fields. An MCP server can call `/v1/*`
directly for model access; deprecated MCP sampling is not silently converted.
Unsupported sampling and elicitation paths return stable errors or enter an
explicit approval backend.

## Five invariant rules

1. A route is a typed trust-graph path; a display alias never identifies a node.
2. Principal, tenant, capability, schema, causal root, and provenance are
   conserved unless a checked delegation explicitly permits the transition.
3. Scope, delegated authority, deadline, money, tokens, and retries only shrink;
   data protection never decreases.
4. Optional translation loss has a bounded integer score; required semantic loss
   rejects before target execution.
5. Queue pressure, retry dissipation, and breaker hysteresis use ordinary,
   falsifiable software definitions. No physics analogy overrides the code.

Run `gaugemesh route explain` for accepted and rejected candidates, integer score
terms, the stable tie breaker, and policy/metric snapshot digests. The analogy
boundary is documented in [the physics model](docs/architecture/PHYSICS_MODEL.md).

## Safety boundaries

- Unauthenticated mode is loopback-only. Remote mode requires TLS, an explicit
  HTTPS public origin, exact OIDC issuer/audience/resource validation, required
  scopes, bounded JWKS caching, a trusted-proxy allowlist, and default-deny
  policy.
- API-key primitives use random material shown once, Argon2id hashes,
  tenant/scope binding, and revocation; the `0.1.0` remote listener authenticates
  OIDC bearer tokens rather than exposing an API-key administration service.
- Downstream bearer tokens are never passed upstream by default. Provider
  credentials remain environment or restricted-file references and are not
  ordinary SQLite values.
- Remote URLs reject unsafe schemes/address classes, pin approved DNS answers,
  bind the exact host/port and peer IP, disable automatic redirects, and bound
  response bodies.
- Stdio uses exact argv, `kill_on_drop`, startup/framing limits, restart budgets,
  and a security-partitioned process key. Unknown servers are non-shareable.
- Admission queues, request bodies, process output, SSE output, tool rounds, and
  shutdown waits are bounded. Cancellation propagates through owned resources.

See [SECURITY.md](SECURITY.md), [THREAT_MODEL.md](THREAT_MODEL.md), and the
[adversarial evidence](docs/compatibility/ADVERSARIAL.md). GaugeMesh does not
claim exactly-once execution, production readiness, universal client/provider
support, official MCP status, MCP certification, or security certification.

## Verified compatibility

| Surface | Evidence | Result |
|---|---|---|
| MCP server, Streamable HTTP, 2025-11-25 | official conformance 0.2.0-alpha.11 | 70/70 scored checks |
| MCP server, Streamable HTTP, 2026-07-28 | official conformance 0.2.0-alpha.11 | 117/117 scored checks |
| MCP client, stdio and HTTP, both revisions | RMCP 3.1.4 cross-process/integration tests | VERIFIED subset |
| OpenAI-compatible HTTP | raw HTTP, provider fixture, and OpenAI Python SDK 3.6.0 | VERIFIED subset |
| Product-specific client installation | not executed | DOCUMENTED_ONLY or UNSUPPORTED |

Conformance-only synthetic capabilities are absent in normal operation. Pending
or unscored extension checks are not counted, MCP tasks are not advertised, and
the results are protocol evidence rather than official certification. See the
[MCP matrix](docs/compatibility/MCP.md), [client levels](docs/compatibility/CLIENTS.md),
and [conformance inventory](docs/compatibility/CONFORMANCE.md).

## ResiliReplay verification

ResiliReplay is optional and external:

```sh
gaugemesh verify --resilireplay
```

GaugeMesh invokes the exact published `resilireplay@0.7.0` executable with an
argument array from sanitized temporary state. Thirteen scenarios produced three
recovery passes and ten explicit failures; the required clean, timeout, and
deterministic-error recovery gate passed, cleanup completed, and duplicate
effects were zero. The honest aggregate is `PARTIAL`. ResiliReplay emitted no
MCP-RES v0.2 profile/evidence class for this command, so GaugeMesh makes no
MCP-RES claim. Details and the evidence digest are in
[the verification record](docs/guides/RESILIREPLAY.md).

## Development

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo test --doc --workspace
cargo deny check advisories bans licenses sources
cargo audit --deny warnings
```

Rust 1.88 is the MSRV. Hosted gates cover current stable and MSRV on Ubuntu and
Windows, stable on macOS, native release archives for Linux x64/ARM64, Windows
x64, and macOS ARM64/x64, plus fuzzing, mutation, Miri, AddressSanitizer,
conformance, ResiliReplay, an SPDX SBOM, checksums, attestations, container smoke,
and clean archive execution.

Contributions must preserve typed invariants and include a test able to falsify
the change. See [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities through
GitHub private vulnerability reporting, not a public issue.

## License

Apache-2.0. Dependency and source-origin notes are in
[docs/research/DEPENDENCIES.md](docs/research/DEPENDENCIES.md).
