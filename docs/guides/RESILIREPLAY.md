# Bounded reliability verification

GaugeMesh invokes `resilireplay@0.7.0` as an optional external CLI. It is not a
runtime library and its source is not vendored.

The release-gated path uses `gaugemesh mcp-stdio`, tool `docs-a__search`, safety
class `read-only`, one retry, a 3000 ms request bound, `--no-regression`, and
separate evidence for one genuine clean control plus every fault exposed by the
published 0.7.0 `mcp test` command. Each fault invocation first runs its own
unmodified control. GaugeMesh derives the single clean-control row from the
first actual clean trace, then runs all twelve faults explicitly; omitting
`--fault` would select `mcp-tool-error`, not a clean-only run. For every fault
GaugeMesh requests a dry-run JSON plan, validates its 64-hex plan SHA-256, then
supplies that exact digest with `--approve`. Each invocation is an argument
array, not a shell command.

ResiliReplay 0.7.0 applies these faults to its recorded trace after receiving a
real MCP response; it does not mutate the MCP wire or GaugeMesh server. In
particular, the timeout row substitutes a synthetic timeout trace event and
then makes one real retry. Its PASS therefore proves that bounded harness
behavior, cleanup, and duplicate-effect observation—not termination or recovery
from a real request timeout.

Observed local result on 2026-09-06 from the corrected PR source:

| Scenario | Matrix result |
|---|---|
| clean control | PASS |
| synthetic timeout trace mutation plus real retry | PASS |
| synthetic deterministic-error trace mutation plus real retry | PASS |
| malformed tools list | FAIL |
| renamed tool | FAIL |
| missing tool | FAIL |
| incompatible argument schema | FAIL |
| oversized content | FAIL |
| protocol-version mismatch | FAIL |
| invalid JSON-RPC ID | FAIL |
| malicious canary instruction | FAIL |
| permission/capability mismatch | FAIL |
| canary leakage attempt | FAIL |

The clean control passed. All twelve fault runs observed the requested trace
mutation, included a passing clean prerequisite, completed cleanup, and
reported zero duplicate effects. The required clean-control and two synthetic
retry rows passed. The combined matrix result is therefore `PARTIAL`, not a
claim that every mutation recovered or that a wire-level timeout was tested.
Its combined evidence SHA-256 is
`sha256:7d6f7a0c7ce1373b93d60374e9e75dc4d90a7ec306fb31b8e5bc703fbef34817`.
The individual plan and evidence digests are emitted by
`gaugemesh verify --resilireplay`.

An equal-environment comparison of base `57b8240` and candidate `1ff927e` found
no status regression. The
discovery, schema, size, protocol, JSON-RPC-ID, and capability mutations are
post-response trace changes, so their failures leave the corresponding target
behavior unproven rather than demonstrating a GaugeMesh rejection. The two
canary rows are intentional negative controls outside 0.7.0's two-fault retry
contract; their detected synthetic injections remain FAIL and are not waived.

The public 0.7.0 command output did not identify an MCP-RES v0.2 profile or
evidence class. GaugeMesh records `mcpRes: null` and makes no MCP-RES compliance,
official MCP certification, security certification, or exactly-once claim.
