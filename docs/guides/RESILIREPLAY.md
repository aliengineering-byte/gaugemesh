# Bounded reliability verification

GaugeMesh invokes `resilireplay@0.7.0` as an optional external CLI. It is not a
runtime library and its source is not vendored.

The release-gated path uses `gaugemesh mcp-stdio`, tool `docs-a__search`, safety
class `read-only`, one retry, a 3000 ms timeout, `--no-regression`, and separate
evidence output for a clean control plus every fault exposed by the published
0.7.0 `mcp test` command. For every scenario GaugeMesh requests a dry-run JSON
plan, validates its 64-hex plan SHA-256, then supplies that exact digest with
`--approve`. Each invocation is an argument array, not a shell command.

Observed local result on 2026-08-30:

| Scenario | Recovery result |
|---|---|
| clean control | PASS |
| tool timeout | PASS |
| deterministic tool error | PASS |
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

All 13 scenarios observed the requested condition, completed cleanup, and
reported zero duplicate effects. The required clean-control, timeout-recovery,
and deterministic-error recovery gate passed. The combined matrix result is
therefore `PARTIAL`, not a claim that every mutation recovered. Its combined
evidence SHA-256 is
`sha256:9491a090c00a510b9c6e3db1439253eafb23ad67ada3df2c66420abd2bf01bc4`.
The individual plan and evidence digests are emitted by
`gaugemesh verify --resilireplay`.

The public 0.7.0 command output did not identify an MCP-RES v0.2 profile or
evidence class. GaugeMesh records `mcpRes: null` and makes no MCP-RES compliance,
official MCP certification, security certification, or exactly-once claim.
