# Adversarial verification

This page records the reproducible evidence used for the 0.1.0 hardening gate. Raw corpora, sanitizer targets, mutation scratch trees, and execution logs remain outside the repository. The results below were produced on Linux x86-64 on 2026-08-30 with Rust 1.88.0 and the pinned `nightly-2026-08-30` toolchain.

## Fuzzing

`cargo-fuzz 0.13.2` ran both checked-in targets with libFuzzer corpora and artifacts stored in external scratch directories.

| Target | Time | Executions | Final coverage/features | Corpus | Faults |
| --- | ---: | ---: | ---: | ---: | ---: |
| `config` | 60 seconds | 1,288,807 | 2,890 / 11,506 | 2,417 inputs, 152 KiB | 0 |
| `protocol_revision` | 60 seconds | 42,672,607 | 18 / 19 | 1 input | 0 |

Neither campaign produced a crash, timeout, out-of-memory condition, or sanitizer diagnostic. These are bounded campaigns, not an exhaustiveness claim; CI keeps the targets reproducible and longer campaigns remain useful as the input surface grows.

## Mutation testing

`cargo-mutants 27.1.0` exercised the safety-critical core files for invariants, translation, routing, policy, capabilities, budgets, causal graphs, and protocol negotiation. An isolated full campaign generated 121 mutants:

- 108 viable mutants were caught by the test suite;
- 0 viable mutants survived;
- 0 viable mutants timed out after focused reruns with extended build and test limits; and
- 13 mutants were compile-invalid because they attempted to return `Default` for domain types that deliberately do not implement `Default`.

The compile-invalid set covered `Budget`, `ConservationReport`, `PolicyDocument`, `PolicyEffect`, `CompiledPolicy`, `PolicyPhase`, `McpRevision`, `RouteMetricSnapshot`, `RoutePlan`, and borrowed observation storage. It was retained as visible unviable output rather than hidden behind broad exclusions. This gate is intentionally focused on the eight named core files; it is not a whole-workspace mutation score.

## Interpreter and sanitizer checks

Miri interpreted 18 deterministic tests under its default isolation: digest (2), policy (3), causal graph (3), invariant (8), and translation (2). All passed. Three property-test harnesses in the invariant module are explicitly ignored only under `cfg(miri)` because proptest failure persistence requests the host working directory; the same properties run in the ordinary and AddressSanitizer suites.

AddressSanitizer used the pinned nightly compiler, `-Zbuild-std`, leak detection, and fail-fast diagnostics. It passed 25 binary unit tests, the stdio integration test, and 63 core tests with no address or leak diagnostic. The sanitizer evidence is Linux-only; native Windows behavior is covered by the hosted platform matrix rather than a Windows sanitizer run.

## Properties and negative controls

The normal Rust 1.88.0 suite includes property, metamorphic, boundary, and failure-path tests for:

- monotone token, money, deadline, and retry budgets;
- append-only policy and approval ledgers;
- delegation prefix connectivity, tenant/scope preservation, and cycle rejection;
- causal acyclicity, including each independent rejection condition;
- translation loss at and beyond the configured equality boundary;
- exact MCP revision negotiation and capability snapshot pinning;
- route, policy, protocol, and conservation decisions; and
- authentication, proxy trust, admission, upstream failure, SSRF, and approval denial paths.

The mutation campaign supplied the negative control: weakened comparisons, removed conditions, altered protocol/capability decisions, and permissive defaults had to make tests fail. Focused reruns confirmed every initially ambiguous viable mutant was killed.

## Operational boundaries

All campaigns used external target directories and scratch corpora. Post-run inspection found no surviving GaugeMesh process or listener. The repository excludes generated mutation, fuzz, sanitizer, benchmark, and conformance output.

Residual risk remains: fuzzing is time-bounded, Miri targets selected pure safety surfaces rather than the entire asynchronous workspace, mutation testing covers the eight most critical core modules, and sanitizer execution is Linux-only. These limits are explicit so future releases can extend the evidence without overstating what this gate proves.
