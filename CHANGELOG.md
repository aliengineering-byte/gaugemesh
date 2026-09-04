# Changelog

All notable changes are documented here.

## Unreleased

## 0.2.2 - 2026-09-03

- Make GitHub Releases and the multi-architecture GHCR image the supported no-crates distribution paths; crate publication is disabled.
- Label the GHCR image with its Official MCP Registry identity and publish schema-current, digest-pinned OCI metadata only after public-image validation.
- Add public registry-query and stdio-launch gates without changing or replacing existing release tags or assets.

## 0.2.1 - 2026-09-02

- Correct the public selected/denied decision examples to use shell redirection
  rather than an unsupported `--output` option.
- Publish consistent `0.2.1` workspace identities and crates.io metadata for
  the `gaugemesh-core` and `gaugemesh` crates.
- Add fail-closed first-publication package inspection and dry-run evidence.

## 0.2.0 - 2026-09-02

- Add an opt-in, versioned route-decision contract for selected routes and a
  digest-bound denial contract that reports every hard-constraint rejection
  when no route is eligible. The default `route explain` JSON remains the
  original `0.1.0` bare-plan shape for existing machine consumers.
- Reject duplicate route IDs and unexplained denials, canonicalize denial
  ordering, and bind the complete selected/denied payload with an unsigned,
  recomputable decision digest.
- Add a checked-in decision JSON Schema and offline `route validate` command.
- Bump the workspace/package identity to `0.2.0` and update package
  acceptance artifacts accordingly.
- Upgrade all workflow checkout pins from immutable v4 to immutable v6 commits.

## 0.1.0 - 2026-08-30

- Add the typed invariant core, deterministic route explanations, capability
  identities and leases, phase-checked policy, memory/SQLite storage, and bounded
  process/runtime controls.
- Federate tools, resources, templates, and prompts over MCP 2025-11-25 and
  2026-07-28 using stdio and Streamable HTTP upstreams.
- Add a bounded OpenAI-compatible models/chat/Responses subset with configured
  provider routing and explicit tool-loop limits.
- Add TLS/OIDC remote-resource-server boundaries, default-deny authorization,
  trusted-proxy/origin validation, SSRF/DNS pinning, and credential ownership.
- Record official MCP conformance, ResiliReplay 0.7.0, fuzz, mutation, Miri,
  AddressSanitizer, supply-chain, cross-platform, cleanup, and performance
  evidence without converting those results into certification claims.
- Ship developer-preview archives, checksums, SPDX SBOM, provenance
  attestations, an optional multi-architecture GHCR image, and GitHub Pages.
