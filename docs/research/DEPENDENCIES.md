# Dependency and source-origin review

Reviewed 2026-08-30. GaugeMesh source is original work under Apache-2.0. No
ResiliReplay or competitor source is vendored. Cargo resolves crates from
crates.io; npm is used only by pinned verification commands in CI/runtime temp
directories.

The authoritative inventory is `Cargo.lock` plus the generated release SBOM.
Direct dependencies are permissively licensed (Apache-2.0, MIT, ISC, BSD, or
Unicode-3.0 families). `cargo deny check licenses sources bans advisories` is a
release gate. Git sources and unknown registries are denied. Duplicate versions
are reported for review rather than silently accepted.

External development verifiers:

- `@modelcontextprotocol/conformance@0.2.0-alpha.11`, official MCP conformance
  runner. The alpha pin is required because the stable 0.1 line does not include
  the 2026-07-28 requirement set.
- `resilireplay@0.7.0`, invoked as an optional external CLI. Its source is not
  imported and its output is retained only as bounded hashes/metadata.
- `openai-python==3.6.0`, used only by release acceptance to verify the documented
  custom-`base_url` subset. It is not a Rust runtime dependency.

Package metadata and licenses can change. The lockfile, deny policy, SBOM and
release commit together define the reviewed dependency set.
