# No crates.io publication

Crates.io is not a GaugeMesh distribution channel. Both workspace packages set
`publish = false`, and CI rejects any change that re-enables Cargo publication.

Supported public installation paths are the checksummed, attested GitHub Release
archives and the multi-architecture GHCR image. The Official MCP Registry record
points to the image by immutable manifest digest after release publication.

No crates.io credential is required, requested, or used by this repository.
