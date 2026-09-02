# First crates.io publication

The official crates.io first-publish flow requires an owner-controlled API token.
Trusted Publishing can be configured only after a crate exists. Never place the
token in source, GitHub Actions, chat, an issue, or a build log.

For `0.2.1`, the owner performs the first publication from the protected
`v0.2.1` tag in this exact dependency order:

```sh
cargo login
cargo publish --dry-run --locked -p gaugemesh-core
cargo publish --locked -p gaugemesh-core
# Wait until https://crates.io/api/v1/crates/gaugemesh-core/0.2.1 resolves.
cargo publish --dry-run --locked -p gaugemesh
cargo publish --locked -p gaugemesh
cargo logout
```

The owner should create and enter the token only in their own authenticated
terminal, then revoke or minimize it after both packages resolve publicly.

After the first publication, configure crates.io Trusted Publishing separately
for `gaugemesh-core` and `gaugemesh`, using GitHub repository
`aliengineering-byte/gaugemesh` and a protected environment such as
`crates-io`. A future release workflow can then exchange GitHub OIDC identity for
a short-lived registry token; `0.2.1` must not be republished through that flow.
