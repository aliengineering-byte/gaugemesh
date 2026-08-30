# GaugeMesh

One endpoint for MCP capabilities and model routes—without losing identity,
authority, budgets, deadlines, side-effect semantics, or causal evidence between
protocols.

GaugeMesh is an early developer preview. The repository is being built in four
reviewable stages; compatibility claims will appear only with reproducible test
evidence.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
```

## License

Apache-2.0.

