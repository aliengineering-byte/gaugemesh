# Two reviewed sources

This discovery example uses two independent GaugeMesh stdio fixtures, both of
which expose a native `search` tool. Replace the executable path with the absolute
path printed by your build system.

```sh
gaugemesh init --force
gaugemesh add mcp source-a --command /absolute/path/gaugemesh --arg mcp-stdio --protocol-revision 2025-11-25
gaugemesh add mcp source-b --command /absolute/path/gaugemesh --arg mcp-stdio --protocol-revision 2026-07-28
gaugemesh list
```

Each `add` performs live stdio discovery and joins the child. `serve` reloads the
reviewed sources into its bounded pool, pins their capability snapshot, and
keeps colliding tools, resources, and prompts distinct by `CapabilityId` and
schema digest.
