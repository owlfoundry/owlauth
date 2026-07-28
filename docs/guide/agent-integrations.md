# Agent integrations

The OwlAuth repository includes a plugin distribution for Codex and Claude. Its initial capability is an OwlAuth integration skill that explains current public boundaries and prevents agents from inventing unavailable OAuth or MCP behavior.

The plugin does not bundle an MCP process. A future MCP interface is expected to be served by OwlAuth itself.

The separate Rust CLI is available as the `owlauth` executable. Its current public command surface is limited to checksum-verified self-update; operator and developer commands remain unimplemented until their server contracts and security semantics are designed. The boundary is documented in [the CLI and MCP specification](https://github.com/owlfoundry/owlauth/blob/main/spec/07-cli-and-mcp-boundaries.md).

See [`plugins/owlauth`](https://github.com/owlfoundry/owlauth/tree/main/plugins/owlauth) for manifests and skill source.
