# Agent integrations

The OwlAuth repository includes a plugin distribution for Codex and Claude. Its initial capability is an OwlAuth integration skill that explains the current public boundaries and prevents agents from inventing unavailable CLI or MCP commands.

The plugin does not bundle an MCP process. A future MCP interface is expected to be served by OwlAuth itself. A future Rust CLI may provide operator and developer workflows separately. Their planned security boundary is documented in [the CLI and MCP specification](https://github.com/owlfoundry/owlauth/blob/main/spec/07-cli-and-mcp-boundaries.md); commands and tools remain unimplemented.

See [`plugins/owlauth`](https://github.com/owlfoundry/owlauth/tree/main/plugins/owlauth) for manifests and skill source.
