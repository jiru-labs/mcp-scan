# mcp-scan

Security scanner for local MCP (Model Context Protocol) configurations.

`mcp-scan` reads the MCP config files on your machine — Claude Desktop, Claude Code, Cursor — and reports security risks: unverified servers, exposed static credentials, overly broad permissions, and tool poisoning patterns in tool descriptions.

It is built for individual developers and small teams who don't have enterprise security tooling.

**Local-first. Read-only by default. Zero telemetry.** The scanner never modifies your files, never makes network calls while scanning, and never logs credential values — only that a credential exists and where.

## Install

```bash
pipx install mcp-scan
```

## Usage

List the MCP servers declared in the host configs found on your machine, grouped by the host that declares them:

```bash
mcp-scan list
```

These are the files it looks for:

| Host | Config |
| --- | --- |
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Claude Code | `~/.claude.json`, and `.mcp.json` in the current directory |
| Cursor | `~/.cursor/mcp.json` |

A host you don't have installed is simply skipped, not an error.

Environment variables are listed by name only — `mcp-scan` never reads, prints or stores their values.

To inspect one config file instead of discovering the installed hosts:

```bash
mcp-scan list --config path/to/claude_desktop_config.json
```

Print the version:

```bash
mcp-scan version
```

The `scan` command is on the way — see the [open issues](https://github.com/jiru-labs/mcp-scan/issues).

## Development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## License

MIT
