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

Scan those same servers for security risks:

```bash
mcp-scan scan
mcp-scan scan --config path/to/claude_desktop_config.json
```

Every detection rule runs against every server found, and the findings are reported worst-first, each naming the server, the host and the config file it came from. A rule that fails is reported as a warning; it never takes the scan down with it.

### What it detects

| Rule | Severity | What it flags |
| --- | --- | --- |
| `static-credential-in-args` | CRITICAL | A credential passed inline on a server's command line — `--api-key=sk-…`, `GITHUB_TOKEN=ghp_…`, `Authorization: Bearer …`. On top of sitting in the config file, it is visible in the process table to every other process running as you. |
| `static-credential-in-env` | WARN | A credential hardcoded as the value of an `env` entry, e.g. `"GITHUB_TOKEN": "ghp_…"`. |

The fix for both is to keep the value in your environment (or a secret manager) and have the config reference it — `"GITHUB_TOKEN": "${GITHUB_TOKEN}"`. A config that already does is not flagged.

A finding tells you *where* the credential is — which variable, which argument — and never what it is. The value is not printed, stored or logged.

More rules are landing — see the [open issues](https://github.com/jiru-labs/mcp-scan/issues). Adding one is adding a file: drop a `Rule` subclass into `mcp_scan/rules/`, give it an `id`, a `title` and a `severity` of `INFO`, `WARN` or `CRITICAL`, and the engine picks it up.

Print the version:

```bash
mcp-scan version
```

## Development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## License

MIT
