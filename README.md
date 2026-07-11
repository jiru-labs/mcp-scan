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

```bash
mcp-scan version
```

More commands (`list`, `scan`) are on the way — see the [open issues](https://github.com/jiru-labs/mcp-scan/issues).

## Development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## License

MIT
