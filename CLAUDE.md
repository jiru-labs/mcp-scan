# mcp-scan

## What this project is

A security CLI that scans local MCP (Model Context Protocol) configurations and detects risks: unverified servers, exposed static credentials, excessive permissions, and tool poisoning patterns in tool descriptions.

Target user: individual developers and small teams using Claude Code, Claude Desktop, Cursor or other MCP hosts, who don't have enterprise security tooling.

Philosophy: local-first, read-only by default, zero telemetry, clear and actionable output.

## Status and roadmap

- Done: reading and listing configs (issues #1–#5), across every host scope
  including local/project scopes (issues #14, #31); risk detection
  (issues #6–#9); credential redaction (issues #16, #22); exportable
  report (issue #10, #19); exit-code hardening for CI (issues #9, #23, #27).
- All issues filed so far (#1–#31) are closed; no open issues or PRs as of
  2026-07-11.
- Next: see the open issues, or propose new ones per the project thesis
  below (e.g. more MCP hosts, CI-friendly output formats).

## Tech stack

- Language: Python 3.11+ (chosen for readability and its security ecosystem)
- CLI framework: Typer
- Output: Rich (tables and colors in the terminal)
- Tests: pytest — every new feature ships with tests
- Packaging: pyproject.toml, installable with pipx
- No network dependencies in the core: the scanner never sends data anywhere

## Repo structure

```
mcp_scan/
  __init__.py
  cli.py          # Typer entrypoint
  discovery.py    # locate MCP config files per host
  parsers.py      # parse each config format
  credentials.py  # what a credential looks like: detection + redaction
  rules/          # one detection rule per file
  report.py       # report generation
tests/
CLAUDE.md
README.md
pyproject.toml
```

## MCP config paths supported

- Claude Desktop: macOS `~/Library/Application Support/Claude/claude_desktop_config.json`,
  Linux `~/.config/Claude/claude_desktop_config.json`, Windows
  `%APPDATA%/Claude/claude_desktop_config.json`.
- Claude Code: global `~/.claude.json`, plus per-project `.mcp.json`.
- Cursor: global `~/.cursor/mcp.json`, plus per-project `.cursor/mcp.json`.
- VS Code: macOS `~/Library/Application Support/Code/User/mcp.json`, Linux
  `~/.config/Code/User/mcp.json`, Windows `%APPDATA%/Code/User/mcp.json`, plus
  per-project `.vscode/mcp.json`. VS Code's top-level key is `servers`, not
  `mcpServers` — `parsers.py` picks the key by host rather than trying both,
  so a config discovered under the wrong host still parses to zero servers
  instead of a silent, misleading "clean scan".
- Windsurf: global `~/.codeium/windsurf/mcp_config.json` (no documented
  project-scoped config).
- Not yet supported: Continue.dev. Its `config.json` nests servers under
  `experimental.modelContextProtocolServers` as a list, not a `mcpServers`/
  `servers` map, and its documented direction is a YAML format the parser
  doesn't read — discovering it needs real parser work first (tracked in a
  follow-up issue).

## Working rules for Claude Code

1. Read the whole issue before touching code. If the issue is ambiguous, leave a comment with the question instead of assuming.
2. One issue = one commit (or a few atomic commits). Commit messages in English, format: `feat: ...`, `fix: ...`, `test: ...`, `docs: ...`
3. All new code ships with tests in `tests/`. Run `pytest` before committing; never commit with failing tests.
4. Don't add new dependencies unless the issue explicitly asks for them.
5. The scanner NEVER modifies user files, NEVER makes network calls in scan mode, and NEVER logs credential values (it only reports that they exist and where).
6. Defensive error handling: malformed configs, non-existent paths or denied permissions must not crash — they're reported as warnings.
7. Code, docstrings, docs, commits and issues in English (public project). When talking to the user, reply in the language they wrote in.
8. If you find technical debt outside the scope of the issue, don't fix it: open a new issue with `gh issue create`.

## Useful commands

```bash
pytest                  # run tests
pip install -e ".[dev]" # install in development mode
python -m mcp_scan      # run the CLI locally
gh issue view N         # read issue N
gh issue list           # list open issues
```

## Project thesis (business context)

Existing MCP security tooling targets enterprise (thousands of €/month). The individual/small-team segment is empty. Expected catalyst: a mass security incident affecting individual agent users. Signal to accelerate: organic growth in stars/installs after publishing. Signal to archive: a large player ships an equivalent free scanner for this segment.
