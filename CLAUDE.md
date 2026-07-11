# mcp-audit

## What this project is

A security CLI that scans local MCP (Model Context Protocol) configurations and
reports what the configuration itself gives away: static credentials written into
it, servers reached over plaintext, launch commands that download and run remote
code or resolve a package name anyone could claim, and servers granted a whole
filesystem or an unrestricted shell.

It reads the configuration, not the servers. A tool's *description* — where a
tool-poisoning payload actually hides — is served by a running server, not
written in the config file, so no rule reads one (issue #35: the project used to
claim it did). What the rules flag are the conditions that let a payload be
planted (a rewritable transport, a launch command whose code can change under
you) and the permissions that decide what it could take. Reading descriptions for
real needs an opt-in live mode; see the network-call policy below.

Target user: individual developers and small teams using Claude Code, Claude Desktop, Cursor or other MCP hosts, who don't have enterprise security tooling.

Philosophy: local-first, read-only by default, zero telemetry, clear and actionable output.

## Status and roadmap

- Done: reading and listing configs (issues #1–#5), across every host scope
  including local/project scopes (issues #14, #31) and VS Code and Windsurf
  (issue #38); risk detection (issues #6–#9); credential redaction
  (issues #16, #22); exportable report (issues #10, #19) in markdown, JSON and
  SARIF (issue #34), located at the line the server is declared on (issue #39);
  exit-code hardening for CI (issues #9, #23, #27).
- Open issues drift out of this list faster than it gets rewritten: run
  `gh issue list` rather than trusting the paragraph above. Open as of
  2026-07-11: #35, #36, #37, #39.
- Next: pick one of those, or propose new ones per the project thesis below
  (e.g. more MCP hosts, more detection rules).

## Tech stack

- Language: Python 3.11+ (chosen for readability and its security ecosystem)
- CLI framework: Typer
- Output: Rich (tables and colors in the terminal)
- Tests: pytest — every new feature ships with tests
- Packaging: pyproject.toml, installable with pipx
- No network dependencies in the core: the scanner never sends data anywhere

## Repo structure

```
mcp_audit/
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
5. The scanner NEVER modifies user files and NEVER logs credential values (it only reports that they exist and where). The **default** scan makes no network call and starts no process — see the network-call policy below.
6. Defensive error handling: malformed configs, non-existent paths or denied permissions must not crash — they're reported as warnings.
7. Code, docstrings, docs, commits and issues in English (public project). When talking to the user, reply in the language they wrote in.
8. If you find technical debt outside the scope of the issue, don't fix it: open a new issue with `gh issue create`.

## Network-call policy (decided 2026-07-11)

The default scan stays local-first: no network call, no process started, no
telemetry. That is the promise the project rests on, and nothing may weaken it.

An **explicit opt-in flag** may break it, because the user asked for it in so
many words. Two are planned:

- `--check-registry` — ask npm/PyPI whether a package still resolves, to catch a
  name that was unpublished and re-registered by someone else (issue #36).
- `--live` — launch each configured server, call `tools/list`, and run the tool
  descriptions through injection-pattern heuristics. The real tool-poisoning
  detection, and the reason the claim in issue #35 was narrowed rather than
  dropped.

Rules for anything that takes this door: off by default; a failed request or a
server that will not start is a **warning**, never a finding (a flaky network
must not turn CI red); and no credential ever leaves the machine.

## Useful commands

```bash
pytest                  # run tests
pip install -e ".[dev]" # install in development mode
python -m mcp_audit      # run the CLI locally
gh issue view N         # read issue N
gh issue list           # list open issues
```

## Project thesis (business context)

Existing MCP security tooling targets enterprise (thousands of €/month). The individual/small-team segment is empty. Expected catalyst: a mass security incident affecting individual agent users. Signal to accelerate: organic growth in stars/installs after publishing. Signal to archive: a large player ships an equivalent free scanner for this segment.
