# Initial issues — mcp-scan

Copy the title and body of each one with `gh issue create --title "..." --body "..."` or from the web. Order matters: they are incremental.

---

## Issue #1 — Project scaffold

**Title:** `feat: project scaffold with Typer CLI and pytest`

**Body:**
Create the base project structure as described in CLAUDE.md:
- `pyproject.toml` with Typer, Rich and pytest as a dev dependency
- `mcp_scan/` package with a `cli.py` exposing the `mcp-scan version` command that prints the version
- `tests/` folder with a test verifying the CLI responds
- `.gitignore` for Python

**Acceptance criteria:** `pip install -e ".[dev]"` works, `mcp-scan version` prints the version, `pytest` passes green.

---

## Issue #2 — Claude Desktop config discovery

**Title:** `feat: discover Claude Desktop MCP config on macOS`

**Body:**
Create `discovery.py` with a function that locates the Claude Desktop config file on macOS (`~/Library/Application Support/Claude/claude_desktop_config.json`). It must return an object with: path, whether it exists, and the host it belongs to ("claude-desktop").

**Acceptance criteria:** function tested with simulated paths (pytest's `tmp_path`), handles the non-existent file case without raising.

---

## Issue #3 — Config parser and `list` command

**Title:** `feat: parse MCP servers from config and add 'list' command`

**Body:**
Create `parsers.py` that reads the config JSON and extracts the list of MCP servers: name, command/URL, args, and declared environment variables (KEYS ONLY, never the values). Add a `mcp-scan list` command that shows a Rich table with the servers found.

**Acceptance criteria:** with a sample config in tests/fixtures, `mcp-scan list` shows the table. Malformed JSON produces a warning, not a crash. No env var value ever appears in the output.

---

## Issue #4 — Claude Code and Cursor support

**Title:** `feat: discover Claude Code and Cursor MCP configs`

**Body:**
Extend `discovery.py` to also locate:
- Claude Code: `~/.claude.json` and `.mcp.json` in the current directory
- Cursor: `~/.cursor/mcp.json`

`mcp-scan list` must group servers by their source host.

**Acceptance criteria:** tests with fixtures for the three formats; the table indicates which host each server comes from.

---

## Issue #5 — Rule engine

**Title:** `feat: rule engine skeleton with severity levels`

**Body:**
Create the `rules/` package with a base `Rule` class (id, title, severity: INFO/WARN/CRITICAL, method `check(server) -> list[Finding]`). Create a `mcp-scan scan` command that runs all registered rules against the discovered servers and shows findings in a Rich table sorted by severity.

**Acceptance criteria:** with a dummy test rule, `mcp-scan scan` produces correct output. Adding a new rule = adding a file, without touching the engine.

---

## Issue #6 — Rule: static credentials

**Title:** `feat: rule to detect static credentials in MCP configs`

**Body:**
Rule that detects static credentials: env vars with names like `*_KEY`, `*_TOKEN`, `*_SECRET`, `*_PASSWORD` holding a non-empty value in the config, and tokens appearing inline in the command args. Severity WARN (env var) / CRITICAL (inline in args). The finding states where the credential is, never the value.

**Acceptance criteria:** tests cover both cases and the negative case. Output contains no sensitive value.

---

## Issue #7 — Rule: tool poisoning patterns

**Title:** `feat: rule to flag suspicious patterns in server definitions`

**Body:**
Heuristic rule that flags risk signals in server definitions: commands that download and execute remote code (`curl | sh`, `npx` of non-scoped packages with suspicious names), execution paths in temporary directories, and servers pointing to non-HTTPS URLs. Severity WARN/CRITICAL depending on the case. Document in the docstring what inspired each heuristic (reference: OWASP MCP Top 10).

**Acceptance criteria:** at least 4 heuristics implemented, each with positive and negative tests.

---

## Issue #8 — Rule: excessive permissions and scope

**Title:** `feat: rule to detect overly broad filesystem/system access`

**Body:**
Rule that detects servers with broad access: filesystem servers pointing at `/`, `~` or whole disks; servers with unrestricted shell access. Severity WARN, with a minimum-scope recommendation included in the finding.

**Acceptance criteria:** tests with sample configs; the finding includes the concrete recommendation.

---

## Issue #9 — Exit codes and CI mode

**Title:** `feat: exit codes and --quiet mode for CI usage`

**Body:**
`mcp-scan scan` must return exit code 0 (clean), 1 (warnings), 2 (criticals) and accept `--quiet` (summary only) so it can be used in scripts and CI.

**Acceptance criteria:** tests verify the three exit codes.

---

## Issue #10 — Exportable report

**Title:** `feat: markdown and JSON report export`

**Body:**
Add `mcp-scan scan --output report.md` and `--output report.json`. The markdown must be readable and shareable (summary, findings table, recommendations). The JSON must be stable for downstream tooling.

**Acceptance criteria:** both formats generated and tested; the markdown renders well on GitHub.

---

## After #10

Once these 10 are closed, the project is publishable: README with a GIF of the scan, publish to PyPI, a dev.to post, and submissions to the awesome-mcp lists. That's the milestone marking the end of Phase 1 of the anchor project.
