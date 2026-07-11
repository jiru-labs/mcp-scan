# mcp-scan

Security scanner for local MCP (Model Context Protocol) configurations.

`mcp-scan` reads the MCP config files on your machine — Claude Desktop, Claude Code, Cursor, VS Code, Windsurf — and reports security risks: unverified servers, exposed static credentials, overly broad permissions, and tool poisoning patterns in tool descriptions.

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
| Claude Desktop | macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`; Linux: `~/.config/Claude/claude_desktop_config.json`; Windows: `%APPDATA%\Claude\claude_desktop_config.json` |
| Claude Code | `~/.claude.json` (both the user-scoped servers and the project-local ones nested inside it), and `.mcp.json` in the current directory |
| Cursor | `~/.cursor/mcp.json`, and `.cursor/mcp.json` in the current directory |
| VS Code | macOS: `~/Library/Application Support/Code/User/mcp.json`; Linux: `~/.config/Code/User/mcp.json`; Windows: `%APPDATA%\Code\User\mcp.json`; and `.vscode/mcp.json` in the current directory |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |

A host you don't have installed is simply skipped, not an error. Every scope is attributed to the host that owns it, so a server added with `claude mcp add --scope local` shows up under Claude Code just like the others.

No credential is ever printed. Environment variables are listed by name only — `mcp-scan` never reads, prints or stores their values — and a credential written into a command line or a URL is masked where the endpoint is shown: `npx server --api-key=***`, `https://mcp.example.com/sse?api_key=***`. A value referenced from the environment, `--api-key=${API_KEY}`, is left readable: it is the fix, not the leak.

To inspect one config file instead of discovering the installed hosts:

```bash
mcp-scan list --config path/to/claude_desktop_config.json
```

Scan those same servers for security risks:

```bash
mcp-scan scan
mcp-scan scan --config path/to/claude_desktop_config.json
```

Every detection rule runs against every server found, and the findings are reported worst-first, grouped under the server each one fired on:

```
─ Findings ─────────────────────────────────────────────────────────────────

installer  claude-desktop  ~/Library/Application Support/Claude/claude_desktop_config.json

  CRITICAL  remote-code-execution
  the launch command downloads code and pipes it straight into an interpreter;
  the server runs whatever the remote host serves at that moment

  WARN      broad-filesystem-access
  the server is given '/', which is the entire filesystem; grant it the
  directories it works in instead, one by one ('~/code/my-app')
```

A rule that fails is reported as a warning; it never takes the scan down with it.

### Sharing the result

```bash
mcp-scan scan --output report.md      # readable, and rendered by GitHub
mcp-scan scan --output report.json    # stable, for whatever reads it next
```

The extension picks the format. The markdown is written for someone who was not at the keyboard: the summary, a table of findings, and a **Recommendations** section saying what to actually do about each rule that fired — once per rule, however many servers tripped it. The JSON carries the same facts under a `schema_version`, including the exit code, so a consumer never has to re-derive the verdict or parse a word of the terminal output.

Neither format contains a credential value. Both say plainly when the scan did not complete, so a report cannot be mistaken for a clean bill of health that nobody actually gave.

`mcp-scan` will refuse to write a report over a config file it just read — `--output ~/.claude.json` is one keystroke away, and a scanner that eats the configuration it was pointed at is worse than no scanner at all.

### In a script, or in CI

`scan` ends with a one-line summary — `3 findings in 2 servers: 1 CRITICAL, 2 WARN.` — and returns the worst thing it found:

| Exit code | Meaning |
| --- | --- |
| `0` | Nothing worse than an `INFO` finding. An `INFO` is worth telling you about, not worth failing your build over. |
| `1` | The worst finding is a `WARN`. |
| `2` | A `CRITICAL` was found. |
| `3` | The run did not complete, so it has no verdict to give: a config would not parse, a rule crashed, or `--output` could not be written. |
| `64` | The command was misused — an unknown flag, a missing value, a command that does not exist. This is `EX_USAGE`, kept off the verdict codes so a typo can never read as a finding. |

So a pipeline can gate on the verdict without reading a word of the output:

```bash
mcp-scan scan --quiet || echo "MCP config needs attention"
```

`--quiet` (`-q`) drops the findings and prints the summary line alone. It does *not* silence warnings — a config that could not be parsed, or a rule that crashed, still says so. A warning is not a risk it found; it is a risk it failed to look for, and that is the last thing a CI run should swallow.

Which is also why a warning exits `3`, and why `3` outranks even a `CRITICAL`. Codes `0`, `1` and `2` are verdicts: each says *I checked everything, and the worst of it was this*. A run that could not read one of your configs, or whose rule crashed, cannot honestly say that at any severity — and the dangerous version of the lie is `0`, where a build passes green not because your config is safe but because nobody ever looked at it. `3` says the one thing that is true: **the result is unknown, go and look.** Nothing is hidden behind it — every finding the scan did manage to make is still reported in full.

A CI job that wants the detail as well as the verdict can have both:

```bash
mcp-scan scan --quiet --output report.json
case $? in
  0) echo "clean" ;;
  1|2) echo "risks found — see report.json" ;;
  3) echo "the scan did not complete — do not trust this run" ;;
esac
```

### What it detects

| Rule | Severity | What it flags |
| --- | --- | --- |
| `static-credential-in-args` | CRITICAL | A credential passed inline on a server's command line — `--api-key=sk-…`, `GITHUB_TOKEN=ghp_…`, `Authorization: Bearer …`. On top of sitting in the config file, it is visible in the process table to every other process running as you. |
| `static-credential-in-url` | CRITICAL | A credential in a remote server's URL — `?api_key=sk-…`, or the `user:password@` before the host. On top of sitting in the config file, it travels: out in the request line, into the access log at the far end, and into wherever the URL gets pasted. |
| `static-credential-in-env` | WARN | A credential hardcoded as the value of an `env` entry, e.g. `"GITHUB_TOKEN": "ghp_…"`. |

The fix for both is to keep the value in your environment (or a secret manager) and have the config reference it — `"GITHUB_TOKEN": "${GITHUB_TOKEN}"`. A config that already does is not flagged.

A finding tells you *where* the credential is — which variable, which argument — and never what it is. The value is not printed, stored or logged, by any command.

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
