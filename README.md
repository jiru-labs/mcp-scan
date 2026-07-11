# mcp-audit

[![CI](https://github.com/jiru-labs/mcp-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/jiru-labs/mcp-audit/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Security scanner for local MCP (Model Context Protocol) configurations.

`mcp-audit` reads the MCP config files on your machine — Claude Desktop, Claude Code, Cursor, VS Code, Windsurf — and reports what the configuration itself gives away: credentials written into it in plain text, servers reached in the clear, launch commands that download and run remote code or resolve a package name anyone could claim, and servers handed a whole filesystem or an unrestricted shell.

It reads the configuration, not the servers. A tool's *description* — where a tool-poisoning payload actually hides, as an instruction to the agent that the user never sees — is served by the running server, not written in the config file, so no rule here reads one. What the rules flag instead are the conditions that let a payload be planted, and the permissions that decide how much it could take: a plaintext transport an attacker can rewrite descriptions over, a launch command whose code can change under you between one run and the next, and a server given far more of your machine than its job needs. That is a narrower claim than "detects tool poisoning", and it is the true one.

It is built for individual developers and small teams who don't have enterprise security tooling.

**Local-first. Read-only by default. Zero telemetry.** The scanner never modifies your files, never makes network calls while scanning, and never logs credential values — only that a credential exists and where.

## Install

```bash
pipx install git+https://github.com/jiru-labs/mcp-audit
```

There is no PyPI release yet, so install from source for now. Once `0.1.0` is
published, `pipx install mcp-audit` is all it takes.

## Usage

List the MCP servers declared in the host configs found on your machine, grouped by the host that declares them:

```bash
mcp-audit list
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

No credential is ever printed. Environment variables are listed by name only — `mcp-audit` never reads, prints or stores their values — and a credential written into a command line or a URL is masked where the endpoint is shown: `npx server --api-key=***`, `https://mcp.example.com/sse?api_key=***`. A value referenced from the environment, `--api-key=${API_KEY}`, is left readable: it is the fix, not the leak.

To inspect one config file instead of discovering the installed hosts:

```bash
mcp-audit list --config path/to/claude_desktop_config.json
```

Scan those same servers for security risks:

```bash
mcp-audit scan
mcp-audit scan --config path/to/claude_desktop_config.json
```

Every detection rule runs against every server found, and the findings are reported worst-first, grouped under the server each one fired on. The heading says where the server is declared, down to the line, so the fix is one click away in most terminals:

```
─ Findings ─────────────────────────────────────────────────────────────────

installer  claude-desktop
~/Library/Application Support/Claude/claude_desktop_config.json:12

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
mcp-audit scan --output report.md        # readable, and rendered by GitHub
mcp-audit scan --output report.json      # stable, for whatever reads it next
mcp-audit scan --output results.sarif    # for a CI security dashboard
```

The extension picks the format. The markdown is written for someone who was not at the keyboard: the summary, a table of findings, and a **Recommendations** section saying what to actually do about each rule that fired — once per rule, however many servers tripped it. The JSON carries the same facts under a `schema_version`, including the exit code, so a consumer never has to re-derive the verdict or parse a word of the terminal output.

No format contains a credential value. Each says plainly when the scan did not complete, so a report cannot be mistaken for a clean bill of health that nobody actually gave.

`mcp-audit` will refuse to write a report over a config file it just read — `--output ~/.claude.json` is one keystroke away, and a scanner that eats the configuration it was pointed at is worse than no scanner at all.

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
mcp-audit scan --quiet || echo "MCP config needs attention"
```

`--quiet` (`-q`) drops the findings and prints the summary line alone. It does *not* silence warnings — a config that could not be parsed, or a rule that crashed, still says so. A warning is not a risk it found; it is a risk it failed to look for, and that is the last thing a CI run should swallow.

Which is also why a warning exits `3`, and why `3` outranks even a `CRITICAL`. Codes `0`, `1` and `2` are verdicts: each says *I checked everything, and the worst of it was this*. A run that could not read one of your configs, or whose rule crashed, cannot honestly say that at any severity — and the dangerous version of the lie is `0`, where a build passes green not because your config is safe but because nobody ever looked at it. `3` says the one thing that is true: **the result is unknown, go and look.** Nothing is hidden behind it — every finding the scan did manage to make is still reported in full.

A CI job that wants the detail as well as the verdict can have both:

```bash
mcp-audit scan --quiet --output report.json
case $? in
  0) echo "clean" ;;
  1|2) echo "risks found — see report.json" ;;
  3) echo "the scan did not complete — do not trust this run" ;;
esac
```

### GitHub code scanning

`--output results.sarif` writes [SARIF](https://sarifweb.azurewebsites.net/), which is what GitHub code scanning, GitLab and most CI security dashboards read. Upload it and each finding becomes an alert in the **Security** tab — tagged as a security alert and ranked, with the rule's remediation as its help text — instead of scrolling past in a job log nobody opens:

```yaml
- run: mcp-audit scan --output results.sarif
  continue-on-error: true          # let the upload run; the alerts are the gate
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

`CRITICAL` maps to SARIF's `error`, `WARN` to `warning`, `INFO` to `note`. A project-scoped config — `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json` — is located relative to the repository, so its alerts land on the line of the pull request that declares the offending server, not on the top of the file: with four servers in one config, the alert is on the one that tripped the rule. A config outside the repository, like `~/.claude.json`, is reported with an absolute path: the alert still names the server, the rule, the file and the line, but GitHub has no diff of yours to pin it to, because the file is not in it.

A scan that did not complete says so in the SARIF too (`invocations[0].executionSuccessful` is `false`, with each warning alongside it), so an upload can never quietly turn a config nobody read into a repository with no alerts.

`.sarif.json` works as well as `.sarif`, since GitHub's own documentation uses both.

### What it detects

Nine rules, every one of them reading the server definition — the command, the arguments, the URL, the `env` keys — and nothing else.

**Credentials written into the config**

| Rule | Severity | What it flags |
| --- | --- | --- |
| `static-credential-in-args` | CRITICAL | A credential passed inline on a server's command line — `--api-key=sk-…`, `GITHUB_TOKEN=ghp_…`, `Authorization: Bearer …`. On top of sitting in the config file, it is visible in the process table to every other process running as you. |
| `static-credential-in-url` | CRITICAL | A credential in a remote server's URL — `?api_key=sk-…`, or the `user:password@` before the host. On top of sitting in the config file, it travels: out in the request line, into the access log at the far end, and into wherever the URL gets pasted. |
| `static-credential-in-env` | WARN | A credential hardcoded as the value of an `env` entry, e.g. `"GITHUB_TOKEN": "ghp_…"`. |

The fix for all three is to keep the value in your environment (or a secret manager) and have the config reference it — `"GITHUB_TOKEN": "${GITHUB_TOKEN}"`. A config that already does is not flagged.

A finding tells you *where* the credential is — which variable, which argument — and never what it is. The value is not printed, stored or logged, by any command.

**How the server is launched, and how it is reached**

| Rule | Severity | What it flags |
| --- | --- | --- |
| `remote-code-execution` | CRITICAL | The launch command downloads code and runs it unseen (`curl … \| sh`). The server is then whatever the remote host served at that moment, which you never reviewed and cannot pin. |
| `insecure-transport` | CRITICAL | The server is reached over plain `http://`. The traffic carries your credentials, and it carries the tool descriptions your agent acts on — so anyone on the network path can not only read it but rewrite it. A loopback address is the one fair exception, and is not flagged. |
| `executable-in-temp-dir` | WARN | The binary or script being executed sits in a world-writable directory, where any other process can replace it between launches without the config changing a character. |
| `unscoped-package` | WARN | The command resolves an unscoped, unpinned package from a registry at every launch (`npx some-server`). The name belongs to whoever currently claims it, and the code behind it is whatever was published most recently. |

**What the server is given**

| Rule | Severity | What it flags |
| --- | --- | --- |
| `broad-filesystem-access` | WARN | The server is pointed at a whole filesystem, a home directory or an entire disk. That scope is the scope an attacker gets: a home directory holds your SSH keys, your browser profile and your `.env` files. |
| `unrestricted-shell-access` | WARN | The server runs whatever command the agent composes, with your privileges — so a prompt injection in anything the agent reads becomes code execution on your machine. |

The last two are the ones that decide how much a *successful* attack costs you, which is why they fire on servers that are otherwise perfectly legitimate. They are a statement about blast radius, not an accusation.

More rules are landing — see the [open issues](https://github.com/jiru-labs/mcp-audit/issues). Adding one is adding a file: drop a `Rule` subclass into `mcp_audit/rules/`, give it an `id`, a `title` and a `severity` of `INFO`, `WARN` or `CRITICAL`, and the engine picks it up.

Print the version:

```bash
mcp-audit version
```

## Development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## Contributing

Bug reports, false positives, missing hosts and new rules are all welcome — and
a new rule is genuinely one file, which the engine discovers on its own.
[CONTRIBUTING.md](CONTRIBUTING.md) shows the shape of one and the four things it
has to respect.

Found a security problem **in the scanner itself** — a credential value that
leaked into the output, a network call in the default scan? Don't open a public
issue. [SECURITY.md](SECURITY.md) says how to report it privately, and spells
out the promises the tool is held to.

## License

[MIT](LICENSE).
