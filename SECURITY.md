# Security policy

`mcp-audit` reads security-sensitive files — your MCP configs, which hold your
API keys — so a bug in it can hurt you in ways an ordinary CLI bug cannot. This
page says how to report one, and what counts as one.

## Reporting a vulnerability

**Do not open a public issue.** Use GitHub's private vulnerability reporting —
the **Report a vulnerability** button under this repository's
[Security tab](https://github.com/jiru-labs/mcp-audit/security/advisories/new) —
or email <llorens.p@proton.me>.

Please include what you did, what happened, and what you expected instead. A
config that reproduces it is the most useful thing you can send — **with the
credential values replaced by fakes.** Never send a real key, to us or to
anyone.

This is a small project maintained in spare time. Expect an acknowledgement
within a week. Once a fix is out, you get the credit unless you'd rather not.

## What counts as a vulnerability

The promises below are the ones the tool is built on. Anything that breaks one
is a vulnerability, not a bug:

- **No credential value is ever printed, written or logged.** A finding says
  *which* argument or variable holds a key, never what the key is. If any
  command, any output format (terminal, markdown, JSON, SARIF) or any error
  message ever reveals a credential value, that is the most serious report you
  can send.
- **The default scan makes no network call and starts no process.** It reads
  files and nothing else. Anything that sends your configuration, your findings
  or a telemetry ping anywhere breaks the core promise. (The planned `--live`
  and `--check-registry` flags will make network calls *because you asked them
  to*, and are opt-in for exactly this reason. A credential must never leave the
  machine even then.)
- **The scanner never modifies your files.** It is read-only, apart from the
  report `--output` writes to the path you name.
- **A malicious config cannot take over the scanner.** It is pointed at files an
  attacker may have written, so a config that achieves code execution, path
  traversal, or a write outside `--output` is in scope.

## What is not a vulnerability

- **A finding about your own config.** If `mcp-audit` reports a hardcoded key or
  a `curl | sh` launch command, it is working: the risk is in your config, and
  the finding tells you how to fix it.
- **A rule that misses something.** A false negative is a gap in coverage —
  valuable, and very welcome as a normal
  [issue](https://github.com/jiru-labs/mcp-audit/issues) or a new rule.
- **A false positive.** Same: open a normal issue with the config that trips it.

## Supported versions

The latest release is the supported one. Until `1.0`, fixes land on `main` and
ship in the next release.
