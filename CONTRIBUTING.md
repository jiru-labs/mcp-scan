# Contributing to mcp-config-audit

Thanks for looking. Bug reports, false positives, missing hosts and new rules
are all welcome.

Found a **security** problem in the tool itself? Don't open an issue — see
[SECURITY.md](SECURITY.md).

## Getting set up

```bash
git clone https://github.com/jiru-labs/mcp-config-audit
cd mcp-config-audit
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

Python 3.11 or newer. The only runtime dependencies are Typer and Rich, and the
project intends to keep it that way — a security tool people install to inspect
their machine should be something they can read in an afternoon.

## Adding a detection rule

This is the most useful contribution, and the cheapest: **a rule is one file.**
Drop a `Rule` subclass into `mcp_config_audit/rules/`, and the engine finds it — no
registry to edit, no import to add.

```python
from mcp_config_audit.parsers import MCPServer
from mcp_config_audit.rules.base import Finding, Rule, Severity


class MyRule(Rule):
    id = "my-rule"                    # stable, kebab-case
    title = "what the rule looks for, phrased as the problem"
    severity = Severity.WARN          # INFO, WARN or CRITICAL
    remediation = "what the user should actually go and do about it"

    def check(self, server: MCPServer) -> list[Finding]:
        if ...:
            return [self.finding(server, "what is wrong with *this* server")]
        return []
```

Four things a rule must respect:

1. **It reads the parsed `MCPServer` and nothing else.** No file, no network, no
   subprocess. `tests/test_docs.py` enforces this by walking the package's
   imports, and it fails the build if a socket or a `subprocess` ever appears.
2. **It never puts a credential value in a message.** Say *which* argument or
   variable holds the key. Never the key. Use the helpers in
   `mcp_config_audit/credentials.py` to redact anything derived from the config,
   including URLs.
3. **`message` is about this server; `remediation` is about the class of
   problem.** The message names the offending argument or path; the remediation
   is identical across every finding the rule makes, and the report groups by it.
4. **Severity is a promise about the exit code.** `CRITICAL` exits `2` and turns
   someone's CI red. Use it when the config is exploitable as written, not when
   it is merely untidy.

Then add it to the rule table in the README with the same id and severity —
`tests/test_docs.py` compares the table against the live rule registry, so a rule
that isn't documented (or is documented wrong) fails the suite. That is
deliberate: a security tool that overstates or understates what it checks is
worse than one that says nothing.

## Adding a host

`mcp_config_audit/discovery.py` locates config files per host; `mcp_config_audit/parsers.py`
reads each format. Note that hosts disagree about the top-level key — VS Code
uses `servers`, everyone else uses `mcpServers` — and the parser picks by host
rather than trying both, so a config parsed under the wrong host yields zero
servers instead of a silent, misleading "clean scan". Keep that property.

Include a fixture in `tests/fixtures/` and a discovery test that runs against a
fake home directory.

## Sending the change

- **Every change ships with tests.** `pytest` must be green before you push.
- One logical change per pull request.
- Commit messages in English: `feat: …`, `fix: …`, `test: …`, `docs: …`,
  `chore: …`.
- Code, comments and docs in English.
- Don't add a dependency without saying why in the pull request; the answer is
  usually no.

If you're unsure whether something is wanted, open an issue first and ask. That
is never wasted time.
