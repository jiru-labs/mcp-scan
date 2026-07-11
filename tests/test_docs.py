"""Hold the documentation to what the code actually does.

The README is the only description of `mcp-audit` most people will ever read, and
a security tool that overstates what it detects is worse than one that says
nothing: the user stops looking for what it told them it had already checked.

That is not hypothetical here. The README claimed detection of "tool poisoning
patterns in tool descriptions" — which no rule has ever done, because a tool's
description is served by a running server and is not in the config file — and it
documented three rules while nine were running. Both went unnoticed for as long
as nothing but a reader was checking.

So the rule table is pinned to the rule registry. A new rule that does not appear
in the README fails the suite, and so does a README row for a rule that does not
exist.
"""

import ast
import re
from pathlib import Path

from mcp_audit.rules import load_rules

README = Path(__file__).parent.parent / "README.md"

#: A row of one of the README's rule tables: `| \`rule-id\` | WARN | … |`.
_RULE_ROW = re.compile(r"^\|\s*`([a-z-]+)`\s*\|\s*(CRITICAL|WARN|INFO)\s*\|", re.MULTILINE)


def _documented_rules() -> dict[str, str]:
    """Every rule the README says it has, and the severity it gives it."""
    return {
        rule_id: severity
        for rule_id, severity in _RULE_ROW.findall(README.read_text(encoding="utf-8"))
    }


def test_the_readme_documents_every_rule_that_runs() -> None:
    """A rule nobody was told about is a rule nobody acts on."""
    documented = _documented_rules()
    implemented = {rule.id for rule in load_rules()}

    assert documented, "the README's rule tables did not parse at all"
    assert set(documented) == implemented


def test_the_readme_gives_each_rule_the_severity_it_actually_has() -> None:
    """A WARN documented as CRITICAL is a promise the exit code will not keep."""
    documented = _documented_rules()

    for rule in load_rules():
        assert documented[rule.id] == str(rule.severity), rule.id


def test_nothing_in_the_scanner_can_reach_the_network_or_start_a_process() -> None:
    """The promise under both claims, held to the imports that would break it.

    A tool description only exists once a server is running, and a package only
    resolves if you ask a registry — so `mcp-audit` cannot be reading either while
    it has no way to open a socket or spawn a child. That is what makes "reads the
    configuration, not the servers" a fact about the code rather than a claim in a
    README, and it is what the READMEs's "never makes network calls while scanning"
    line is worth.

    When an opt-in `--live` or `--check-registry` lands (see CLAUDE.md's
    network-call policy), this test is the tripwire it has to walk through on
    purpose: allow the module the flag gates, and nothing else. It must never be
    deleted to make an import go green.
    """
    # Transports and process spawning. `urllib.parse` is deliberately absent: it
    # splits a string into a scheme and a host and opens nothing, which is exactly
    # what `insecure-transport` needs to tell `http://` from `https://` without
    # ever going there.
    forbidden = (
        "aiohttp",
        "asyncio",
        "ftplib",
        "http.client",
        "httpx",
        "multiprocessing",
        "requests",
        "socket",
        "ssl",
        "subprocess",
        "urllib.error",
        "urllib.request",
    )

    offenders = {}
    for source in (Path(__file__).parent.parent / "mcp_audit").rglob("*.py"):
        imported = _imported_modules(ast.parse(source.read_text(encoding="utf-8")))
        reached = sorted(
            module
            for module in imported
            if any(module == name or module.startswith(f"{name}.") for name in forbidden)
        )
        if reached:
            offenders[source.name] = reached

    assert offenders == {}


def _imported_modules(tree: ast.AST) -> set[str]:
    """Every module a source file imports, by its full dotted name."""
    modules = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module)
    return modules
