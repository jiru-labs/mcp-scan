"""Tests for the rule engine."""

import importlib
from pathlib import Path

import pytest

from mcp_config_audit.parsers import MCPServer
from mcp_config_audit.rules import Finding, Rule, Severity, load_rules, run_rules


class AlwaysFires(Rule):
    """A rule that flags every server it sees."""

    id = "always-fires"
    title = "Server exists"
    severity = Severity.CRITICAL

    def check(self, server: MCPServer) -> list[Finding]:
        return [self.finding(server, f"{server.name} was checked")]


class NeverFires(Rule):
    """A rule that flags nothing — the common case for a clean server."""

    id = "never-fires"
    title = "Server is fine"
    severity = Severity.INFO

    def check(self, server: MCPServer) -> list[Finding]:
        return []


class WarnsOnRemote(Rule):
    """A rule that flags only some servers."""

    id = "warns-on-remote"
    title = "Server is remote"
    severity = Severity.WARN

    def check(self, server: MCPServer) -> list[Finding]:
        return [self.finding(server)] if server.url else []


class Explodes(Rule):
    """A rule with a bug in it."""

    id = "explodes"
    title = "Rule that raises"
    severity = Severity.INFO

    def check(self, server: MCPServer) -> list[Finding]:
        raise RuntimeError("boom")


def _server(name: str, url: str | None = None) -> MCPServer:
    return MCPServer(name=name, source=Path("/tmp/config.json"), host="cursor", url=url)


def test_severities_are_ordered_from_least_to_most_serious() -> None:
    assert Severity.INFO < Severity.WARN < Severity.CRITICAL


def test_a_rule_stamps_its_identity_on_the_findings_it_builds() -> None:
    server = _server("filesystem")

    finding = AlwaysFires().check(server)[0]

    assert finding.rule_id == "always-fires"
    assert finding.title == "Server exists"
    assert finding.severity is Severity.CRITICAL
    assert finding.server is server
    assert finding.message == "filesystem was checked"


def test_a_finding_without_a_message_falls_back_to_the_rule_title() -> None:
    finding = WarnsOnRemote().check(_server("notes", url="https://notes.example.com"))[0]

    assert finding.message == "Server is remote"


def test_a_rule_must_declare_an_id_and_a_title() -> None:
    with pytest.raises(ValueError, match="id and a title"):

        class Nameless(Rule):
            def check(self, server: MCPServer) -> list[Finding]:
                return []


def test_run_rules_checks_every_server_against_every_rule() -> None:
    servers = [_server("filesystem"), _server("notes", url="https://notes.example.com")]

    result = run_rules(servers, [AlwaysFires(), NeverFires(), WarnsOnRemote()])

    assert [(f.rule_id, f.server.name) for f in result.findings] == [
        ("always-fires", "filesystem"),
        ("always-fires", "notes"),
        ("warns-on-remote", "notes"),
    ]


def test_run_rules_sorts_findings_worst_first() -> None:
    servers = [_server("notes", url="https://notes.example.com")]

    result = run_rules(servers, [WarnsOnRemote(), AlwaysFires()])

    assert [f.severity for f in result.findings] == [Severity.CRITICAL, Severity.WARN]


def test_run_rules_reports_nothing_for_a_clean_server() -> None:
    result = run_rules([_server("filesystem")], [NeverFires()])

    assert result.findings == []
    assert result.warnings == []


def test_run_rules_reports_no_findings_when_there_are_no_servers() -> None:
    result = run_rules([], [AlwaysFires()])

    assert result.findings == []


def test_a_rule_that_raises_becomes_a_warning_and_the_scan_continues() -> None:
    result = run_rules([_server("filesystem")], [Explodes(), AlwaysFires()])

    assert len(result.warnings) == 1
    assert "explodes" in result.warnings[0]
    assert "filesystem" in result.warnings[0]
    # The healthy rule still ran.
    assert [f.rule_id for f in result.findings] == ["always-fires"]


def _write_rules_package(root: Path, name: str, modules: dict[str, str]) -> None:
    """Write an importable rules package under `root`."""
    package = root / name
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    for module_name, source in modules.items():
        (package / f"{module_name}.py").write_text(source, encoding="utf-8")


RULE_MODULE = """
from mcp_config_audit.rules import Finding, Rule, Severity


class {class_name}(Rule):
    id = "{rule_id}"
    title = "A rule in its own file"
    severity = Severity.WARN

    def check(self, server) -> list[Finding]:
        return [self.finding(server)]
"""


def test_load_rules_discovers_a_rule_from_the_file_that_defines_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Adding a rule is adding a file: the engine finds it with no wiring."""
    _write_rules_package(
        tmp_path,
        "discovered_rules",
        {
            "zeta": RULE_MODULE.format(class_name="Zeta", rule_id="zeta"),
            "alpha": RULE_MODULE.format(class_name="Alpha", rule_id="alpha"),
        },
    )
    monkeypatch.syspath_prepend(tmp_path)

    rules = load_rules(importlib.import_module("discovered_rules"))

    # Both files found, and rules run in a stable order regardless of the order
    # the filesystem hands the modules over in.
    assert [rule.id for rule in rules] == ["alpha", "zeta"]


def test_load_rules_ignores_a_module_that_defines_no_rule(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A helper module in the package — or an import of Rule itself — is not a rule."""
    _write_rules_package(
        tmp_path,
        "helper_rules",
        {
            "helpers": "from mcp_config_audit.rules import Rule, Severity\n\nSHARED = 1\n",
            "real": RULE_MODULE.format(class_name="Real", rule_id="real"),
        },
    )
    monkeypatch.syspath_prepend(tmp_path)

    rules = load_rules(importlib.import_module("helper_rules"))

    assert [rule.id for rule in rules] == ["real"]


def test_load_rules_on_the_shipped_package_returns_usable_rules() -> None:
    """Whatever rules ship today, they must all be instantiable and identified."""
    rules = load_rules()

    assert all(rule.id and rule.title for rule in rules)
    assert len({rule.id for rule in rules}) == len(rules), "rule ids must be unique"
