"""Tests for the CLI entrypoint."""

from pathlib import Path

import pytest
from conftest import InstalledHosts
from rich.console import Console
from typer.testing import CliRunner

from mcp_scan import __version__, cli
from mcp_scan.cli import app
from mcp_scan.discovery import (
    HOST_CLAUDE_CODE,
    HOST_CLAUDE_DESKTOP,
    HOST_CURSOR,
    ConfigLocation,
    find_all_configs,
)
from mcp_scan.parsers import MCPServer
from mcp_scan.rules import Finding, Rule, Severity

runner = CliRunner()


class FlagsEveryServer(Rule):
    """A dummy rule, standing in for the real ones until they land."""

    id = "test-critical"
    title = "Test rule that flags everything"
    severity = Severity.CRITICAL

    def check(self, server: MCPServer) -> list[Finding]:
        return [self.finding(server, f"{server.name} was flagged")]


class FlagsRemoteServers(Rule):
    """A dummy rule of a lesser severity, to check the ordering."""

    id = "test-info"
    title = "Test rule that flags remote servers"
    severity = Severity.INFO

    def check(self, server: MCPServer) -> list[Finding]:
        return [self.finding(server)] if server.url else []


class FlagsNothing(Rule):
    """A dummy rule that leaves every server alone."""

    id = "test-clean"
    title = "Test rule that flags nothing"
    severity = Severity.WARN

    def check(self, server: MCPServer) -> list[Finding]:
        return []


class BrokenRule(Rule):
    """A dummy rule with a bug in it."""

    id = "test-broken"
    title = "Test rule that raises"
    severity = Severity.WARN

    def check(self, server: MCPServer) -> list[Finding]:
        raise RuntimeError("boom")


@pytest.fixture(autouse=True)
def wide_console(monkeypatch: pytest.MonkeyPatch) -> None:
    """Render tables wide enough that assertions see unwrapped cell text."""
    monkeypatch.setattr(cli, "console", Console(width=200, no_color=True))


def _pretend_hosts_installed_at(
    monkeypatch: pytest.MonkeyPatch, home: Path, project_dir: Path
) -> None:
    """Make discovery look for host configs under `home` and `project_dir`."""
    monkeypatch.setattr(
        cli,
        "find_all_configs",
        lambda: find_all_configs(home=home, project_dir=project_dir),
    )


def _pretend_only_claude_desktop_config_at(
    monkeypatch: pytest.MonkeyPatch, path: Path
) -> None:
    """Make discovery report Claude Desktop as the only host, living at `path`."""
    location = ConfigLocation(
        host=HOST_CLAUDE_DESKTOP, path=path, exists=path.is_file()
    )
    monkeypatch.setattr(cli, "find_all_configs", lambda: [location])


def _pretend_rules_are(monkeypatch: pytest.MonkeyPatch, *rules: Rule) -> None:
    """Make `scan` run these rules instead of the ones shipped in the package."""
    monkeypatch.setattr(cli, "load_rules", lambda: list(rules))


def test_version_command_prints_version() -> None:
    result = runner.invoke(app, ["version"])

    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_no_args_shows_help() -> None:
    result = runner.invoke(app, [])

    assert result.exit_code != 0
    assert "version" in result.stdout


def test_list_shows_a_table_of_servers_from_a_config(sample_config: Path) -> None:
    result = runner.invoke(app, ["list", "--config", str(sample_config)])

    assert result.exit_code == 0
    assert "MCP servers" in result.stdout
    assert "filesystem" in result.stdout
    assert "github" in result.stdout
    assert "remote-notes" in result.stdout
    assert "https://notes.example.com/mcp" in result.stdout


def test_list_shows_env_var_keys_but_never_their_values(
    sample_config: Path, sample_secrets: list[str]
) -> None:
    result = runner.invoke(app, ["list", "--config", str(sample_config)])

    assert "GITHUB_PERSONAL_ACCESS_TOKEN" in result.stdout
    assert "NOTES_API_KEY" in result.stdout
    assert sample_secrets  # the fixture must actually carry secrets to test
    for secret in sample_secrets:
        assert secret not in result.stdout


def test_list_warns_on_malformed_config_without_crashing(
    malformed_config: Path,
) -> None:
    result = runner.invoke(app, ["list", "--config", str(malformed_config)])

    assert result.exit_code == 0
    assert result.exception is None
    assert "malformed JSON" in result.stdout


def test_list_discovers_installed_hosts_when_no_config_given(
    monkeypatch: pytest.MonkeyPatch, sample_config: Path
) -> None:
    _pretend_only_claude_desktop_config_at(monkeypatch, sample_config)

    result = runner.invoke(app, ["list"])

    assert result.exit_code == 0
    assert "filesystem" in result.stdout


def test_list_reports_when_no_config_is_found(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _pretend_only_claude_desktop_config_at(monkeypatch, tmp_path / "missing.json")

    result = runner.invoke(app, ["list"])

    assert result.exit_code == 0
    assert "No MCP config files found." in result.stdout


def test_list_reports_a_config_that_declares_no_servers(tmp_path: Path) -> None:
    empty = tmp_path / "empty.json"
    empty.write_text("{}", encoding="utf-8")

    result = runner.invoke(app, ["list", "--config", str(empty)])

    assert result.exit_code == 0
    assert "No MCP servers" in result.stdout


def test_list_shows_servers_from_every_installed_host(
    monkeypatch: pytest.MonkeyPatch, installed_hosts: InstalledHosts
) -> None:
    _pretend_hosts_installed_at(
        monkeypatch, installed_hosts.home, installed_hosts.project_dir
    )

    result = runner.invoke(app, ["list"])

    assert result.exit_code == 0
    # One server from each of the four configs.
    assert "filesystem" in result.stdout  # Claude Desktop
    assert "linear" in result.stdout  # Claude Code, user scope
    assert "project-db" in result.stdout  # Claude Code, project scope
    assert "cursor-search" in result.stdout  # Cursor


def test_list_groups_servers_under_the_host_that_declares_them(
    monkeypatch: pytest.MonkeyPatch, installed_hosts: InstalledHosts
) -> None:
    _pretend_hosts_installed_at(
        monkeypatch, installed_hosts.home, installed_hosts.project_dir
    )

    result = runner.invoke(app, ["list"])

    assert result.exit_code == 0

    # Each host labels its own group, and its servers follow it — including
    # Claude Code's two configs, which fall under a single claude-code group.
    rows = result.stdout
    order = [
        HOST_CLAUDE_DESKTOP,
        "filesystem",
        HOST_CLAUDE_CODE,
        "linear",
        "project-db",
        HOST_CURSOR,
        "cursor-search",
    ]
    positions = [rows.index(text) for text in order]
    assert positions == sorted(positions), rows


def test_list_abbreviates_config_paths_under_the_home_directory(
    monkeypatch: pytest.MonkeyPatch, installed_hosts: InstalledHosts
) -> None:
    _pretend_hosts_installed_at(
        monkeypatch, installed_hosts.home, installed_hosts.project_dir
    )
    monkeypatch.setattr(cli.Path, "home", classmethod(lambda cls: installed_hosts.home))

    result = runner.invoke(app, ["list"])

    assert "~/.cursor/mcp.json" in result.stdout
    assert str(installed_hosts.home) not in result.stdout


def test_display_path_abbreviates_only_paths_under_home(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    home = tmp_path / "home"
    monkeypatch.setattr(cli.Path, "home", classmethod(lambda cls: home))

    assert cli._display_path(home / ".cursor" / "mcp.json") == "~/.cursor/mcp.json"
    # A config outside home — a project's .mcp.json — keeps its full path.
    outside = tmp_path / "work" / "repo" / ".mcp.json"
    assert cli._display_path(outside) == str(outside)


def test_list_never_prints_a_credential_from_any_host(
    monkeypatch: pytest.MonkeyPatch, installed_hosts: InstalledHosts
) -> None:
    _pretend_hosts_installed_at(
        monkeypatch, installed_hosts.home, installed_hosts.project_dir
    )

    result = runner.invoke(app, ["list"])

    assert installed_hosts.secrets  # the fixtures must actually carry secrets
    for secret in installed_hosts.secrets:
        assert secret not in result.stdout
    # The keys, however, are exactly what the user needs to see.
    assert "LINEAR_API_KEY" in result.stdout
    assert "DATABASE_URL" in result.stdout


def test_scan_shows_a_table_of_findings(
    monkeypatch: pytest.MonkeyPatch, sample_config: Path
) -> None:
    _pretend_rules_are(monkeypatch, FlagsEveryServer())

    result = runner.invoke(app, ["scan", "--config", str(sample_config)])

    assert result.exit_code == 0
    assert "Findings" in result.stdout
    assert "CRITICAL" in result.stdout
    assert "test-critical" in result.stdout
    # Every server in the config was checked, and its finding names it.
    for server in ("filesystem", "github", "remote-notes"):
        assert f"{server} was flagged" in result.stdout


def test_scan_sorts_findings_worst_first(
    monkeypatch: pytest.MonkeyPatch, sample_config: Path
) -> None:
    _pretend_rules_are(monkeypatch, FlagsRemoteServers(), FlagsEveryServer())

    result = runner.invoke(app, ["scan", "--config", str(sample_config)])

    assert result.exit_code == 0
    # The lone INFO finding lands below every CRITICAL one, whatever order the
    # rules ran in.
    assert result.stdout.index("CRITICAL") < result.stdout.index("INFO")
    assert result.stdout.rindex("CRITICAL") < result.stdout.index("INFO")


def test_scan_reports_a_clean_config(
    monkeypatch: pytest.MonkeyPatch, sample_config: Path
) -> None:
    _pretend_rules_are(monkeypatch, FlagsNothing())

    result = runner.invoke(app, ["scan", "--config", str(sample_config)])

    assert result.exit_code == 0
    assert "No findings in 3 servers." in result.stdout


def test_scan_discovers_installed_hosts_when_no_config_given(
    monkeypatch: pytest.MonkeyPatch, installed_hosts: InstalledHosts
) -> None:
    _pretend_hosts_installed_at(
        monkeypatch, installed_hosts.home, installed_hosts.project_dir
    )
    _pretend_rules_are(monkeypatch, FlagsEveryServer())

    result = runner.invoke(app, ["scan"])

    assert result.exit_code == 0
    # A finding for a server of every host, each naming the host it came from.
    assert "cursor-search was flagged" in result.stdout
    assert HOST_CURSOR in result.stdout
    assert "project-db was flagged" in result.stdout
    assert HOST_CLAUDE_CODE in result.stdout


def test_scan_reports_when_no_config_is_found(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _pretend_only_claude_desktop_config_at(monkeypatch, tmp_path / "missing.json")
    _pretend_rules_are(monkeypatch, FlagsEveryServer())

    result = runner.invoke(app, ["scan"])

    assert result.exit_code == 0
    assert "No MCP config files found." in result.stdout


def test_scan_warns_on_malformed_config_without_crashing(
    monkeypatch: pytest.MonkeyPatch, malformed_config: Path
) -> None:
    _pretend_rules_are(monkeypatch, FlagsEveryServer())

    result = runner.invoke(app, ["scan", "--config", str(malformed_config)])

    assert result.exit_code == 0
    assert result.exception is None
    assert "malformed JSON" in result.stdout


def test_scan_warns_about_a_broken_rule_and_keeps_scanning(
    monkeypatch: pytest.MonkeyPatch, sample_config: Path
) -> None:
    _pretend_rules_are(monkeypatch, BrokenRule(), FlagsEveryServer())

    result = runner.invoke(app, ["scan", "--config", str(sample_config)])

    assert result.exit_code == 0
    assert result.exception is None
    assert "test-broken" in result.stdout
    # The healthy rule still reported.
    assert "filesystem was flagged" in result.stdout


def test_list_renders_a_server_name_that_looks_like_console_markup(
    markup_config: Path,
) -> None:
    """A hostile server name is printed literally, not parsed as Rich markup."""
    result = runner.invoke(app, ["list", "--config", str(markup_config)])

    assert result.exit_code == 0
    assert result.exception is None
    assert "evil [/bold]" in result.stdout


def test_scan_renders_a_server_name_that_looks_like_console_markup(
    monkeypatch: pytest.MonkeyPatch, markup_config: Path
) -> None:
    _pretend_rules_are(monkeypatch, FlagsEveryServer())

    result = runner.invoke(app, ["scan", "--config", str(markup_config)])

    assert result.exit_code == 0
    assert result.exception is None
    # The name survives into the finding the rule built from it.
    assert "evil [/bold] was flagged" in result.stdout


def test_scan_never_prints_a_credential(
    monkeypatch: pytest.MonkeyPatch, sample_config: Path, sample_secrets: list[str]
) -> None:
    _pretend_rules_are(monkeypatch, FlagsEveryServer())

    result = runner.invoke(app, ["scan", "--config", str(sample_config)])

    assert sample_secrets  # the fixture must actually carry secrets to test
    for secret in sample_secrets:
        assert secret not in result.stdout
