"""Tests for the CLI entrypoint."""

import json
import os
from pathlib import Path

import pytest
from conftest import InstalledHosts
from rich.console import Console
from typer.testing import CliRunner, Result

from mcp_scan import __version__, cli, report
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

# The contract `scan` owes a CI pipeline, written out rather than imported: a
# test that read these from the CLI would pass whatever the CLI decided to
# return.
EXIT_CLEAN = 0
EXIT_WARN = 1
EXIT_CRITICAL = 2
EXIT_INCOMPLETE = 3
EXIT_USAGE = 64


def _crashed(result: Result) -> bool:
    """True when the command died rather than exiting with a verdict.

    A non-zero exit is how `scan` *reports* a finding, and Click files the
    `SystemExit` that carried it under `result.exception`. Anything else there
    is a real crash.
    """
    return result.exception is not None and not isinstance(result.exception, SystemExit)


def _without_summary(output: str) -> str:
    """Everything `scan` printed above its summary line, which is always last."""
    return "\n".join(output.splitlines()[:-1])


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


class WarnsOnEveryServer(Rule):
    """A dummy rule whose worst word is a warning — the exit-1 case."""

    id = "test-warn"
    title = "Test rule that warns about everything"
    severity = Severity.WARN

    def check(self, server: MCPServer) -> list[Finding]:
        return [self.finding(server, f"{server.name} is questionable")]


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
    # A server from every scope of every host, including the two #14 added.
    assert "filesystem" in result.stdout  # Claude Desktop
    assert "linear" in result.stdout  # Claude Code, user scope
    assert "local-scoped-db" in result.stdout  # Claude Code, local scope
    assert "project-db" in result.stdout  # Claude Code, project scope
    assert "cursor-search" in result.stdout  # Cursor, global
    assert "cursor-project-tools" in result.stdout  # Cursor, project scope


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
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))

    assert report.display_path(home / ".cursor" / "mcp.json") == "~/.cursor/mcp.json"
    # A config outside home — a project's .mcp.json — keeps its full path.
    outside = tmp_path / "work" / "repo" / ".mcp.json"
    assert report.display_path(outside) == str(outside)


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


def test_list_masks_a_credential_passed_inline_in_the_command_args(
    credentials_config: Path, credentials_secrets: list[str]
) -> None:
    """The command line is what `list` is for — but not the secret in it."""
    result = runner.invoke(app, ["list", "--config", str(credentials_config)])

    assert result.exit_code == 0

    assert credentials_secrets  # the fixture must actually carry secrets to test
    for secret in credentials_secrets:
        assert secret not in result.stdout

    # Masked in place: the flag names what to go and fix, and the rest of the
    # command line is still there to recognise the server by.
    assert "--api-key=***" in result.stdout
    assert "@example/mcp-remote" in result.stdout
    assert "--verbose" in result.stdout


def test_list_leaves_a_credential_referenced_from_the_environment_readable(
    tmp_path: Path,
) -> None:
    """`${API_KEY}` is the fix. Masking it would hide the good news."""
    config = tmp_path / "referenced.json"
    config.write_text(
        '{"mcpServers": {"clean": {"command": "npx",'
        ' "args": ["server", "--api-key=${API_KEY}"]}}}',
        encoding="utf-8",
    )

    result = runner.invoke(app, ["list", "--config", str(config)])

    assert result.exit_code == 0
    assert "--api-key=${API_KEY}" in result.stdout


def test_scan_shows_the_findings(
    monkeypatch: pytest.MonkeyPatch, sample_config: Path
) -> None:
    _pretend_rules_are(monkeypatch, FlagsEveryServer())

    result = runner.invoke(app, ["scan", "--config", str(sample_config)])

    assert result.exit_code == EXIT_CRITICAL
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

    assert result.exit_code == EXIT_CRITICAL
    # The lone INFO finding lands below every CRITICAL one, whatever order the
    # rules ran in. The summary line names both severities, and sits below the
    # lot of them: the ordering under test is the table's.
    table = _without_summary(result.stdout)
    assert table.index("CRITICAL") < table.index("INFO")
    assert table.rindex("CRITICAL") < table.index("INFO")


def test_scan_reports_a_clean_config(
    monkeypatch: pytest.MonkeyPatch, sample_config: Path
) -> None:
    _pretend_rules_are(monkeypatch, FlagsNothing())

    result = runner.invoke(app, ["scan", "--config", str(sample_config)])

    assert result.exit_code == EXIT_CLEAN
    assert "No findings in 3 servers." in result.stdout


class TestExitCodes:
    """The verdict a script reads: the worst finding of the run, and nothing else.

    A pipeline gates on this without parsing a word of the output, so each code
    is asserted as the literal number `mcp-scan` promises.
    """

    def test_a_clean_scan_exits_0(
        self, monkeypatch: pytest.MonkeyPatch, sample_config: Path
    ) -> None:
        _pretend_rules_are(monkeypatch, FlagsNothing())

        result = runner.invoke(app, ["scan", "--config", str(sample_config)])

        assert result.exit_code == EXIT_CLEAN

    def test_a_warning_exits_1(
        self, monkeypatch: pytest.MonkeyPatch, sample_config: Path
    ) -> None:
        _pretend_rules_are(monkeypatch, WarnsOnEveryServer())

        result = runner.invoke(app, ["scan", "--config", str(sample_config)])

        assert result.exit_code == EXIT_WARN

    def test_a_critical_exits_2(
        self, monkeypatch: pytest.MonkeyPatch, sample_config: Path
    ) -> None:
        _pretend_rules_are(monkeypatch, FlagsEveryServer())

        result = runner.invoke(app, ["scan", "--config", str(sample_config)])

        assert result.exit_code == EXIT_CRITICAL

    def test_the_worst_finding_decides_the_code(
        self, monkeypatch: pytest.MonkeyPatch, sample_config: Path
    ) -> None:
        """A critical among warnings is still a critical."""
        _pretend_rules_are(
            monkeypatch, WarnsOnEveryServer(), FlagsRemoteServers(), FlagsEveryServer()
        )

        result = runner.invoke(app, ["scan", "--config", str(sample_config)])

        assert result.exit_code == EXIT_CRITICAL

    def test_info_findings_alone_exit_0(
        self, monkeypatch: pytest.MonkeyPatch, sample_config: Path
    ) -> None:
        """INFO is worth saying, not worth failing a build over."""
        _pretend_rules_are(monkeypatch, FlagsRemoteServers())

        result = runner.invoke(app, ["scan", "--config", str(sample_config)])

        assert result.exit_code == EXIT_CLEAN
        assert "INFO" in result.stdout

    def test_a_scan_with_nothing_to_scan_exits_0(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """No config is not a risk. The output says so; the exit code does not."""
        _pretend_only_claude_desktop_config_at(monkeypatch, tmp_path / "missing.json")
        _pretend_rules_are(monkeypatch, FlagsEveryServer())

        result = runner.invoke(app, ["scan"])

        assert result.exit_code == EXIT_CLEAN


class TestUsageErrors:
    """A misuse of the CLI must not read as a verdict about a config.

    Click exits 2 for a usage error, which is our CRITICAL. A pipeline gating on
    the exit code would take a typo'd flag for a critical finding, so a usage
    error gets its own code (64, EX_USAGE) that collides with none of 0-3.
    """

    def test_an_unknown_flag_does_not_look_like_a_critical(self) -> None:
        result = runner.invoke(app, ["scan", "--no-such-flag"])

        assert result.exit_code == EXIT_USAGE
        assert result.exit_code != EXIT_CRITICAL

    def test_a_missing_option_value_does_not_look_like_a_critical(self) -> None:
        """`--config` with no path after it."""
        result = runner.invoke(app, ["scan", "--config"])

        assert result.exit_code == EXIT_USAGE
        assert result.exit_code != EXIT_CRITICAL

    def test_an_unknown_command_does_not_look_like_a_critical(self) -> None:
        result = runner.invoke(app, ["frobnicate"])

        assert result.exit_code == EXIT_USAGE
        assert result.exit_code != EXIT_CRITICAL

    def test_a_real_verdict_still_uses_its_own_code(
        self, monkeypatch: pytest.MonkeyPatch, sample_config: Path
    ) -> None:
        """Moving usage errors off 2 must leave a genuine CRITICAL on 2."""
        _pretend_rules_are(monkeypatch, FlagsEveryServer())

        result = runner.invoke(app, ["scan", "--config", str(sample_config)])

        assert result.exit_code == EXIT_CRITICAL

    def test_help_is_not_an_error(self) -> None:
        """`--help` is a request that succeeded, not a misuse. Click exits 0."""
        result = runner.invoke(app, ["--help"])

        assert result.exit_code == EXIT_CLEAN


class TestIncompleteScan:
    """Exit 3: the scan did not complete, so it has no verdict to give.

    The failure a security scanner cannot have is passing green over a config it
    never managed to read. Codes 0, 1 and 2 all assert complete coverage — "I
    checked everything, and the worst of it was X" — so a run that skipped part
    of the config may return none of them, however clean the part it did read.
    """

    def test_a_config_that_could_not_be_read_exits_3_rather_than_clean(
        self, monkeypatch: pytest.MonkeyPatch, malformed_config: Path
    ) -> None:
        """The bug this code exists for: no findings, because nothing was read."""
        _pretend_rules_are(monkeypatch, FlagsEveryServer())

        result = runner.invoke(app, ["scan", "--config", str(malformed_config)])

        assert result.exit_code == EXIT_INCOMPLETE
        assert "malformed JSON" in result.stdout

    def test_a_config_that_does_not_exist_exits_3(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Asked to scan a named file, we either scan it or say we could not."""
        _pretend_rules_are(monkeypatch, FlagsNothing())

        result = runner.invoke(app, ["scan", "--config", str(tmp_path / "gone.json")])

        assert result.exit_code == EXIT_INCOMPLETE

    def test_a_config_we_lack_permission_to_open_exits_3(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        unreadable = tmp_path / "unreadable.json"
        unreadable.write_text('{"mcpServers": {}}', encoding="utf-8")
        unreadable.chmod(0o000)
        if os.access(unreadable, os.R_OK):  # pragma: no cover — root ignores the mode
            pytest.skip("running as root: the mode bits do not deny us the read")

        _pretend_rules_are(monkeypatch, FlagsNothing())

        result = runner.invoke(app, ["scan", "--config", str(unreadable)])

        assert result.exit_code == EXIT_INCOMPLETE
        assert not _crashed(result)

    def test_a_broken_rule_exits_3(
        self, monkeypatch: pytest.MonkeyPatch, sample_config: Path
    ) -> None:
        """A rule that crashed is a check that did not run."""
        _pretend_rules_are(monkeypatch, BrokenRule(), FlagsNothing())

        result = runner.invoke(app, ["scan", "--config", str(sample_config)])

        assert result.exit_code == EXIT_INCOMPLETE
        assert not _crashed(result)

    def test_an_incomplete_scan_outranks_a_critical_finding(
        self, monkeypatch: pytest.MonkeyPatch, sample_config: Path
    ) -> None:
        """A CRITICAL is a verdict, and this run is not entitled to one.

        Both codes fail a build, so nothing is missed by choosing 3 — and the
        critical is still printed in full. What the exit code must not do is
        claim the run knows the worst of the config when a rule it needed never
        ran.
        """
        _pretend_rules_are(monkeypatch, BrokenRule(), FlagsEveryServer())

        result = runner.invoke(app, ["scan", "--config", str(sample_config)])

        assert result.exit_code == EXIT_INCOMPLETE
        assert result.exit_code != EXIT_CRITICAL
        # Stepping back from a verdict is not the same as going quiet.
        assert "CRITICAL" in result.stdout
        assert "filesystem was flagged" in result.stdout

    def test_it_says_out_loud_that_the_scan_did_not_complete(
        self, monkeypatch: pytest.MonkeyPatch, malformed_config: Path
    ) -> None:
        """The summary line counts findings; it cannot count what was never read."""
        _pretend_rules_are(monkeypatch, FlagsEveryServer())

        result = runner.invoke(app, ["scan", "--config", str(malformed_config)])

        assert "Scan incomplete: 1 warning" in result.stdout

    def test_the_exit_code_survives_quiet(
        self, monkeypatch: pytest.MonkeyPatch, malformed_config: Path
    ) -> None:
        """The case from the issue, verbatim: `scan --config broken.json -q`."""
        _pretend_rules_are(monkeypatch, FlagsEveryServer())

        result = runner.invoke(
            app, ["scan", "--config", str(malformed_config), "--quiet"]
        )

        assert result.exit_code == EXIT_INCOMPLETE

    def test_a_scan_that_completed_keeps_the_codes_it_promised(
        self, monkeypatch: pytest.MonkeyPatch, sample_config: Path
    ) -> None:
        """Nothing above changes what a healthy run returns."""
        for rule, expected in (
            (FlagsNothing(), EXIT_CLEAN),
            (WarnsOnEveryServer(), EXIT_WARN),
            (FlagsEveryServer(), EXIT_CRITICAL),
        ):
            _pretend_rules_are(monkeypatch, rule)

            result = runner.invoke(app, ["scan", "--config", str(sample_config)])

            assert result.exit_code == expected, rule.id
            assert "Scan incomplete" not in result.stdout, rule.id

    def test_a_host_that_is_simply_not_installed_is_not_an_incomplete_scan(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Nothing to scan is a complete scan of nothing. Only 0 is honest here.

        Discovery skips a host whose config does not exist, so no warning is
        raised and no coverage is lost — unlike `--config missing.json`, where
        the user named a file we then failed to read.
        """
        _pretend_only_claude_desktop_config_at(monkeypatch, tmp_path / "missing.json")
        _pretend_rules_are(monkeypatch, FlagsEveryServer())

        result = runner.invoke(app, ["scan"])

        assert result.exit_code == EXIT_CLEAN
        assert "No MCP config files found." in result.stdout


class TestOutput:
    """`--output`: the same scan, written to a file for someone else to read."""

    def test_a_md_path_writes_a_markdown_report(
        self, monkeypatch: pytest.MonkeyPatch, sample_config: Path, tmp_path: Path
    ) -> None:
        _pretend_rules_are(monkeypatch, FlagsEveryServer())
        output = tmp_path / "report.md"

        result = runner.invoke(
            app, ["scan", "--config", str(sample_config), "--output", str(output)]
        )

        assert result.exit_code == EXIT_CRITICAL
        assert output.read_text(encoding="utf-8").startswith("# MCP scan report")
        assert str(output) in result.stdout

    def test_a_json_path_writes_a_json_report(
        self, monkeypatch: pytest.MonkeyPatch, sample_config: Path, tmp_path: Path
    ) -> None:
        _pretend_rules_are(monkeypatch, FlagsEveryServer())
        output = tmp_path / "report.json"

        result = runner.invoke(
            app, ["scan", "--config", str(sample_config), "-o", str(output)]
        )

        assert result.exit_code == EXIT_CRITICAL

        document = json.loads(output.read_text(encoding="utf-8"))
        assert document["summary"]["findings"] == 3
        # The report knows what the shell was told, so a consumer need not guess.
        assert document["summary"]["exit_code"] == EXIT_CRITICAL

    def test_a_sarif_path_writes_a_sarif_report(
        self, monkeypatch: pytest.MonkeyPatch, sample_config: Path, tmp_path: Path
    ) -> None:
        """What a CI job uploads to GitHub code scanning."""
        _pretend_rules_are(monkeypatch, FlagsEveryServer())
        output = tmp_path / "results.sarif"

        result = runner.invoke(
            app, ["scan", "--config", str(sample_config), "-o", str(output)]
        )

        assert result.exit_code == EXIT_CRITICAL

        document = json.loads(output.read_text(encoding="utf-8"))
        assert document["version"] == "2.1.0"
        assert len(document["runs"][0]["results"]) == 3

    def test_the_report_is_written_even_when_quiet(
        self, monkeypatch: pytest.MonkeyPatch, sample_config: Path, tmp_path: Path
    ) -> None:
        """--quiet is about the terminal. The file was asked for separately."""
        _pretend_rules_are(monkeypatch, FlagsEveryServer())
        output = tmp_path / "report.json"

        result = runner.invoke(
            app,
            ["scan", "--config", str(sample_config), "-o", str(output), "--quiet"],
        )

        assert result.exit_code == EXIT_CRITICAL
        assert json.loads(output.read_text(encoding="utf-8"))["findings"]

    def test_an_unwritable_format_exits_3_rather_than_reporting_a_verdict(
        self, monkeypatch: pytest.MonkeyPatch, sample_config: Path, tmp_path: Path
    ) -> None:
        """Asked for a report and given none, the run did not do what it was told.

        The findings still stand and are still printed — but a pipeline about to
        read `report.txt` would find last week's file, or none, and must not be
        told the run went fine.
        """
        _pretend_rules_are(monkeypatch, FlagsNothing())
        output = tmp_path / "report.txt"

        result = runner.invoke(
            app, ["scan", "--config", str(sample_config), "-o", str(output)]
        )

        assert result.exit_code == EXIT_INCOMPLETE
        assert not _crashed(result)
        assert "report.txt" in result.stdout
        assert not output.exists()

    def test_it_refuses_to_write_the_report_over_the_config_it_scanned(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """`--output ~/.claude.json` is a typo away, and would eat the config."""
        config = tmp_path / ".claude.json"
        original = '{"mcpServers": {"github": {"command": "npx"}}}'
        config.write_text(original, encoding="utf-8")

        _pretend_rules_are(monkeypatch, FlagsNothing())

        result = runner.invoke(
            app, ["scan", "--config", str(config), "-o", str(config)]
        )

        assert result.exit_code == EXIT_INCOMPLETE
        assert not _crashed(result)
        # The config is exactly as it was. This is the whole point.
        assert config.read_text(encoding="utf-8") == original

    def test_it_refuses_even_when_the_config_declared_no_servers(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """The real hazard: a `~/.claude.json` is mostly not an mcpServers block.

        The scan reads such a file and parses zero servers from it, so a guard
        that leaned on the parsed servers would find nothing to protect and write
        the report straight over the user's startup state.
        """
        config = tmp_path / ".claude.json"
        original = '{"numStartups": 42, "projects": {"/app": {}}, "userID": "keep"}'
        config.write_text(original, encoding="utf-8")

        _pretend_rules_are(monkeypatch, FlagsEveryServer())

        result = runner.invoke(
            app, ["scan", "--config", str(config), "-o", str(config)]
        )

        assert result.exit_code == EXIT_INCOMPLETE
        assert not _crashed(result)
        assert config.read_text(encoding="utf-8") == original

    def test_a_directory_that_does_not_exist_is_reported_not_raised(
        self, monkeypatch: pytest.MonkeyPatch, sample_config: Path, tmp_path: Path
    ) -> None:
        _pretend_rules_are(monkeypatch, FlagsNothing())
        output = tmp_path / "nowhere" / "report.md"

        result = runner.invoke(
            app, ["scan", "--config", str(sample_config), "-o", str(output)]
        )

        assert result.exit_code == EXIT_INCOMPLETE
        assert not _crashed(result)
        assert "error:" in result.stdout

    def test_an_incomplete_scan_still_exits_3_when_the_report_was_written(
        self, monkeypatch: pytest.MonkeyPatch, malformed_config: Path, tmp_path: Path
    ) -> None:
        """Writing a report about a scan that failed does not make it a success."""
        _pretend_rules_are(monkeypatch, FlagsEveryServer())
        output = tmp_path / "report.json"

        result = runner.invoke(
            app, ["scan", "--config", str(malformed_config), "-o", str(output)]
        )

        assert result.exit_code == EXIT_INCOMPLETE
        assert json.loads(output.read_text(encoding="utf-8"))["summary"]["complete"] is False

    def test_the_report_never_writes_a_credential(
        self, sample_config: Path, sample_secrets: list[str], tmp_path: Path
    ) -> None:
        """The real rules, the real config, both formats, on disk."""
        for name in ("report.md", "report.json", "results.sarif"):
            output = tmp_path / name

            runner.invoke(
                app, ["scan", "--config", str(sample_config), "-o", str(output)]
            )

            written = output.read_text(encoding="utf-8")
            assert sample_secrets  # the fixture must actually carry secrets
            for secret in sample_secrets:
                assert secret not in written, name

    def test_the_report_masks_a_credential_a_rule_message_names(
        self, tmp_path: Path
    ) -> None:
        """The nastiest case: a secret carried where a rule quotes it back.

        A plaintext URL trips `insecure-transport`, whose message names the URL,
        and a proxy server carries a password in a URL in its own args. Both are
        printed and written, and neither may carry the secret to disk — with the
        real rules, not a stand-in, since it is the rules doing the quoting.
        """
        password = "hunter2SuperSecret"
        token = "sk-abcdef0123456789abcdef01"
        config = tmp_path / "leaky.json"
        config.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "plain": {"url": f"http://u:{password}@evil.example.com/mcp?api_key={token}"},
                        "proxy": {
                            "command": "npx",
                            "args": ["mcp-remote", f"https://u:{password}@host.example.com/sse"],
                        },
                    }
                }
            ),
            encoding="utf-8",
        )

        for name in ("report.md", "report.json", "results.sarif"):
            output = tmp_path / name

            result = runner.invoke(
                app, ["scan", "--config", str(config), "-o", str(output)]
            )
            assert not _crashed(result)

            written = output.read_text(encoding="utf-8")
            assert password not in written, name
            assert token not in written, name


class TestQuiet:
    """`--quiet`: the summary line, and whatever the run failed to look at."""

    def test_prints_the_summary_instead_of_the_table(
        self, monkeypatch: pytest.MonkeyPatch, sample_config: Path
    ) -> None:
        _pretend_rules_are(monkeypatch, FlagsEveryServer())

        result = runner.invoke(app, ["scan", "--config", str(sample_config), "--quiet"])

        assert result.exit_code == EXIT_CRITICAL
        assert "3 findings in 3 servers: 3 CRITICAL." in result.stdout
        # The table, and the per-finding detail only it carries, are gone.
        assert "Findings" not in result.stdout
        assert "was flagged" not in result.stdout

    def test_counts_each_severity_worst_first(
        self, monkeypatch: pytest.MonkeyPatch, sample_config: Path
    ) -> None:
        _pretend_rules_are(monkeypatch, FlagsRemoteServers(), FlagsEveryServer())

        result = runner.invoke(app, ["scan", "--config", str(sample_config), "-q"])

        # Three servers flagged CRITICAL, the one remote server also INFO.
        assert "4 findings in 3 servers: 3 CRITICAL, 1 INFO." in result.stdout

    def test_a_clean_scan_still_says_so(
        self, monkeypatch: pytest.MonkeyPatch, sample_config: Path
    ) -> None:
        _pretend_rules_are(monkeypatch, FlagsNothing())

        result = runner.invoke(app, ["scan", "--config", str(sample_config), "-q"])

        assert result.exit_code == EXIT_CLEAN
        assert "No findings in 3 servers." in result.stdout

    def test_a_config_that_could_not_be_read_is_still_reported(
        self, monkeypatch: pytest.MonkeyPatch, malformed_config: Path
    ) -> None:
        """The one thing --quiet must not swallow.

        A warning does not report a risk, it reports that we failed to look for
        one. The exit code now says so too (3, see `TestIncompleteScan`), but a
        code says only *that* the scan fell short — the line says which file, and
        where in it, which is what the person fixing it needs.
        """
        _pretend_rules_are(monkeypatch, FlagsEveryServer())

        result = runner.invoke(
            app, ["scan", "--config", str(malformed_config), "--quiet"]
        )

        assert result.exit_code == EXIT_INCOMPLETE
        assert "malformed JSON" in result.stdout

    def test_the_summary_is_printed_with_the_findings_too(
        self, monkeypatch: pytest.MonkeyPatch, sample_config: Path
    ) -> None:
        """--quiet drops the findings. It does not add the summary."""
        _pretend_rules_are(monkeypatch, FlagsEveryServer())

        result = runner.invoke(app, ["scan", "--config", str(sample_config)])

        assert "Findings" in result.stdout
        assert "3 findings in 3 servers: 3 CRITICAL." in result.stdout


def test_scan_discovers_installed_hosts_when_no_config_given(
    monkeypatch: pytest.MonkeyPatch, installed_hosts: InstalledHosts
) -> None:
    _pretend_hosts_installed_at(
        monkeypatch, installed_hosts.home, installed_hosts.project_dir
    )
    _pretend_rules_are(monkeypatch, FlagsEveryServer())

    result = runner.invoke(app, ["scan"])

    assert result.exit_code == EXIT_CRITICAL
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

    assert result.exit_code == EXIT_INCOMPLETE
    assert not _crashed(result)
    assert "malformed JSON" in result.stdout


def test_scan_warns_about_a_broken_rule_and_keeps_scanning(
    monkeypatch: pytest.MonkeyPatch, sample_config: Path
) -> None:
    _pretend_rules_are(monkeypatch, BrokenRule(), FlagsEveryServer())

    result = runner.invoke(app, ["scan", "--config", str(sample_config)])

    assert result.exit_code == EXIT_INCOMPLETE
    assert not _crashed(result)
    assert "test-broken" in result.stdout
    # The healthy rule still reported, and its findings are still printed: the
    # exit code steps back from a verdict, the output does not go quiet.
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

    assert result.exit_code == EXIT_CRITICAL
    assert not _crashed(result)
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


def test_scan_reports_hardcoded_credentials_without_printing_them(
    credentials_config: Path, credentials_secrets: list[str]
) -> None:
    """The shipped rules, end to end: a real config in, a real report out."""
    result = runner.invoke(app, ["scan", "--config", str(credentials_config)])

    assert result.exit_code == EXIT_CRITICAL

    # The credential on the command line outranks the one in the config file.
    assert result.stdout.index("CRITICAL") < result.stdout.index("WARN")
    assert "static-credential-in-args" in result.stdout
    assert "static-credential-in-env" in result.stdout
    # Named, so the user knows which variable to move out of the file.
    assert "EXAMPLE_API_KEY" in result.stdout
    # The server that references its credential from the environment is clean.
    assert "env-referenced" not in result.stdout

    assert credentials_secrets  # the fixture must actually carry secrets to test
    for secret in credentials_secrets:
        assert secret not in result.stdout
