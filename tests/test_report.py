"""Tests for the three shapes a scan is rendered into.

The terminal tests pin the thing #19 was filed about: at eighty columns, the
message a user has to read must arrive as a sentence, not as a ribbon two words
wide, and the rule that fired must be nameable without widening the window.

The markdown and JSON tests pin the two things a report must never do: leak a
credential, or let a config file it is reporting on decide how it reads.
"""

import json
from pathlib import Path

import pytest
from rich.console import Console

from mcp_scan import report
from mcp_scan.parsers import MCPServer
from mcp_scan.report import Report, UnknownFormat, WouldOverwriteConfig
from mcp_scan.rules import Finding, Severity, load_rules

#: The width the findings have to be readable at. Not a round number chosen for
#: neatness: it is the default terminal, and it is where the old table failed.
NARROW = 80


def _server(
    name: str = "github",
    host: str = "claude-desktop",
    source: str = "/home/dev/.claude.json",
    **kwargs: object,
) -> MCPServer:
    return MCPServer(name=name, host=host, source=Path(source), **kwargs)  # type: ignore[arg-type]


def _finding(
    server: MCPServer | None = None,
    rule_id: str = "static-credential-in-args",
    severity: Severity = Severity.CRITICAL,
    message: str = "argument 3 of the command holds the value of '--api-key'",
    remediation: str = "Take the credential off the command line.",
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title="Credential hardcoded in a command argument",
        severity=severity,
        server=server if server is not None else _server(),
        message=message,
        remediation=remediation,
    )


def _rendered(renderable: object, width: int = NARROW) -> str:
    """What the terminal would actually show, at a given width."""
    console = Console(width=width, no_color=True, force_terminal=False)
    with console.capture() as capture:
        console.print(renderable)
    return capture.get()


class TestTerminal:
    """The block layout, and the eighty-column failure that asked for it."""

    def test_a_rule_name_is_never_truncated_at_eighty_columns(self) -> None:
        """The old table ellipsized these into `remote-code…`, `plaintext-…`."""
        findings = [
            _finding(rule_id="static-credential-in-args"),
            _finding(rule_id="broad-filesystem-access", severity=Severity.WARN),
        ]

        output = _rendered(report.terminal(Report(findings=findings)))

        assert "static-credential-in-args" in output
        assert "broad-filesystem-access" in output
        assert "…" not in output

    def test_the_message_arrives_as_a_sentence_not_a_ribbon(self) -> None:
        """The point of the whole issue: the message gets the full width.

        In the six-column table this wrapped into a thirteen-character column,
        one or two words a line. Here it may wrap — it is a long sentence — but
        it wraps at something like the width of the terminal, not at a fraction
        of it.
        """
        message = (
            "the server is given '/', which is the entire filesystem; grant it "
            "the directories it works in instead, one by one ('~/code/my-app')"
        )
        finding = _finding(message=message, rule_id="broad-filesystem-access")

        output = _rendered(report.terminal(Report(findings=[finding])))

        # Every word survives, in order, however the lines happened to break.
        assert " ".join(output.split()).count(" ".join(message.split())) == 1

        # And the lines it broke into use the width they were given, rather than
        # a sixth of it. The old table left ~13 characters for this text.
        body = [
            line.strip()
            for line in output.splitlines()
            if line.strip() and "Findings" not in line
        ]
        assert max(len(line) for line in body) > 40

    def test_no_line_overflows_the_terminal(self) -> None:
        finding = _finding(
            server=_server(name="a-server-with-a-very-long-name-indeed"),
            message="a message " * 30,
        )

        output = _rendered(report.terminal(Report(findings=[finding])))

        assert max(len(line) for line in output.splitlines()) <= NARROW

    def test_a_server_is_named_once_for_all_of_its_findings(self) -> None:
        """What the per-row Server, Host and Source columns were costing."""
        server = _server(name="github")
        findings = [
            _finding(server=server, rule_id="static-credential-in-args"),
            _finding(
                server=server, rule_id="broad-filesystem-access", severity=Severity.WARN
            ),
        ]

        output = _rendered(report.terminal(Report(findings=findings)))

        assert output.count("github") == 1
        assert output.count("claude-desktop") == 1

    def test_two_hosts_declaring_the_same_server_name_stay_apart(self) -> None:
        """A `github` in Cursor and a `github` in Claude Code are two servers."""
        findings = [
            _finding(server=_server(name="github", host="cursor")),
            _finding(server=_server(name="github", host="claude-code")),
        ]

        output = _rendered(report.terminal(Report(findings=findings)))

        assert output.count("github") == 2
        assert "cursor" in output
        assert "claude-code" in output

    def test_the_worst_server_comes_first(self) -> None:
        """Grouping by server must not disturb worst-first ordering."""
        findings = [
            _finding(
                server=_server(name="critical-one"),
                severity=Severity.CRITICAL,
            ),
            _finding(
                server=_server(name="warn-one"),
                severity=Severity.WARN,
            ),
            _finding(
                server=_server(name="info-one"),
                severity=Severity.INFO,
            ),
        ]

        output = _rendered(report.terminal(Report(findings=findings)))

        positions = [output.index(name) for name in ("critical-one", "warn-one", "info-one")]
        assert positions == sorted(positions), output

    def test_a_server_name_that_looks_like_console_markup_is_printed_literally(
        self,
    ) -> None:
        finding = _finding(server=_server(name="evil [/bold]"))

        output = _rendered(report.terminal(Report(findings=[finding])))

        assert "evil [/bold]" in output

    def test_the_heading_says_which_line_the_server_is_on(self) -> None:
        """`path:line` is what a terminal opens at the line, not decoration."""
        finding = _finding(server=_server(source="/etc/mcp.json", line=12))

        output = _rendered(report.terminal(Report(findings=[finding])))

        assert "/etc/mcp.json:12" in output

    def test_the_heading_of_a_server_with_no_line_is_just_its_file(self) -> None:
        finding = _finding(server=_server(source="/etc/mcp.json", line=None))

        output = _rendered(report.terminal(Report(findings=[finding])))

        assert "/etc/mcp.json" in output
        assert "/etc/mcp.json:" not in output


class TestMarkdown:
    """The shareable report: summary, findings, recommendations."""

    def test_it_leads_with_the_summary(self) -> None:
        document = report.to_markdown(
            Report(servers=[_server()], findings=[_finding()])
        )

        assert document.startswith("# MCP scan report")
        assert "**1 finding in 1 server: 1 CRITICAL.**" in document

    def test_it_has_the_sections_the_issue_asked_for(self) -> None:
        document = report.to_markdown(
            Report(servers=[_server()], findings=[_finding()])
        )

        assert "## Findings" in document
        assert "## Recommendations" in document
        assert "## Servers scanned" in document

    def test_the_findings_table_is_a_table(self) -> None:
        document = report.to_markdown(
            Report(servers=[_server()], findings=[_finding()])
        )

        assert "| Severity | Rule | Server | Host | Finding |" in document
        assert "| --- | --- | --- | --- | --- |" in document
        assert "| CRITICAL | `static-credential-in-args` | `github` |" in document

    def test_the_servers_table_says_which_line_each_server_is_on(self) -> None:
        """A colleague reading the report should not have to search the config."""
        document = report.to_markdown(
            Report(servers=[_server(source="/etc/mcp.json", line=12)])
        )

        assert "`/etc/mcp.json:12`" in document

    def test_a_rule_is_recommended_once_however_many_servers_tripped_it(self) -> None:
        """Four findings from one rule are one thing to go and do."""
        findings = [
            _finding(server=_server(name=name), remediation="Rotate the key.")
            for name in ("one", "two", "three")
        ]

        document = report.to_markdown(Report(findings=findings))

        assert document.count("Rotate the key.") == 1
        # And it says which servers it is talking about.
        assert "affects `one`, `two`, `three`" in document

    def test_a_clean_scan_says_so_rather_than_printing_an_empty_table(self) -> None:
        document = report.to_markdown(Report(servers=[_server()]))

        assert "None. Every server checked came back clean." in document
        assert "| Severity |" not in document

    def test_an_incomplete_scan_is_flagged_at_the_top_and_itemised_below(self) -> None:
        scanned = Report(
            servers=[_server()],
            warnings=["~/.claude.json: malformed JSON at line 6"],
            exit_code=3,
        )

        document = report.to_markdown(scanned)

        assert "> [!WARNING]" in document
        assert "**The scan did not complete.**" in document
        assert "## What was not checked" in document
        assert "malformed JSON at line 6" in document

    def test_a_complete_scan_carries_no_warning_banner(self) -> None:
        document = report.to_markdown(Report(servers=[_server()]))

        assert "[!WARNING]" not in document
        assert "## What was not checked" not in document

    def test_it_never_writes_a_credential(
        self, credentials_config: Path, credentials_secrets: list[str]
    ) -> None:
        document = report.to_markdown(_scan_of(credentials_config))

        assert credentials_secrets  # the fixture must actually carry secrets
        for secret in credentials_secrets:
            assert secret not in document
        # Masked in place, so the user can still find the flag to go and fix.
        assert "--api-key=\\*\\*\\*" in document or "--api-key=***" in document

    def test_a_pipe_in_a_server_name_cannot_break_the_table(self) -> None:
        """A config that could reshape the report about it would be quite a bug."""
        finding = _finding(server=_server(name="evil | --- | injected"))

        document = report.to_markdown(Report(findings=[finding]))

        row = next(
            line for line in document.splitlines() if "injected" in line and "|" in line
        )
        # Five columns, so six pipes. The name's own pipe is escaped, not counted.
        assert row.count("|") - row.count("\\|") == 6

    def test_markdown_in_a_message_is_shown_rather_than_rendered(self) -> None:
        """A message is prose, so it is escaped: a config cannot format the page."""
        finding = _finding(
            message="a [link](https://evil.example.com), an <img> tag and **bold**"
        )

        document = report.to_markdown(Report(findings=[finding]))

        assert "\\[link\\]" in document
        assert "\\<img\\>" in document
        assert "\\*\\*bold\\*\\*" in document

    def test_markdown_in_a_server_name_is_shown_rather_than_rendered(self) -> None:
        """A name is a code span, which is the other way to be literal.

        Nothing inside backticks is markdown, so the name needs no escaping to be
        inert — only the pipe does, which would end the table cell regardless.
        """
        finding = _finding(server=_server(name="**bold** <img>"))

        document = report.to_markdown(Report(findings=[finding]))

        assert "`**bold** <img>`" in document

    def test_a_backtick_in_a_name_does_not_escape_its_code_span(self) -> None:
        finding = _finding(server=_server(name="a`b"))

        document = report.to_markdown(Report(findings=[finding]))

        # Fenced with a longer run of backticks than the one inside it.
        assert "``a`b``" in document

    def test_our_own_remediation_keeps_its_formatting(self) -> None:
        """The one string on the page that is ours, and is meant to be markdown."""
        finding = _finding(remediation="Reference it: `${GITHUB_TOKEN}`.")

        document = report.to_markdown(Report(findings=[finding]))

        assert "Reference it: `${GITHUB_TOKEN}`." in document


class TestJson:
    """The machine-readable report: stable, and parseable whatever the config."""

    def test_it_is_valid_json(self) -> None:
        document = json.loads(
            report.to_json(Report(servers=[_server()], findings=[_finding()]))
        )

        assert document["schema_version"] == report.SCHEMA_VERSION
        assert document["tool"]["name"] == "mcp-scan"

    def test_the_summary_carries_the_verdict(self) -> None:
        scanned = Report(
            servers=[_server(), _server(name="other")],
            findings=[_finding()],
            exit_code=2,
        )

        summary = json.loads(report.to_json(scanned))["summary"]

        assert summary["complete"] is True
        assert summary["exit_code"] == 2
        assert summary["servers_scanned"] == 2
        assert summary["findings"] == 1
        assert summary["by_severity"] == {"CRITICAL": 1, "WARN": 0, "INFO": 0}

    def test_an_incomplete_scan_says_so_in_the_data(self) -> None:
        """A consumer must be able to tell a clean scan from an unfinished one."""
        scanned = Report(warnings=["broken.json: malformed JSON"], exit_code=3)

        document = json.loads(report.to_json(scanned))

        assert document["summary"]["complete"] is False
        assert document["summary"]["exit_code"] == 3
        assert document["warnings"] == ["broken.json: malformed JSON"]

    def test_a_finding_carries_what_it_takes_to_act_on_it(self) -> None:
        document = json.loads(
            report.to_json(Report(findings=[_finding(server=_server(line=12))]))
        )

        finding = document["findings"][0]
        assert finding["rule"] == "static-credential-in-args"
        assert finding["severity"] == "CRITICAL"
        assert finding["message"]
        assert finding["remediation"]
        assert finding["server"] == {
            "name": "github",
            "host": "claude-desktop",
            "source": "/home/dev/.claude.json",
            "line": 12,
        }

    def test_a_server_with_no_line_carries_a_null_rather_than_a_guess(self) -> None:
        """A consumer that opens the file can tell "no line" from "line 1"."""
        scanned = Report(servers=[_server(line=None)], findings=[_finding()])

        document = json.loads(report.to_json(scanned))

        assert document["servers"][0]["line"] is None
        assert document["findings"][0]["server"]["line"] is None

    def test_it_never_writes_a_credential(
        self, credentials_config: Path, credentials_secrets: list[str]
    ) -> None:
        document = report.to_json(_scan_of(credentials_config))

        assert credentials_secrets  # the fixture must actually carry secrets
        for secret in credentials_secrets:
            assert secret not in document

    def test_the_endpoint_it_reports_is_the_redacted_one(
        self, credentials_config: Path
    ) -> None:
        document = json.loads(report.to_json(_scan_of(credentials_config)))

        endpoints = {server["name"]: server["endpoint"] for server in document["servers"]}
        assert endpoints["args-inline"].endswith("--api-key=*** --verbose")
        assert "api_key=***" in endpoints["url-inline"]

    def test_a_hostile_server_name_cannot_break_the_document(self) -> None:
        """Whatever is in the config, what comes out has to still parse."""
        finding = _finding(server=_server(name='evil", "injected": "yes'))

        document = json.loads(report.to_json(Report(findings=[finding])))

        assert document["findings"][0]["server"]["name"] == 'evil", "injected": "yes'
        assert "injected" not in document


class TestSarif:
    """The CI dashboard's report: ingestible, and one alert per finding."""

    def test_it_is_valid_sarif(self) -> None:
        document = json.loads(
            report.to_sarif(Report(servers=[_server()], findings=[_finding()]))
        )

        assert document["version"] == "2.1.0"
        assert document["$schema"] == report.SARIF_SCHEMA

        driver = document["runs"][0]["tool"]["driver"]
        assert driver["name"] == "mcp-scan"
        assert driver["version"]
        assert driver["informationUri"]

    def test_severities_map_onto_sarif_levels(self) -> None:
        findings = [
            _finding(rule_id="critical-rule", severity=Severity.CRITICAL),
            _finding(rule_id="warn-rule", severity=Severity.WARN),
            _finding(rule_id="info-rule", severity=Severity.INFO),
        ]

        results = json.loads(report.to_sarif(Report(findings=findings)))["runs"][0][
            "results"
        ]

        assert [result["level"] for result in results] == ["error", "warning", "note"]

    def test_a_rule_is_described_once_however_many_servers_tripped_it(self) -> None:
        """The driver describes the rule; the results say where it fired."""
        findings = [
            _finding(server=_server(name=name), remediation="Rotate the key.")
            for name in ("one", "two", "three")
        ]

        run = json.loads(report.to_sarif(Report(findings=findings)))["runs"][0]

        assert len(run["tool"]["driver"]["rules"]) == 1
        assert len(run["results"]) == 3

    def test_every_result_indexes_the_rule_it_names(self) -> None:
        """`ruleIndex` is an offset into the driver's rules, and must land."""
        findings = [
            _finding(rule_id="static-credential-in-args"),
            _finding(rule_id="broad-filesystem-access", severity=Severity.WARN),
            _finding(rule_id="static-credential-in-args", server=_server(name="other")),
        ]

        run = json.loads(report.to_sarif(Report(findings=findings)))["runs"][0]

        rules = run["tool"]["driver"]["rules"]
        for result in run["results"]:
            assert rules[result["ruleIndex"]]["id"] == result["ruleId"]

    def test_a_rule_carries_its_remediation_as_the_alert_help(self) -> None:
        finding = _finding(remediation="Reference it: `${GITHUB_TOKEN}`.")

        rule = json.loads(report.to_sarif(Report(findings=[finding])))["runs"][0][
            "tool"
        ]["driver"]["rules"][0]

        assert rule["help"]["markdown"] == "Reference it: `${GITHUB_TOKEN}`."
        assert rule["shortDescription"]["text"]
        assert rule["defaultConfiguration"]["level"] == "error"

    def test_a_finding_is_filed_as_a_security_alert_and_ranked(self) -> None:
        """Without the tag GitHub files it as lint; without the number, unranked."""
        findings = [
            _finding(rule_id="critical-rule", severity=Severity.CRITICAL),
            _finding(rule_id="warn-rule", severity=Severity.WARN),
        ]

        rules = json.loads(report.to_sarif(Report(findings=findings)))["runs"][0][
            "tool"
        ]["driver"]["rules"]

        assert all("security" in rule["properties"]["tags"] for rule in rules)
        severities = [rule["properties"]["security-severity"] for rule in rules]
        assert float(severities[0]) > float(severities[1])

    def test_a_config_in_the_repository_is_located_relative_to_it(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The case the format exists for: an alert GitHub can pin to the diff.

        A relative URI is what lets code scanning map the result onto a file in
        the pull request — for a project-scoped `.mcp.json`, that is the file the
        pull request is changing.
        """
        monkeypatch.chdir(tmp_path)
        config = tmp_path / ".mcp.json"
        finding = _finding(server=_server(source=str(config)))

        result = json.loads(report.to_sarif(Report(findings=[finding])))["runs"][0][
            "results"
        ][0]

        location = result["locations"][0]["physicalLocation"]
        assert location["artifactLocation"]["uri"] == ".mcp.json"
        # GitHub will not display a result with no region at all.
        assert location["region"]["startLine"] == 1

    def test_a_result_is_located_on_the_line_the_server_is_declared_on(self) -> None:
        """The whole point of the region: the alert lands on the offending server.

        A reviewer with four servers in one config should not have to go and find
        which of them the alert is about.
        """
        finding = _finding(server=_server(line=12))

        result = json.loads(report.to_sarif(Report(findings=[finding])))["runs"][0][
            "results"
        ][0]

        region = result["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] == 12

    def test_a_server_with_no_line_still_produces_a_located_result(self) -> None:
        """Line 1 as a fallback, because a result with no region is not displayed.

        Dropping the region would drop the finding, which is the one thing a
        scanner may not do.
        """
        finding = _finding(server=_server(line=None))

        result = json.loads(report.to_sarif(Report(findings=[finding])))["runs"][0][
            "results"
        ][0]

        region = result["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] == 1

    def test_the_fingerprint_does_not_move_when_the_server_does(self) -> None:
        """A server pushed down the file is the same finding, not a new one.

        Hashing the line would retire every alert on a config the moment somebody
        added a server above them.
        """
        before = _finding(server=_server(line=12))
        after = _finding(server=_server(line=40))

        fingerprints = [
            json.loads(report.to_sarif(Report(findings=[finding])))["runs"][0][
                "results"
            ][0]["partialFingerprints"]["mcpScanFinding/v1"]
            for finding in (before, after)
        ]

        assert fingerprints[0] == fingerprints[1]

    def test_a_config_outside_the_repository_keeps_an_absolute_uri(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A home config is not in the repository, and must not pretend to be."""
        monkeypatch.chdir(tmp_path)
        finding = _finding(server=_server(source="/home/dev/.claude.json"))

        result = json.loads(report.to_sarif(Report(findings=[finding])))["runs"][0][
            "results"
        ][0]

        uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert uri.startswith("file://")
        assert uri.endswith("/.claude.json")

    def test_two_servers_in_one_file_tripping_one_rule_stay_two_alerts(self) -> None:
        """The finding that would otherwise vanish on upload.

        Both results carry the same rule and the same location — the config file,
        with no line to tell them apart — so a dashboard generating its own
        fingerprints would collapse them into one alert. The fingerprint we send
        is what keeps them apart.
        """
        source = "/home/dev/.claude.json"
        findings = [
            _finding(server=_server(name="github", source=source)),
            _finding(server=_server(name="postgres", source=source)),
        ]

        results = json.loads(report.to_sarif(Report(findings=findings)))["runs"][0][
            "results"
        ]

        fingerprints = {
            result["partialFingerprints"]["mcpScanFinding/v1"] for result in results
        }
        assert len(fingerprints) == 2

    def test_one_rule_firing_twice_on_one_server_stays_two_alerts(self) -> None:
        """The same trap again, and the easier one to walk into.

        `Rule.check` returns a list precisely because a rule may find two things
        wrong with one server — two credential-bearing arguments on one command,
        say. Those findings share a rule, a server and a file, so anything the
        fingerprint is built from must include what actually tells them apart:
        what each one says.
        """
        server = _server()
        findings = [
            _finding(server=server, message="argument 3 holds the value of '--api-key'"),
            _finding(server=server, message="argument 5 holds the value of '--token'"),
        ]

        results = json.loads(report.to_sarif(Report(findings=findings)))["runs"][0][
            "results"
        ]

        fingerprints = {
            result["partialFingerprints"]["mcpScanFinding/v1"] for result in results
        }
        assert len(fingerprints) == 2

    def test_a_fingerprint_does_not_move_between_runs(self) -> None:
        """An alert tracked across commits is an alert the user can close."""
        finding = _finding()

        first = json.loads(report.to_sarif(Report(findings=[finding])))
        second = json.loads(report.to_sarif(Report(findings=[finding])))

        assert (
            first["runs"][0]["results"][0]["partialFingerprints"]
            == second["runs"][0]["results"][0]["partialFingerprints"]
        )

    def test_an_incomplete_scan_says_so_where_a_dashboard_reads_it(self) -> None:
        """A scan that never finished must not upload as a scan that came back clean."""
        scanned = Report(warnings=["~/.claude.json: malformed JSON"], exit_code=3)

        invocation = json.loads(report.to_sarif(scanned))["runs"][0]["invocations"][0]

        assert invocation["executionSuccessful"] is False
        assert invocation["toolExecutionNotifications"][0]["message"]["text"] == (
            "~/.claude.json: malformed JSON"
        )

    def test_a_complete_scan_reports_a_successful_run(self) -> None:
        invocation = json.loads(report.to_sarif(Report(servers=[_server()])))["runs"][0][
            "invocations"
        ][0]

        assert invocation["executionSuccessful"] is True
        assert invocation["toolExecutionNotifications"] == []

    def test_a_clean_scan_is_a_run_with_no_results(self) -> None:
        run = json.loads(report.to_sarif(Report(servers=[_server()])))["runs"][0]

        assert run["results"] == []
        assert run["tool"]["driver"]["rules"] == []

    def test_it_never_writes_a_credential(
        self, credentials_config: Path, credentials_secrets: list[str]
    ) -> None:
        document = report.to_sarif(_scan_of(credentials_config))

        assert credentials_secrets  # the fixture must actually carry secrets
        for secret in credentials_secrets:
            assert secret not in document

    def test_an_alert_says_which_server_it_is_about(self) -> None:
        """SARIF has no server column, so the message is the only place to say it."""
        finding = _finding(
            server=_server(name="github", host="cursor"),
            message="argument 3 of the command holds the value of '--api-key'",
        )

        result = json.loads(report.to_sarif(Report(findings=[finding])))["runs"][0][
            "results"
        ][0]

        text = result["message"]["text"]
        assert "github" in text
        assert "cursor" in text
        assert "argument 3 of the command holds the value of '--api-key'" in text

    def test_a_hostile_server_name_cannot_break_the_document(self) -> None:
        """A config that could reshape the SARIF about it would be quite a bug."""
        finding = _finding(server=_server(name='evil", "injected": "yes'))

        document = json.loads(report.to_sarif(Report(findings=[finding])))

        result = document["runs"][0]["results"][0]
        assert 'evil", "injected": "yes' in result["message"]["text"]
        assert "injected" not in result


class TestWrite:
    """`--output`: the extension picks the format, and some paths are refused."""

    @pytest.mark.parametrize("name", ["report.md", "report.markdown", "REPORT.MD"])
    def test_a_markdown_extension_writes_markdown(
        self, tmp_path: Path, name: str
    ) -> None:
        path = tmp_path / name

        report.write(Report(servers=[_server()], findings=[_finding()]), path)

        assert path.read_text(encoding="utf-8").startswith("# MCP scan report")

    def test_a_json_extension_writes_json(self, tmp_path: Path) -> None:
        path = tmp_path / "report.json"

        report.write(Report(servers=[_server()], findings=[_finding()]), path)

        assert json.loads(path.read_text(encoding="utf-8"))["schema_version"] == 1

    @pytest.mark.parametrize("name", ["results.sarif", "RESULTS.SARIF"])
    def test_a_sarif_extension_writes_sarif(self, tmp_path: Path, name: str) -> None:
        path = tmp_path / name

        report.write(Report(servers=[_server()], findings=[_finding()]), path)

        assert json.loads(path.read_text(encoding="utf-8"))["version"] == "2.1.0"

    def test_a_sarif_json_extension_writes_sarif_and_not_json(
        self, tmp_path: Path
    ) -> None:
        """`results.sarif.json` is the name GitHub's own docs use.

        Its `Path.suffix` is `.json`, so a dispatch on the last suffix alone would
        quietly write our JSON report into a file the pipeline then rejects as
        invalid SARIF — for a reason nobody could see from the filename.
        """
        path = tmp_path / "results.sarif.json"

        report.write(Report(servers=[_server()], findings=[_finding()]), path)

        written = json.loads(path.read_text(encoding="utf-8"))
        assert written["version"] == "2.1.0"
        assert "schema_version" not in written

    def test_an_unrelated_double_extension_still_writes_by_its_last(
        self, tmp_path: Path
    ) -> None:
        """`.sarif.json` is a special case, not a licence to misread `x.y.json`."""
        path = tmp_path / "mcp-scan.2026-07-11.json"

        report.write(Report(servers=[_server()], findings=[_finding()]), path)

        assert json.loads(path.read_text(encoding="utf-8"))["schema_version"] == 1

    def test_an_extension_we_do_not_write_is_refused(self, tmp_path: Path) -> None:
        path = tmp_path / "report.txt"

        with pytest.raises(UnknownFormat, match="report.txt"):
            report.write(Report(), path)

        assert not path.exists()

    def test_it_refuses_to_write_the_report_over_a_config_it_just_scanned(
        self, tmp_path: Path
    ) -> None:
        """`--output ~/.claude.json` is one keystroke, and would eat the config.

        The extension check does not catch it — a Claude Code config *is* a
        `.json` file — so the path is checked against what the scan just read.
        """
        config = tmp_path / ".claude.json"
        original = '{"mcpServers": {"github": {"command": "npx"}}}'
        config.write_text(original, encoding="utf-8")

        scanned = Report(servers=[_server(source=str(config))], sources=[config])

        with pytest.raises(WouldOverwriteConfig, match="config file"):
            report.write(scanned, config)

        assert config.read_text(encoding="utf-8") == original

    def test_it_refuses_to_overwrite_a_config_that_yielded_no_servers(
        self, tmp_path: Path
    ) -> None:
        """The dangerous case: the guard cannot lean on a parsed server.

        A real `~/.claude.json` keeps startup counters and project state under
        keys that are not `mcpServers`, so the scan reads it and parses zero
        servers from it. A guard built from `servers` would find nothing to
        protect and write the report straight over it. The file is still the
        user's, and still theirs to keep.
        """
        config = tmp_path / ".claude.json"
        original = '{"numStartups": 42, "userID": "keep-me"}'
        config.write_text(original, encoding="utf-8")

        # No servers — exactly what the parser returns for this file — but the
        # path it was read from is still on the report.
        scanned = Report(servers=[], sources=[config])

        with pytest.raises(WouldOverwriteConfig, match="config file"):
            report.write(scanned, config)

        assert config.read_text(encoding="utf-8") == original

    def test_the_refusal_sees_through_a_roundabout_spelling_of_the_path(
        self, tmp_path: Path
    ) -> None:
        config = tmp_path / ".claude.json"
        config.write_text("{}", encoding="utf-8")
        scanned = Report(sources=[config])

        roundabout = tmp_path / "sub" / ".." / ".claude.json"
        (tmp_path / "sub").mkdir()

        with pytest.raises(WouldOverwriteConfig):
            report.write(scanned, roundabout)

    def test_a_path_that_is_not_a_config_is_written_happily(
        self, tmp_path: Path
    ) -> None:
        config = tmp_path / ".claude.json"
        config.write_text("{}", encoding="utf-8")
        scanned = Report(sources=[config])

        path = tmp_path / "report.json"
        report.write(scanned, path)

        assert path.exists()


def test_every_shipped_rule_explains_how_to_fix_what_it_finds() -> None:
    """A finding the user cannot act on is a finding that wastes their afternoon.

    `remediation` defaults to empty so a throwaway rule in a test need not write
    a paragraph about nothing. Nothing we actually ship may take that default.
    """
    for rule in load_rules():
        assert rule.remediation, f"rule '{rule.id}' ships without a remediation"
        assert len(rule.remediation) > 40, f"rule '{rule.id}' barely explains itself"


def _scan_of(config: Path) -> Report:
    """A real scan of a real config, rules and all — not a hand-built Report.

    The credential tests want the actual pipeline: whatever the parser kept and
    the rules said about it is what a report would have to print, and that is
    the thing that must not contain a secret.
    """
    from mcp_scan.parsers import parse_config_file
    from mcp_scan.rules import run_rules

    parsed = parse_config_file(config)
    result = run_rules(parsed.servers, load_rules())

    return Report(
        servers=parsed.servers,
        findings=result.findings,
        warnings=parsed.warnings + result.warnings,
        sources=[config],
    )
