"""Render a scan for the reader it is aimed at.

Three readers, three shapes, one set of facts:

* the terminal, where findings are printed as blocks — a heading per server,
  then each finding under it with room for the message to be a sentence;
* markdown, for a report shared with someone who was not at the keyboard, and
  therefore needs the summary, the findings and what to do about them;
* JSON, for whatever consumes the scan next, and needs the same facts in a
  shape that will not move under it.

The blocks exist because a table did not work. Six columns at eighty is a
thirteen-character `Finding` column, wrapping the one thing the user has to read
into a ribbon two words wide — and a finding nobody reads is a finding we did
not make. A block gives the message the full width and costs nothing but a
newline.

No renderer here ever prints a credential. Servers are printed through
`redacted_endpoint`, environment variables by name only. `test_report` holds
every format to that, against the secrets of the fixtures themselves.
"""

import json
import re
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from rich.console import Group, RenderableType
from rich.padding import Padding
from rich.rule import Rule as HorizontalRule
from rich.table import Table
from rich.text import Text

from mcp_scan import __version__
from mcp_scan.parsers import MCPServer
from mcp_scan.rules import Finding, Severity

#: The JSON contract, versioned so a consumer can tell when it moves. Bump it
#: when a key changes meaning or leaves; adding a key is not a break.
SCHEMA_VERSION = 1

SEVERITY_STYLES = {
    Severity.CRITICAL: "bold red",
    Severity.WARN: "yellow",
    Severity.INFO: "blue",
}

#: Width the severity label is padded to, so rule names line up under each other
#: down the left of a block. `CRITICAL` is the longest of them.
_SEVERITY_WIDTH = len("CRITICAL")

#: The characters that would otherwise turn text from a config file into
#: markdown: emphasis, code, links, raw HTML, and the pipe that ends a table
#: cell. Server names and commands are attacker-controlled, and a report is
#: something the user then pastes into an issue — so they go in escaped.
_MARKDOWN_SPECIAL = re.compile(r"([\\`*_\[\]<>|])")


class UnknownFormat(ValueError):
    """The `--output` path does not name a format we can write."""


class WouldOverwriteConfig(ValueError):
    """The `--output` path is a config file we just read.

    Writing there would destroy the very thing the user asked us to scan. A
    scanner does not modify the files it scans, so this is a refusal, not a
    prompt.
    """


@dataclass(frozen=True)
class Report:
    """Everything one scan established, in one place.

    `exit_code` is passed in rather than derived: what a code means is the CLI's
    contract with a pipeline, and this module's job is to write it down, not to
    decide it.
    """

    servers: list[MCPServer] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    exit_code: int = 0

    @property
    def complete(self) -> bool:
        """True when the scan actually looked at everything it was pointed at.

        A warning means it did not — a config that would not parse, a rule that
        crashed — and every count below is then a count of the part it managed
        to read, not of the configuration.
        """
        return not self.warnings

    @property
    def counts(self) -> Counter[Severity]:
        """How many findings of each severity, for the summary and the JSON."""
        return Counter(finding.severity for finding in self.findings)


def summary(report: Report) -> str:
    """One line saying what the scan found, in whatever medium is asking.

    Severities are counted worst-first: `3 findings in 2 servers: 1 CRITICAL,
    2 WARN.` A scan with no findings says so instead — the sentence a user
    reads first should not be an empty tally.
    """
    if not report.findings:
        return f"No findings in {count(len(report.servers), 'server')}."

    counts = report.counts
    tally = ", ".join(
        f"{counts[severity]} {severity}" for severity in sorted(counts, reverse=True)
    )
    return (
        f"{count(len(report.findings), 'finding')} in "
        f"{count(len(report.servers), 'server')}: {tally}."
    )


def count(total: int, noun: str) -> str:
    """`1 server`, `3 servers` — a count the user can read out loud."""
    return f"{total} {noun}" if total == 1 else f"{total} {noun}s"


def display_path(path: Path) -> str:
    """Abbreviate a path under the user's home to `~/...`.

    Shorter to read, and it keeps the user's name out of a report they may well
    paste somewhere public.
    """
    home = Path.home()
    if path.is_relative_to(home):
        return str(Path("~") / path.relative_to(home))
    return str(path)


def terminal(report: Report) -> RenderableType:
    """The findings, as blocks grouped under the server each one fired on.

    Servers come worst-first, and so do the findings within a server, so the
    thing to fix first is the thing at the top.
    """
    blocks: list[RenderableType] = [
        HorizontalRule("Findings", align="left", style="dim")
    ]

    for findings in _by_server(report.findings):
        blocks.append(Text())
        blocks.append(_server_heading(findings[0].server))
        blocks.extend(
            Padding(_finding_block(finding), (1, 0, 0, 2)) for finding in findings
        )

    return Group(*blocks)


def to_markdown(report: Report) -> str:
    """The scan as a document: what was found, and what to do about it.

    Written for someone who was not at the keyboard — a colleague, a ticket, a
    pull request — so it leads with the verdict, says plainly when the scan did
    not complete, and ends with the remediation for every rule that fired.
    """
    lines = [
        "# MCP scan report",
        "",
        f"**{_text(summary(report))}**",
        "",
    ]

    if not report.complete:
        lines += [
            "> [!WARNING]",
            f"> **The scan did not complete.** "
            f"{_text(count(len(report.warnings), 'warning').capitalize())} below: "
            f"part of the configuration was never checked, so the findings here "
            f"are not a complete picture of the risk.",
            "",
        ]

    lines += _markdown_findings(report)
    lines += _markdown_recommendations(report)
    lines += _markdown_servers(report)
    lines += _markdown_warnings(report)

    lines += [
        "---",
        "",
        f"Generated by [mcp-scan](https://github.com/jiru-labs/mcp-scan) "
        f"{__version__}. No credential value appears in this report: environment "
        f"variables are listed by name only, and a credential in a command line "
        f"or a URL is masked.",
        "",
    ]

    return "\n".join(lines)


def to_json(report: Report) -> str:
    """The scan as data, in a shape that will not move under a consumer.

    Paths are absolute here, unlike everywhere else: a tool reading this wants
    to open the file, and `~/…` is for humans.
    """
    counts = report.counts
    document = {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "mcp-scan", "version": __version__},
        "summary": {
            "complete": report.complete,
            "exit_code": report.exit_code,
            "servers_scanned": len(report.servers),
            "findings": len(report.findings),
            "by_severity": {
                str(severity): counts[severity]
                for severity in sorted(Severity, reverse=True)
            },
        },
        "findings": [
            {
                "rule": finding.rule_id,
                "title": finding.title,
                "severity": str(finding.severity),
                "message": finding.message,
                "remediation": finding.remediation,
                "server": {
                    "name": finding.server.name,
                    "host": finding.server.host,
                    "source": str(finding.server.source),
                },
            }
            for finding in report.findings
        ],
        "servers": [
            {
                "name": server.name,
                "host": server.host,
                "transport": server.transport,
                # Redacted, like everywhere else. A report that is safe to read
                # and unsafe to store would be no use to anyone.
                "endpoint": server.redacted_endpoint,
                "env_keys": list(server.env_keys),
                "env_static_keys": list(server.env_static_keys),
                "source": str(server.source),
            }
            for server in report.servers
        ],
        "warnings": list(report.warnings),
    }
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


#: What `--output` can write, keyed by the extension that asks for it.
FORMATS = {
    ".md": to_markdown,
    ".markdown": to_markdown,
    ".json": to_json,
}


def write(report: Report, path: Path) -> None:
    """Write `report` to `path`, in the format its extension asks for.

    Raises:
        UnknownFormat: The extension names no format we can write.
        WouldOverwriteConfig: The path is one of the config files we just read.
    """
    render = FORMATS.get(path.suffix.lower())
    if render is None:
        raise UnknownFormat(
            f"cannot write '{path.name}': expected one of "
            f"{', '.join(sorted(FORMATS))} — the extension chooses the format"
        )

    _refuse_to_overwrite_a_config(report, path)

    path.write_text(render(report), encoding="utf-8")


def _refuse_to_overwrite_a_config(report: Report, path: Path) -> None:
    """Stop `--output ~/.claude.json` from writing a report over a live config.

    The extension check does not catch this one: a Claude Code config *is* a
    `.json` file, and the flag is one keystroke away from the path we just read
    it from. A scanner that eats the configuration it was pointed at is worse
    than no scanner, so this is refused before anything is opened for writing.
    """
    scanned = {_resolved(server.source) for server in report.servers}
    if _resolved(path) in scanned:
        raise WouldOverwriteConfig(
            f"refusing to write the report to '{path}': that is a config file "
            f"this scan just read. Pick another path — mcp-scan does not modify "
            f"the files it scans."
        )


def _resolved(path: Path) -> Path:
    """A path in a form two spellings of the same file agree on."""
    try:
        return path.resolve()
    except OSError:  # pragma: no cover — a path the OS will not even resolve
        return path.absolute()


def _by_server(findings: Sequence[Finding]) -> list[list[Finding]]:
    """Findings bucketed by the server they fired on, worst-hit server first.

    A server is identified by where it was declared, not by its name alone: two
    hosts may each declare a `github`, and they are not the same server.

    Findings arrive sorted worst-first and each bucket keeps that order, so
    ordering the buckets by their worst finding preserves it across the report
    as a whole — the first thing printed is still the worst thing found.
    """
    groups: dict[tuple[str, str, Path], list[Finding]] = {}
    for finding in findings:
        server = finding.server
        key = (server.name, server.host, server.source)
        groups.setdefault(key, []).append(finding)

    return sorted(
        groups.values(),
        key=lambda group: -max(finding.severity for finding in group),
    )


def _server_heading(server: MCPServer) -> Text:
    """The heading a server's findings are filed under: who, then where.

    Printed once per server, rather than repeated down a `Server`, a `Host` and
    a `Source` column on every row.

    The path gets a line to itself because it is the one part that is long: a
    Claude Desktop config lives at `~/Library/Application Support/Claude/…`,
    which alone is most of an eighty-column terminal, and sharing a line with it
    would push the server's own name into a wrap.
    """
    return Text.assemble(
        (server.name, "bold"),
        "  ",
        (server.host, "cyan"),
        "\n",
        (display_path(server.source), "dim"),
    )


def _finding_block(finding: Finding) -> Text:
    """One finding: severity and rule on top, the message below in full.

    Text from a config reaches this as a `Text` fragment, never as console
    markup: a server called `evil [/bold]` is printed, not parsed.
    """
    return Text.assemble(
        (str(finding.severity).ljust(_SEVERITY_WIDTH), SEVERITY_STYLES[finding.severity]),
        "  ",
        (finding.rule_id, "bold"),
        "\n",
        finding.message,
    )


def _markdown_findings(report: Report) -> list[str]:
    """The findings table — the part a reader scans before reading anything."""
    if not report.findings:
        return ["## Findings", "", "None. Every server checked came back clean.", ""]

    rows = [
        "| Severity | Rule | Server | Host | Finding |",
        "| --- | --- | --- | --- | --- |",
    ]
    rows += [
        f"| {_text(str(finding.severity))} "
        f"| {_code(finding.rule_id)} "
        f"| {_code(finding.server.name)} "
        f"| {_text(finding.server.host)} "
        f"| {_text(finding.message)} |"
        for finding in report.findings
    ]

    return ["## Findings", "", *rows, ""]


def _markdown_recommendations(report: Report) -> list[str]:
    """What to actually do, once per rule that fired rather than once per row.

    The remediation for a rule is the same however many servers tripped it, so
    it is written once and the servers are listed under it. A reader with four
    findings from one rule has one thing to go and do, and should be told so.
    """
    if not report.findings:
        return []

    lines = ["## Recommendations", ""]

    for findings in _by_rule(report.findings):
        rule = findings[0]
        servers = ", ".join(
            _code(finding.server.name) for finding in _unique_by_server(findings)
        )
        lines += [
            f"### {_text(str(rule.severity))} — {_text(rule.title)}",
            "",
            f"{_code(rule.rule_id)} · affects {servers}",
            "",
            # Written by us, in this repository, as markdown — so it is the one
            # string here that goes in unescaped. Everything else on this page
            # came from a config file and is therefore somebody else's text.
            rule.remediation or "_No remediation given._",
            "",
        ]

    return lines


def _markdown_servers(report: Report) -> list[str]:
    """What was scanned — the other half of a report, and the easy half to skip.

    A reader cannot judge a clean result without it: `no findings` means one
    thing across nine servers and quite another across none.
    """
    if not report.servers:
        return ["## Servers scanned", "", "None.", ""]

    rows = [
        "| Server | Host | Transport | Command / URL | Env keys | Source |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    rows += [
        f"| {_code(server.name)} "
        f"| {_text(server.host)} "
        f"| {_text(server.transport)} "
        f"| {_code(server.redacted_endpoint) if server.redacted_endpoint else '—'} "
        f"| {', '.join(_code(key) for key in server.env_keys) or '—'} "
        f"| {_code(display_path(server.source))} |"
        for server in report.servers
    ]

    return ["## Servers scanned", "", *rows, ""]


def _markdown_warnings(report: Report) -> list[str]:
    """Everything the scan failed to look at, said out loud in the document too.

    The banner at the top says the scan fell short; this says where, which is
    what the person fixing it needs.
    """
    if report.complete:
        return []

    return [
        "## What was not checked",
        "",
        *(f"- {_text(warning)}" for warning in report.warnings),
        "",
    ]


def _by_rule(findings: Sequence[Finding]) -> list[list[Finding]]:
    """Findings bucketed by the rule that made them, worst rule first."""
    groups: dict[str, list[Finding]] = {}
    for finding in findings:
        groups.setdefault(finding.rule_id, []).append(finding)

    return sorted(
        groups.values(),
        key=lambda group: (-group[0].severity, group[0].rule_id),
    )


def _unique_by_server(findings: Iterable[Finding]) -> list[Finding]:
    """One finding per server, for a rule that fired on the same server twice."""
    seen: dict[tuple[str, str, Path], Finding] = {}
    for finding in findings:
        server = finding.server
        seen.setdefault((server.name, server.host, server.source), finding)
    return list(seen.values())


def _text(value: str) -> str:
    """Text from a config, rendered as text rather than as markdown.

    A server named `**` or a command holding a `|` would otherwise reshape the
    document it is reported in — mangling a table at best, and at worst letting
    a config decide how the report about it reads.
    """
    return _MARKDOWN_SPECIAL.sub(r"\\\1", value).replace("\n", " ")


def _code(value: str) -> str:
    """The same, as an inline code span, with the backticks it takes to hold it.

    A value containing backticks needs a longer fence than the run inside it,
    and one that starts or ends with a backtick needs a space to breathe. The
    pipe is escaped even in here: inside a table cell it would still end the
    cell, code span or not.
    """
    value = value.replace("|", "\\|").replace("\n", " ")

    longest = max((len(run) for run in re.findall(r"`+", value)), default=0)
    fence = "`" * (longest + 1)
    padding = " " if value.startswith("`") or value.endswith("`") else ""

    return f"{fence}{padding}{value}{padding}{fence}"


def servers_table(servers: Sequence[MCPServer]) -> Table:
    """The `list` command's table of servers, grouped by host.

    Lives here with the other renderers, though it is not part of a scan report:
    it prints the same servers, redacted the same way.
    """
    table = Table(title="MCP servers")
    table.add_column("Host", style="cyan")
    table.add_column("Server", style="bold")
    table.add_column("Transport")
    table.add_column("Command / URL", overflow="fold")
    table.add_column("Env keys", overflow="fold")
    table.add_column("Source", overflow="fold", style="dim")

    for index, (host, group) in enumerate(_group_by_host(servers).items()):
        if index:
            table.add_section()
        for position, server in enumerate(group):
            table.add_row(
                # The host labels its group once, on the first of its servers.
                host if position == 0 else "",
                Text(server.name),
                server.transport,
                Text(server.redacted_endpoint or "-"),
                Text(", ".join(server.env_keys) or "-"),
                Text(display_path(server.source)),
            )

    return table


def _group_by_host(servers: Sequence[MCPServer]) -> dict[str, list[MCPServer]]:
    """Servers bucketed by host, hosts in the order they were discovered."""
    groups: dict[str, list[MCPServer]] = {}
    for server in servers:
        groups.setdefault(server.host, []).append(server)
    return groups
