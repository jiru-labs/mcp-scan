"""Render a scan for the reader it is aimed at.

Four readers, four shapes, one set of facts:

* the terminal, where findings are printed as blocks — a heading per server,
  then each finding under it with room for the message to be a sentence;
* markdown, for a report shared with someone who was not at the keyboard, and
  therefore needs the summary, the findings and what to do about them;
* JSON, for whatever consumes the scan next, and needs the same facts in a
  shape that will not move under it;
* SARIF, for a CI security dashboard — GitHub code scanning, GitLab — which
  will read no other shape, and turns the findings into annotations on the pull
  request that introduced them.

The blocks exist because a table did not work. Six columns at eighty is a
thirteen-character `Finding` column, wrapping the one thing the user has to read
into a ribbon two words wide — and a finding nobody reads is a finding we did
not make. A block gives the message the full width and costs nothing but a
newline.

SARIF speaks its own severities, so ours map onto them: CRITICAL is an `error`,
WARN a `warning`, INFO a `note`. That much a dashboard reads on its own; GitHub
additionally files an alert by the `security-severity` property, and only tags a
result as a security problem at all when the rule says it is one — so each rule
carries both, and mcp-config-audit's findings arrive in the Security tab as security
findings rather than as lint.

No renderer here ever prints a credential. Servers are printed through
`redacted_endpoint`, environment variables by name only. `test_report` holds
every format to that, against the secrets of the fixtures themselves.
"""

import hashlib
import json
import re
from collections import Counter
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from rich.console import Group, RenderableType
from rich.padding import Padding
from rich.rule import Rule as HorizontalRule
from rich.table import Table
from rich.text import Text

from mcp_config_audit import __version__
from mcp_config_audit.parsers import MCPServer
from mcp_config_audit.rules import Finding, Severity

#: The JSON contract, versioned so a consumer can tell when it moves. Bump it
#: when a key changes meaning or leaves; adding a key is not a break.
SCHEMA_VERSION = 1

#: The SARIF dialect we write. 2.1.0 is the OASIS standard, and what GitHub
#: code scanning and GitLab both ingest.
SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

#: Where mcp-config-audit lives, for the tool block of a report read far from here.
PROJECT_URL = "https://github.com/jiru-labs/mcp-config-audit"

SEVERITY_STYLES = {
    Severity.CRITICAL: "bold red",
    Severity.WARN: "yellow",
    Severity.INFO: "blue",
}

#: Our severities in SARIF's vocabulary. SARIF has a fourth level, `none`, for a
#: result that reports something other than a problem; nothing here is that.
SARIF_LEVELS = {
    Severity.CRITICAL: "error",
    Severity.WARN: "warning",
    Severity.INFO: "note",
}

#: The same three severities again, on the CVSS-like scale GitHub sorts security
#: alerts by: 9.0+ is critical, 7.0 high, 4.0 medium, anything below that low.
#: Without this a security alert is filed by `level` alone, which puts every WARN
#: and INFO in the same bucket — so the numbers exist to keep the ordering the
#: user already sees in the terminal.
SARIF_SECURITY_SEVERITIES = {
    Severity.CRITICAL: "9.0",
    Severity.WARN: "5.5",
    Severity.INFO: "2.0",
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

    #: The config files this scan read, or tried to. Held apart from `servers`
    #: because a config that parsed to nothing — malformed, empty, or simply
    #: without an `mcpServers` block, which is most of a real `~/.claude.json` —
    #: still contributes a path that `--output` must refuse to write over. A
    #: guard built from `servers` would wave that file through and destroy it,
    #: which is exactly the config a confused user is most likely to aim at.
    sources: list[Path] = field(default_factory=list)

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


def display_source(server: MCPServer) -> str:
    """Where a server was declared: `~/.claude.json:12`.

    The `path:line` spelling is not decoration — it is what an editor and most
    terminals will open at the line, and it is the difference between telling a
    reader which file to go and search and telling them where to look. A server
    whose line the parser could not find is named by its file alone.
    """
    path = display_path(server.source)
    return f"{path}:{server.line}" if server.line else path


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
        f"Generated by [mcp-config-audit](https://github.com/jiru-labs/mcp-config-audit) "
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
        "tool": {"name": "mcp-config-audit", "version": __version__},
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
                    # Null when the parser could not find the declaration in the
                    # config's text. A consumer that opens the file gets a line to
                    # jump to; one that gets null knows there is none to jump to,
                    # which is not the same thing as line 1.
                    "line": finding.server.line,
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
                "line": server.line,
            }
            for server in report.servers
        ],
        "warnings": list(report.warnings),
    }
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


def to_sarif(report: Report) -> str:
    """The scan as SARIF, for a CI dashboard to annotate a pull request with.

    Every finding becomes a result, pointing at the config file the server was
    declared in; every rule that fired becomes a rule in the tool's driver, once,
    carrying its remediation as the alert's help text. Severities map as the
    module docstring says: CRITICAL/WARN/INFO to error/warning/note.

    A finding is located at the line its server is declared on, which is what puts
    the alert on the offending server in the diff of a pull request rather than on
    the first line of the config. That line comes from the parser, which reads it
    back out of the config's own text (`parsers._ServerLines`).

    A server the parser could not find a line for falls back to line 1 — the
    honest reading of which is "somewhere in this file", and the alert claims
    nothing beyond that. It is a fallback and not an omission because GitHub
    refuses to display a result carrying no region at all: dropping the region
    would drop the finding.
    """
    rules = _sarif_rules(report.findings)
    index = {rule["id"]: position for position, rule in enumerate(rules)}

    document = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcp-config-audit",
                        "version": __version__,
                        "informationUri": PROJECT_URL,
                        "rules": rules,
                    }
                },
                "results": [
                    _sarif_result(finding, index) for finding in report.findings
                ],
                # SARIF's way of saying what the markdown banner and the JSON's
                # `complete` say: the run fell short, and its findings are not a
                # verdict. A dashboard that reads only the results would otherwise
                # show a scan that never finished as a scan that came back clean.
                "invocations": [
                    {
                        "executionSuccessful": report.complete,
                        "toolExecutionNotifications": [
                            {"level": "warning", "message": {"text": warning}}
                            for warning in report.warnings
                        ],
                    }
                ],
            }
        ],
    }
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


def _sarif_rules(findings: Sequence[Finding]) -> list[dict]:
    """One entry per rule that fired, in the order the findings first name them.

    A rule appears once however many servers tripped it — the driver describes
    the rule, and the results below it say where it fired.
    """
    rules: dict[str, dict] = {}
    for finding in findings:
        if finding.rule_id in rules:
            continue

        rule = {
            "id": finding.rule_id,
            "shortDescription": {"text": finding.title},
            "defaultConfiguration": {"level": SARIF_LEVELS[finding.severity]},
            "properties": {
                # `security` is what makes GitHub file the result as a security
                # alert rather than a code-quality one, and the number below is
                # how it then ranks it.
                "tags": ["security", "mcp"],
                "security-severity": SARIF_SECURITY_SEVERITIES[finding.severity],
            },
        }
        if finding.remediation:
            # Ours, written as markdown, and rendered as such by a dashboard that
            # can — the same string the markdown report puts under
            # "Recommendations".
            rule["help"] = {
                "text": finding.remediation,
                "markdown": finding.remediation,
            }

        rules[finding.rule_id] = rule

    return list(rules.values())


def _sarif_result(finding: Finding, index: dict[str, int]) -> dict:
    """One finding, as the result a dashboard turns into an alert.

    The message names the server, which no other renderer's has to: the terminal
    heads a block with it, markdown and JSON each give it a field of its own, and
    SARIF has nowhere to put it but here. Two servers in one config file trip a
    rule and produce two alerts on the same file — and an alert that cannot say
    which of them it is about is an alert nobody can act on.
    """
    server = finding.server
    return {
        "ruleId": finding.rule_id,
        "ruleIndex": index[finding.rule_id],
        "level": SARIF_LEVELS[finding.severity],
        # The message is already redacted by the rule that made it, and the name
        # and host come from the config, where neither is a secret.
        "message": {"text": f"{server.name} ({server.host}): {finding.message}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": _sarif_uri(server.source)},
                    # Line 1 stands for "this file, line unknown" — see `to_sarif`.
                    "region": {"startLine": server.line or 1},
                }
            }
        ],
        "partialFingerprints": {"mcpScanFinding/v1": _sarif_fingerprint(finding)},
    }


def _sarif_uri(source: Path) -> str:
    """Where a config file is, said in the way a dashboard can act on.

    A config inside the repository being scanned is named relative to it, which
    is what lets GitHub map the alert onto a file in the pull request — the whole
    point of the format for a project-scoped `.mcp.json` or `.vscode/mcp.json`.

    A config outside it — `~/.claude.json`, and every other host's — gets an
    absolute `file://` URI. GitHub cannot map that onto the repository, and
    should not: the file is not in it. The alert is still reported, still says
    which server and which rule, and names a path the developer can open.
    """
    path = _resolved(source)
    try:
        return path.relative_to(_resolved(Path.cwd())).as_posix()
    except ValueError:
        return path.as_uri()


def _sarif_fingerprint(finding: Finding) -> str:
    """A stable identity for a finding, so a dashboard can track it across runs.

    GitHub matches an alert to the one it saw yesterday by fingerprint, and
    generates one itself when a result carries none — from the rule and the
    location, which is a file and a line. Two findings of one rule on one server
    share both, so they would be fingerprinted alike, collapse into a single
    alert, and one of them would vanish on upload. A dropped finding is the one
    failure a scanner may not have, so the fingerprint is ours to compute.

    It is built from everything that tells two findings apart: the rule, the
    server — named, as everywhere else, by where it was declared and not by its
    name alone — and the message, which is what distinguishes one finding of a
    rule from the next one it makes on the same server (`Rule.check` returns a
    list because a command may carry two credentials, and each is its own alert).

    The line is deliberately not among them, though the result now carries one.
    A finding does not become a different finding because a server moved down the
    file, and hashing the line would retire every alert on a config the moment
    somebody added a server above them.

    Including the message costs a re-created alert whenever a rule is reworded.
    That is the right way round: an alert that comes back after a rewrite is a
    nuisance, and a finding that never arrives is a vulnerability nobody was told
    about.

    The file is identified the way the result's location is, rather than by its
    absolute path — the fingerprint has to survive the move from the developer's
    machine to a CI runner, whose checkout is somewhere else entirely. Nothing
    hashed here is a credential; a message reaches us already redacted.
    """
    server = finding.server
    identity = "\0".join(
        [
            finding.rule_id,
            server.host,
            server.name,
            _sarif_uri(server.source),
            finding.message,
        ]
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


#: What `--output` can write, keyed by the extension that asks for it. The
#: compound `.sarif.json` is here because it is the name GitHub's own docs use,
#: and `Path.suffix` would read it as plain `.json` — writing a JSON report to a
#: file the pipeline then rejects as invalid SARIF, for a reason nobody could see
#: from the filename.
FORMATS = {
    ".md": to_markdown,
    ".markdown": to_markdown,
    ".json": to_json,
    ".sarif": to_sarif,
    ".sarif.json": to_sarif,
}


def write(report: Report, path: Path) -> None:
    """Write `report` to `path`, in the format its extension asks for.

    Raises:
        UnknownFormat: The extension names no format we can write.
        WouldOverwriteConfig: The path is one of the config files we just read.
    """
    render = _format_for(path)
    if render is None:
        raise UnknownFormat(
            f"cannot write '{path.name}': expected one of "
            f"{', '.join(sorted(FORMATS))} — the extension chooses the format"
        )

    _refuse_to_overwrite_a_config(report, path)

    path.write_text(render(report), encoding="utf-8")


def _format_for(path: Path) -> Callable[[Report], str] | None:
    """The renderer a filename asks for, longest extension first.

    Two suffixes before one, so `results.sarif.json` is SARIF rather than the
    JSON its last suffix alone would name.
    """
    suffixes = [suffix.lower() for suffix in path.suffixes]
    if not suffixes:
        return None

    compound = "".join(suffixes[-2:])
    return FORMATS.get(compound) or FORMATS.get(suffixes[-1])


def _refuse_to_overwrite_a_config(report: Report, path: Path) -> None:
    """Stop `--output ~/.claude.json` from writing a report over a live config.

    The extension check does not catch this one: a Claude Code config *is* a
    `.json` file, and the flag is one keystroke away from the path we just read
    it from. A scanner that eats the configuration it was pointed at is worse
    than no scanner, so this is refused before anything is opened for writing.

    Checked against the files the scan *read*, not the servers it parsed out of
    them — a config that yielded no servers is still a config, and overwriting it
    is still destroying the user's file.
    """
    scanned = {_resolved(source) for source in report.sources}
    if _resolved(path) in scanned:
        raise WouldOverwriteConfig(
            f"refusing to write the report to '{path}': that is a config file "
            f"this scan just read. Pick another path — mcp-config-audit does not modify "
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
        (display_source(server), "dim"),
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
        f"| {_code(display_source(server))} |"
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
