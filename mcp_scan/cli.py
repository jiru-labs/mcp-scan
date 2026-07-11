"""Typer entrypoint for the mcp-scan CLI."""

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.text import Text

from mcp_scan import __version__, report
from mcp_scan.discovery import HOST_UNKNOWN, ConfigLocation, find_all_configs
from mcp_scan.parsers import MCPServer, parse_config_file
from mcp_scan.report import Report, SEVERITY_STYLES
from mcp_scan.rules import Finding, Severity, load_rules, run_rules

app = typer.Typer(
    name="mcp-scan",
    help="Scan local MCP configurations for security risks.",
    no_args_is_help=True,
    add_completion=False,
)

console = Console()

CONFIG_OPTION = typer.Option(
    "--config",
    "-c",
    help="Read this config file instead of discovering the installed hosts.",
    # Click checks a path for readability before the command ever runs, and
    # fails with a usage error when the check fails. That is the wrong answer
    # for a config we lack permission to open: it is not a mistake in how the
    # user invoked us, it is a config we could not scan, and we report it as
    # the warning it is. The parser opens the file and handles the refusal.
    readable=False,
)

QUIET_OPTION = typer.Option(
    "--quiet",
    "-q",
    help="Print the summary line only, without the findings.",
)

OUTPUT_OPTION = typer.Option(
    "--output",
    "-o",
    help=(
        "Also write the report to this file. The extension picks the format: "
        ".md for markdown, .json for JSON."
    ),
)

#: What `scan` returns to the shell, so a script can act on the verdict without
#: parsing the output. Keyed by the *worst* finding of the run.
#:
#: INFO returns 0 along with a clean scan: it is something worth telling the
#: user, not something worth failing their build over. A pipeline that wants to
#: be stricter than that can read the summary line.
EXIT_CODES = {
    Severity.INFO: 0,
    Severity.WARN: 1,
    Severity.CRITICAL: 2,
}

EXIT_CLEAN = 0

#: The run did not complete: a config could not be read, a rule crashed, or the
#: report the user asked for could not be written.
#:
#: Distinct from the codes above, and it outranks every one of them. They are
#: verdicts — each says "I checked everything, and the worst of it was X" — and
#: a run that failed to look at part of the config cannot honestly say that, at
#: any severity. 0 would be the dangerous version of the lie (a build passes
#: green over a config nobody read), but 1 and 2 are the same claim of complete
#: coverage, and are just as untrue.
#:
#: So this code says the one thing that is true: the verdict is unknown, go and
#: look. Nothing is hidden by it — every finding the scan did manage to make is
#: still reported in full — but the single integer says "I don't know" rather
#: than overstating what the run actually managed to check.
EXIT_INCOMPLETE = 3


@app.callback()
def main() -> None:
    """Keep mcp-scan a command group even while only one command exists."""


@app.command()
def version() -> None:
    """Print the mcp-scan version."""
    console.print(f"mcp-scan {__version__}")


@app.command("list")
def list_servers(
    config: Annotated[Path | None, CONFIG_OPTION] = None,
) -> None:
    """List the MCP servers declared in your local host configs.

    Servers are grouped by the host that declares them. No credential is ever
    printed: environment variables are reported by name only, and a credential
    passed inline in a command argument is masked.
    """
    locations, servers, warnings = _read_servers(config)

    if servers:
        console.print(report.servers_table(servers))

    _print_warnings(warnings)

    # Only explain an empty result that the warnings above have not already
    # explained.
    if not servers and not warnings:
        console.print(f"[yellow]{_nothing_to_report(locations)}[/yellow]")


@app.command()
def scan(
    config: Annotated[Path | None, CONFIG_OPTION] = None,
    quiet: Annotated[bool, QUIET_OPTION] = False,
    output: Annotated[Path | None, OUTPUT_OPTION] = None,
) -> None:
    """Scan your MCP servers for security risks.

    Runs every detection rule against every server found, and reports what they
    flag, worst first. Read-only: no config file is ever modified.

    Exits 0 when nothing worse than an INFO finding is reported, 1 when the
    worst is a WARN, and 2 when a CRITICAL is found — so a script can gate on
    the verdict without reading the output. A run that could not complete,
    because a config would not parse, a rule crashed, or --output could not be
    written, exits 3 rather than passing off a partial look as a verdict.

    With --output, the same report is written to a file as markdown or JSON,
    for sharing or for whatever consumes the scan next. With --quiet, the
    summary line is all it prints, and the exit code carries the rest.
    """
    locations, servers, warnings = _read_servers(config)

    result = run_rules(servers, load_rules())
    warnings.extend(result.warnings)

    scanned = Report(
        servers=servers,
        findings=result.findings,
        warnings=warnings,
        exit_code=_exit_code(result.findings, warnings),
    )

    if scanned.findings and not quiet:
        console.print(report.terminal(scanned))
        console.print()

    # A warning survives --quiet. It does not report a risk, it reports that we
    # failed to look for one — a config we could not read, a rule that crashed —
    # and a CI run that swallows *that* is a CI run that passes green over an
    # unscanned config.
    _print_warnings(warnings)

    if scanned.findings:
        console.print(Text(report.summary(scanned), style=SEVERITY_STYLES[max(scanned.counts)]))
    elif servers:
        console.print(Text(report.summary(scanned), style="green"))
    elif not warnings:
        # Nothing was scanned, and no warning has already explained why.
        console.print(f"[yellow]{_nothing_to_report(locations)}[/yellow]")

    if warnings:
        # Said out loud, because the summary line above it cannot say it. That
        # line counts what the rules found, and a scan that skipped half the
        # config still reports "no findings" — true of what it read, and
        # worthless as a verdict. This is the sentence that stops a user reading
        # green where there is only silence.
        console.print(_incomplete(warnings))

    if output is not None and not _written(scanned, output):
        # Asked for a report and given none, a pipeline must not carry on as if
        # it had one — least of all one about to read a stale file from the last
        # run. Whatever the findings were, this run did not deliver.
        raise typer.Exit(EXIT_INCOMPLETE)

    raise typer.Exit(scanned.exit_code)


def _written(scanned: Report, output: Path) -> bool:
    """Write the report to `output`, saying whether it got there.

    Every way this fails is the user's to fix — a format we do not write, a path
    that is one of their configs, a directory that does not exist — so each one
    is reported as itself rather than as a traceback.
    """
    try:
        report.write(scanned, output)
    except (report.UnknownFormat, report.WouldOverwriteConfig) as exc:
        console.print(Text.assemble(("error: ", "bold red"), Text(str(exc))))
        return False
    except OSError as exc:
        console.print(
            Text.assemble(
                ("error: ", "bold red"), Text(f"could not write '{output}': {exc}")
            )
        )
        return False

    console.print(f"[dim]Report written to {_quoted(str(output))}[/dim]")
    return True


def _read_servers(
    config: Path | None,
) -> tuple[list[ConfigLocation], list[MCPServer], list[str]]:
    """Read the servers to work on, from `config` or from the installed hosts.

    Returns the config files read alongside the servers, so a caller can tell
    "no host installed" from "a host with no servers".
    """
    locations = (
        [ConfigLocation(host=HOST_UNKNOWN, path=config, exists=True)]
        if config is not None
        else [location for location in find_all_configs() if location.exists]
    )

    servers: list[MCPServer] = []
    warnings: list[str] = []
    for location in locations:
        result = parse_config_file(location.path, host=location.host)
        servers.extend(result.servers)
        warnings.extend(result.warnings)

    return locations, servers, warnings


def _print_warnings(warnings: list[str]) -> None:
    for warning in warnings:
        console.print(Text.assemble(("warning: ", "yellow"), _quoted(warning)))


def _quoted(value: str) -> Text:
    """Text straight from a config file, rendered literally.

    Server names, commands and paths are attacker-controlled input. Passed to
    Rich as a plain string, a name like `evil [/bold]` would be read as console
    markup — at best mangling the output, at worst raising MarkupError and
    taking the command down. `Text` renders it verbatim.
    """
    return Text(value)


def _nothing_to_report(locations: list[ConfigLocation]) -> str:
    """Why a run that read no servers found nothing to say."""
    if not locations:
        return "No MCP config files found."
    return "No MCP servers declared in any config file."


def _exit_code(findings: list[Finding], warnings: list[str]) -> int:
    """What the run returns to the shell: the worst thing it found.

    A warning outranks every finding, because it is not a statement about the
    config — it is a statement about the scan, and it says the scan is not
    trustworthy. See `EXIT_INCOMPLETE`.

    A clean scan and a scan that found nothing to scan both return 0. They are
    different results, and the output says which — but neither is a risk, and
    an exit code is not the place to argue about it.
    """
    if warnings:
        return EXIT_INCOMPLETE
    if not findings:
        return EXIT_CLEAN
    return EXIT_CODES[max(finding.severity for finding in findings)]


def _incomplete(warnings: list[str]) -> Text:
    """The line that says the run above it is not a verdict."""
    return Text(
        f"Scan incomplete: {report.count(len(warnings), 'warning')} above. "
        f"Part of your configuration was not checked.",
        style="yellow",
    )
