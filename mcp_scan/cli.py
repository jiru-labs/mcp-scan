"""Typer entrypoint for the mcp-scan CLI."""

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from mcp_scan import __version__
from mcp_scan.discovery import HOST_UNKNOWN, ConfigLocation, find_all_configs
from mcp_scan.parsers import MCPServer, parse_config_file
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
)

SEVERITY_STYLES = {
    Severity.CRITICAL: "bold red",
    Severity.WARN: "yellow",
    Severity.INFO: "blue",
}


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
        console.print(_servers_table(servers))

    _print_warnings(warnings)

    # Only explain an empty result that the warnings above have not already
    # explained.
    if not servers and not warnings:
        console.print(f"[yellow]{_nothing_to_report(locations)}[/yellow]")


@app.command()
def scan(
    config: Annotated[Path | None, CONFIG_OPTION] = None,
) -> None:
    """Scan your MCP servers for security risks.

    Runs every detection rule against every server found, and reports what they
    flag, worst first. Read-only: no config file is ever modified.
    """
    locations, servers, warnings = _read_servers(config)

    result = run_rules(servers, load_rules())
    warnings.extend(result.warnings)

    if result.findings:
        console.print(_findings_table(result.findings))

    _print_warnings(warnings)

    if servers and not result.findings:
        console.print(f"[green]No findings in {_count(len(servers), 'server')}.[/green]")
    elif not servers and not warnings:
        # Nothing was scanned, and no warning has already explained why.
        console.print(f"[yellow]{_nothing_to_report(locations)}[/yellow]")


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


def _count(total: int, noun: str) -> str:
    """`1 server`, `3 servers` — a count the user can read out loud."""
    return f"{total} {noun}" if total == 1 else f"{total} {noun}s"


def _servers_table(servers: list[MCPServer]) -> Table:
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
                _quoted(server.name),
                server.transport,
                _quoted(server.redacted_endpoint or "-"),
                _quoted(", ".join(server.env_keys) or "-"),
                _quoted(_display_path(server.source)),
            )

    return table


def _findings_table(findings: list[Finding]) -> Table:
    """Render findings worst-first, one horizontal rule between severities."""
    table = Table(title="Findings")
    table.add_column("Severity")
    table.add_column("Rule", style="bold")
    table.add_column("Server")
    table.add_column("Host", style="cyan")
    table.add_column("Finding", overflow="fold")
    table.add_column("Source", overflow="fold", style="dim")

    previous: Severity | None = None
    for finding in findings:
        if previous is not None and finding.severity != previous:
            table.add_section()
        previous = finding.severity

        table.add_row(
            _severity_label(finding.severity),
            finding.rule_id,
            _quoted(finding.server.name),
            finding.server.host,
            # A rule's message quotes the server it fired on, so it is no more
            # trustworthy than the config the server came from.
            _quoted(finding.message),
            _quoted(_display_path(finding.server.source)),
        )

    return table


def _severity_label(severity: Severity) -> Text:
    return Text(str(severity), style=SEVERITY_STYLES[severity])


def _group_by_host(servers: list[MCPServer]) -> dict[str, list[MCPServer]]:
    """Servers bucketed by host, hosts in the order they were discovered."""
    groups: dict[str, list[MCPServer]] = {}
    for server in servers:
        groups.setdefault(server.host, []).append(server)
    return groups


def _display_path(path: Path) -> str:
    """Abbreviate a path under the user's home to `~/...`, to keep rows narrow."""
    home = Path.home()
    if path.is_relative_to(home):
        return str(Path("~") / path.relative_to(home))
    return str(path)
