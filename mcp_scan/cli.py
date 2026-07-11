"""Typer entrypoint for the mcp-scan CLI."""

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from mcp_scan import __version__
from mcp_scan.discovery import HOST_UNKNOWN, ConfigLocation, find_all_configs
from mcp_scan.parsers import MCPServer, parse_config_file

app = typer.Typer(
    name="mcp-scan",
    help="Scan local MCP configurations for security risks.",
    no_args_is_help=True,
    add_completion=False,
)

console = Console()


@app.callback()
def main() -> None:
    """Keep mcp-scan a command group even while only one command exists."""


@app.command()
def version() -> None:
    """Print the mcp-scan version."""
    console.print(f"mcp-scan {__version__}")


@app.command("list")
def list_servers(
    config: Annotated[
        Path | None,
        typer.Option(
            "--config",
            "-c",
            help="Parse this config file instead of discovering the installed hosts.",
        ),
    ] = None,
) -> None:
    """List the MCP servers declared in your local host configs.

    Servers are grouped by the host that declares them. Environment variables
    are reported by name only; their values are never read into the report.
    """
    locations = (
        [ConfigLocation(host=HOST_UNKNOWN, path=config, exists=True)]
        if config is not None
        else _installed_host_configs()
    )

    servers: list[MCPServer] = []
    warnings: list[str] = []
    for location in locations:
        result = parse_config_file(location.path, host=location.host)
        servers.extend(result.servers)
        warnings.extend(result.warnings)

    if servers:
        console.print(_servers_table(servers))

    for warning in warnings:
        console.print(f"[yellow]warning:[/yellow] {warning}")

    # Only explain an empty result that the warnings above have not already
    # explained.
    if not servers and not warnings:
        message = (
            "No MCP servers declared in any config file."
            if locations
            else "No MCP config files found."
        )
        console.print(f"[yellow]{message}[/yellow]")


def _installed_host_configs() -> list[ConfigLocation]:
    """The host configs that actually exist on this machine."""
    return [location for location in find_all_configs() if location.exists]


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
                server.name,
                server.transport,
                server.endpoint or "-",
                ", ".join(server.env_keys) or "-",
                _display_path(server.source),
            )

    return table


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
