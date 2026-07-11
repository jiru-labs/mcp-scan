"""Typer entrypoint for the mcp-scan CLI."""

import typer
from rich.console import Console

from mcp_scan import __version__

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
