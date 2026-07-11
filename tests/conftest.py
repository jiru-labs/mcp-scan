"""Shared fixtures for the test suite."""

import json
import shutil
from dataclasses import dataclass
from pathlib import Path

import pytest

from mcp_scan.discovery import (
    CLAUDE_CODE_CONFIG_RELPATH,
    CLAUDE_CODE_PROJECT_CONFIG_FILENAME,
    CLAUDE_DESKTOP_CONFIG_RELPATH,
    CURSOR_CONFIG_RELPATH,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def sample_config() -> Path:
    """A well-formed config with a local, a credentialed and a remote server."""
    return FIXTURES_DIR / "sample_config.json"


@pytest.fixture
def malformed_config() -> Path:
    """A config whose JSON does not parse."""
    return FIXTURES_DIR / "malformed_config.json"


@pytest.fixture
def markup_config() -> Path:
    """A config whose server name and args read as Rich console markup.

    Names come from the config, so they are attacker-controlled: rendering one
    as markup would mangle the report or crash the command.
    """
    return FIXTURES_DIR / "markup_config.json"


@pytest.fixture
def sample_secrets(sample_config: Path) -> list[str]:
    """Every env var value in the sample config.

    Read straight from the fixture so the guarantee still holds if the fixture
    changes: none of these strings may ever reach a parse result or the
    terminal.
    """
    return _env_values(sample_config)


@dataclass(frozen=True)
class InstalledHosts:
    """A machine with Claude Desktop, Claude Code and Cursor configs in place.

    `secrets` are the env var values declared across all of them; none may ever
    surface in output.
    """

    home: Path
    project_dir: Path
    secrets: list[str]


@pytest.fixture
def installed_hosts(tmp_path: Path) -> InstalledHosts:
    """Lay the three host formats out where discovery expects to find them."""
    home = tmp_path / "home"
    project_dir = tmp_path / "project"

    sources = {
        home / CLAUDE_DESKTOP_CONFIG_RELPATH: "sample_config.json",
        home / CLAUDE_CODE_CONFIG_RELPATH: "claude_code_config.json",
        project_dir
        / CLAUDE_CODE_PROJECT_CONFIG_FILENAME: "claude_code_project_config.json",
        home / CURSOR_CONFIG_RELPATH: "cursor_config.json",
    }

    secrets: list[str] = []
    for destination, fixture_name in sources.items():
        fixture = FIXTURES_DIR / fixture_name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(fixture, destination)
        secrets.extend(_env_values(fixture))

    return InstalledHosts(home=home, project_dir=project_dir, secrets=secrets)


def _env_values(config: Path) -> list[str]:
    """Every env var value declared in a config file."""
    data = json.loads(config.read_text(encoding="utf-8"))
    return [
        value
        for server in data["mcpServers"].values()
        for value in server.get("env", {}).values()
    ]
