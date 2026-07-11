"""Shared fixtures for the test suite."""

import json
import re
import shutil
from dataclasses import dataclass
from pathlib import Path

import pytest

from mcp_scan.discovery import (
    CLAUDE_CODE_CONFIG_RELPATH,
    CLAUDE_CODE_PROJECT_CONFIG_FILENAME,
    CURSOR_CONFIG_RELPATH,
    claude_desktop_config_path,
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
def credentials_config() -> Path:
    """A config with a credential in `env`, one inline in `args`, and neither.

    The three cases the static-credential rules have to tell apart, in the shape
    a real host config would carry them.
    """
    return FIXTURES_DIR / "credentials_config.json"


@pytest.fixture
def suspicious_config() -> Path:
    """A config with one server per suspicious-pattern heuristic, plus a clean one.

    The clean server is the point of the fixture as much as the other four: it
    uses a package runner, a scoped and pinned package and an HTTPS URL, and no
    heuristic may fire on it.
    """
    return FIXTURES_DIR / "suspicious_config.json"


@pytest.fixture
def broad_access_config() -> Path:
    """A config with servers handed a root, a home, a whole disk and a shell.

    The last server is the counterweight: it uses the same filesystem server as
    the first two, scoped to a single project directory, and nothing may fire
    on it.
    """
    return FIXTURES_DIR / "broad_access_config.json"


@pytest.fixture
def sample_secrets(sample_config: Path) -> list[str]:
    """Every credential value in the sample config.

    Read straight from the fixture so the guarantee still holds if the fixture
    changes: none of these strings may ever reach a parse result or the
    terminal.
    """
    return _config_secrets(sample_config)


@pytest.fixture
def credentials_secrets(credentials_config: Path) -> list[str]:
    """Every credential value in the credentials config, in `env` and in `args`."""
    return _config_secrets(credentials_config)


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
        # Wherever discovery would actually look on the platform running the
        # tests, so this fixture stays correct on macOS, Linux and Windows.
        claude_desktop_config_path(home): "sample_config.json",
        # Carries a local-scope server nested under `projects[...]`, too.
        home / CLAUDE_CODE_CONFIG_RELPATH: "claude_code_config.json",
        project_dir
        / CLAUDE_CODE_PROJECT_CONFIG_FILENAME: "claude_code_project_config.json",
        home / CURSOR_CONFIG_RELPATH: "cursor_config.json",
        project_dir / CURSOR_CONFIG_RELPATH: "cursor_project_config.json",
    }

    secrets: list[str] = []
    for destination, fixture_name in sources.items():
        fixture = FIXTURES_DIR / fixture_name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(fixture, destination)
        secrets.extend(_config_secrets(fixture))

    return InstalledHosts(home=home, project_dir=project_dir, secrets=secrets)


#: A query parameter of a fixture URL whose value is a credential. Spelled out
#: here rather than imported from `mcp_scan.credentials`, so that a hole in the
#: scanner's own idea of what a secret looks like cannot quietly blind the test
#: that checks it never prints one.
SECRET_QUERY_PARAM = re.compile(r"[?&](?:[^=&]*_)?(?:key|token|secret|password)=([^&]+)")


def _config_secrets(config: Path) -> list[str]:
    """Every credential value a config declares, wherever it hides.

    That is every `env` value, the value half of any `--flag=value` argument,
    and any credential-bearing query parameter of a remote server's URL — the
    three places a config can pin a secret, and the three a report must never
    echo. Walked across the top-level servers *and* Claude Code's local scope,
    nested under `projects[...]`, so a secret hiding there is checked too.
    """
    data = json.loads(config.read_text(encoding="utf-8"))

    secrets: list[str] = []
    for servers in _server_mappings(data):
        for server in servers.values():
            secrets.extend(str(value) for value in server.get("env", {}).values())
            for arg in server.get("args", []):
                _, separator, value = str(arg).partition("=")
                if separator:
                    secrets.append(value)
            secrets.extend(SECRET_QUERY_PARAM.findall(str(server.get("url", ""))))

    # A `$…` value references the environment and pins nothing: it is the fix,
    # not the leak, and it is meant to be printed. An empty value is a substring
    # of every output there is; asserting it never appears would fail on
    # principle.
    return [
        secret
        for secret in secrets
        if secret and not secret.strip().startswith("$")
    ]


def _server_mappings(data: dict) -> list[dict]:
    """Every `mcpServers` mapping in a config: the top-level one and each nested
    under a Claude Code `projects[...]` entry."""
    mappings = []
    top_level = data.get("mcpServers")
    if isinstance(top_level, dict):
        mappings.append(top_level)
    for project in (data.get("projects") or {}).values():
        if isinstance(project, dict) and isinstance(project.get("mcpServers"), dict):
            mappings.append(project["mcpServers"])
    return mappings
