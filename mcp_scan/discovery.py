"""Locate MCP config files belonging to each supported host.

Discovery is strictly read-only: it resolves well-known paths and checks
whether they exist. It never opens, parses or modifies a config file.

Two hosts keep more than one config, and both places a server can hide are
discovered:

* Claude Code keeps user-scoped servers in `~/.claude.json` and project-scoped
  servers in a `.mcp.json` committed next to the code. (A third, *local* scope
  also lives inside `~/.claude.json`, under `projects[...]`; that one is not a
  separate file, so it is the parser's to find, not discovery's.)
* Cursor reads a global `~/.cursor/mcp.json` and a per-project `.cursor/mcp.json`
  in the directory it is opened on.

Every config is attributed to the host that owns it, whichever scope it came
from.
"""

import os
import sys
from dataclasses import dataclass
from pathlib import Path

HOST_CLAUDE_DESKTOP = "claude-desktop"
HOST_CLAUDE_CODE = "claude-code"
HOST_CURSOR = "cursor"

# Host of a config the user pointed us at explicitly (`--config`): we know the
# file, not the tool that owns it.
HOST_UNKNOWN = "unknown"

# Paths relative to the user's home directory (Claude Code and Cursor are the
# same on every platform; Claude Desktop is not — see claude_desktop_config_path).
CLAUDE_DESKTOP_CONFIG_RELPATH = Path(
    "Library/Application Support/Claude/claude_desktop_config.json"
)
CLAUDE_DESKTOP_CONFIG_RELPATH_LINUX = Path(".config/Claude/claude_desktop_config.json")
# Relative to %APPDATA%, not to the home directory.
CLAUDE_DESKTOP_CONFIG_RELPATH_WINDOWS = Path("Claude/claude_desktop_config.json")
CLAUDE_CODE_CONFIG_RELPATH = Path(".claude.json")
CURSOR_CONFIG_RELPATH = Path(".cursor/mcp.json")

# Claude Code's project-scoped config, resolved against the project directory.
CLAUDE_CODE_PROJECT_CONFIG_FILENAME = ".mcp.json"


@dataclass(frozen=True)
class ConfigLocation:
    """A config file that a host is expected to use.

    `exists` is False when the file is absent, unreadable, or the path could
    not be resolved. A missing config is a normal outcome, not an error: the
    user may simply not have that host installed.
    """

    host: str
    path: Path
    exists: bool


def _locate(host: str, path: Path) -> ConfigLocation:
    """Describe a candidate config path.

    is_file() swallows OSError (permission denied, symlink loop) and returns
    False, which is the behaviour we want: an unreachable config is absent,
    not a crash.
    """
    return ConfigLocation(host=host, path=path, exists=path.is_file())


def claude_desktop_config_path(
    home: Path | None = None,
    *,
    platform: str = sys.platform,
    appdata: str | None = os.environ.get("APPDATA"),
) -> Path:
    """Where Claude Desktop's config lives on the running platform.

    Windows resolves against `%APPDATA%`, falling back to `home/AppData/Roaming`
    on the rare machine where the variable is unset. macOS and Linux resolve
    against `home`, each at its own well-known path.

    `appdata` defaults to the real `%APPDATA%`, captured once at import time
    (mirroring `platform`'s default). Tests pass their own path, or `None` to
    exercise the fallback, without needing to touch the environment.
    """
    base = home if home is not None else Path.home()
    if platform == "win32":
        appdata_dir = Path(appdata) if appdata is not None else base / "AppData" / "Roaming"
        return appdata_dir / CLAUDE_DESKTOP_CONFIG_RELPATH_WINDOWS
    if platform == "darwin":
        return base / CLAUDE_DESKTOP_CONFIG_RELPATH
    return base / CLAUDE_DESKTOP_CONFIG_RELPATH_LINUX


def find_claude_desktop_config(
    home: Path | None = None,
    *,
    platform: str = sys.platform,
    appdata: str | None = os.environ.get("APPDATA"),
) -> ConfigLocation:
    """Locate the Claude Desktop config file.

    Args:
        home: Home directory to resolve the config against. Defaults to the
            current user's home. Tests pass a tmp_path here.
        platform: `sys.platform` value driving which layout to use. Defaults
            to the real platform; tests inject `"darwin"`, `"linux"` or
            `"win32"` to stay deterministic across the machines pytest runs on.
        appdata: Windows' `%APPDATA%`, only consulted when `platform` is
            `"win32"`. Defaults to the real environment variable; tests inject
            a path instead of depending on it being set.
    """
    path = claude_desktop_config_path(home, platform=platform, appdata=appdata)
    return _locate(HOST_CLAUDE_DESKTOP, path)


def find_claude_code_configs(
    home: Path | None = None, project_dir: Path | None = None
) -> list[ConfigLocation]:
    """Locate every Claude Code config: the user-scoped one and the project one.

    Args:
        home: Home directory holding `~/.claude.json`. Defaults to the current
            user's home.
        project_dir: Directory holding a project-scoped `.mcp.json`. Defaults
            to the current working directory.
    """
    base = home if home is not None else Path.home()
    project = project_dir if project_dir is not None else Path.cwd()

    return [
        _locate(HOST_CLAUDE_CODE, base / CLAUDE_CODE_CONFIG_RELPATH),
        _locate(HOST_CLAUDE_CODE, project / CLAUDE_CODE_PROJECT_CONFIG_FILENAME),
    ]


def find_cursor_configs(
    home: Path | None = None, project_dir: Path | None = None
) -> list[ConfigLocation]:
    """Locate every Cursor config: the global one and the project one.

    Cursor reads a global `~/.cursor/mcp.json` and, in a project it opens, a
    `.cursor/mcp.json` in that project's directory. Both are attributed to the
    same host.

    Args:
        home: Home directory holding the global config. Defaults to the current
            user's home.
        project_dir: Directory holding a project-scoped `.cursor/mcp.json`.
            Defaults to the current working directory.
    """
    base = home if home is not None else Path.home()
    project = project_dir if project_dir is not None else Path.cwd()

    return [
        _locate(HOST_CURSOR, base / CURSOR_CONFIG_RELPATH),
        _locate(HOST_CURSOR, project / CURSOR_CONFIG_RELPATH),
    ]


def find_all_configs(
    home: Path | None = None, project_dir: Path | None = None
) -> list[ConfigLocation]:
    """Locate the configs of every supported host.

    Returns candidates for all hosts, present or not, so callers can tell an
    uninstalled host from an installed one. Filter on `exists` to get the
    configs actually worth reading.

    Deduplicated by path: run from your home directory, a host's global and
    project configs resolve to the same file, and it must be scanned once, not
    reported — and findings counted — twice.
    """
    return _unique_by_path(
        [
            find_claude_desktop_config(home),
            *find_claude_code_configs(home, project_dir),
            *find_cursor_configs(home, project_dir),
        ]
    )


def _unique_by_path(locations: list[ConfigLocation]) -> list[ConfigLocation]:
    """The same locations, first spelling of each file kept, order preserved."""
    seen: set[Path] = set()
    unique: list[ConfigLocation] = []
    for location in locations:
        key = _canonical(location.path)
        if key not in seen:
            seen.add(key)
            unique.append(location)
    return unique


def _canonical(path: Path) -> Path:
    """A path in a form two spellings of the same file agree on.

    Absent files resolve fine — resolution normalises `..` and symlinks without
    requiring the target to exist — and a path the OS will not resolve at all
    falls back to its absolute form rather than raising.
    """
    try:
        return path.resolve()
    except OSError:  # pragma: no cover — a path the OS will not even resolve
        return path.absolute()
