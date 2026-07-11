"""Locate MCP config files belonging to each supported host.

Discovery is strictly read-only: it resolves well-known paths and checks
whether they exist. It never opens, parses or modifies a config file.

Claude Code keeps two configs: user-scoped servers in `~/.claude.json`, and
project-scoped servers in a `.mcp.json` committed next to the code. Both are
discovered, and both are attributed to the same host.
"""

from dataclasses import dataclass
from pathlib import Path

HOST_CLAUDE_DESKTOP = "claude-desktop"
HOST_CLAUDE_CODE = "claude-code"
HOST_CURSOR = "cursor"

# Host of a config the user pointed us at explicitly (`--config`): we know the
# file, not the tool that owns it.
HOST_UNKNOWN = "unknown"

# Paths relative to the user's home directory (macOS layout for Claude
# Desktop; the others are the same on every platform).
CLAUDE_DESKTOP_CONFIG_RELPATH = Path(
    "Library/Application Support/Claude/claude_desktop_config.json"
)
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


def find_claude_desktop_config(home: Path | None = None) -> ConfigLocation:
    """Locate the Claude Desktop config file.

    Args:
        home: Home directory to resolve the config against. Defaults to the
            current user's home. Tests pass a tmp_path here.
    """
    base = home if home is not None else Path.home()
    return _locate(HOST_CLAUDE_DESKTOP, base / CLAUDE_DESKTOP_CONFIG_RELPATH)


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


def find_cursor_config(home: Path | None = None) -> ConfigLocation:
    """Locate the Cursor config file.

    Args:
        home: Home directory to resolve the config against. Defaults to the
            current user's home.
    """
    base = home if home is not None else Path.home()
    return _locate(HOST_CURSOR, base / CURSOR_CONFIG_RELPATH)


def find_all_configs(
    home: Path | None = None, project_dir: Path | None = None
) -> list[ConfigLocation]:
    """Locate the configs of every supported host.

    Returns candidates for all hosts, present or not, so callers can tell an
    uninstalled host from an installed one. Filter on `exists` to get the
    configs actually worth reading.
    """
    return [
        find_claude_desktop_config(home),
        *find_claude_code_configs(home, project_dir),
        find_cursor_config(home),
    ]
