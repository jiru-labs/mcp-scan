"""Locate MCP config files belonging to each supported host.

Discovery is strictly read-only: it resolves well-known paths and checks
whether they exist. It never opens, parses or modifies a config file.
"""

from dataclasses import dataclass
from pathlib import Path

HOST_CLAUDE_DESKTOP = "claude-desktop"

# Path relative to the user's home directory (macOS).
CLAUDE_DESKTOP_CONFIG_RELPATH = Path(
    "Library/Application Support/Claude/claude_desktop_config.json"
)


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


def find_claude_desktop_config(home: Path | None = None) -> ConfigLocation:
    """Locate the Claude Desktop config file.

    Args:
        home: Home directory to resolve the config against. Defaults to the
            current user's home. Tests pass a tmp_path here.
    """
    base = home if home is not None else Path.home()
    path = base / CLAUDE_DESKTOP_CONFIG_RELPATH

    # is_file() swallows OSError (permission denied, symlink loop) and returns
    # False, which is the behaviour we want: an unreachable config is absent,
    # not a crash.
    return ConfigLocation(
        host=HOST_CLAUDE_DESKTOP,
        path=path,
        exists=path.is_file(),
    )
