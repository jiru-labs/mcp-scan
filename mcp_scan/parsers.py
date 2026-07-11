"""Parse MCP host config files into a common server model.

All supported hosts (Claude Desktop, Claude Code, Cursor) declare their
servers under a top-level `mcpServers` object, so a single parser covers
them. A server is either local (`command` + `args`, stdio transport) or
remote (`url`).

Environment variables are recorded by KEY ONLY. Their values are secrets and
never leave this module: they are not stored on the model, logged, or shown.

Parsing is defensive by design. A file that is missing, unreadable or
malformed yields warnings and whatever servers could still be read, never an
exception.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path

from mcp_scan.discovery import HOST_UNKNOWN

SERVERS_KEY = "mcpServers"

TRANSPORT_STDIO = "stdio"
TRANSPORT_REMOTE = "remote"
TRANSPORT_UNKNOWN = "unknown"


@dataclass(frozen=True)
class MCPServer:
    """A single MCP server as declared in a host config.

    `host` is the tool that owns the config the server was read from, and
    `source` the config file itself. `env_keys` holds the names of the declared
    environment variables, never their values.
    """

    name: str
    source: Path
    host: str = HOST_UNKNOWN
    command: str | None = None
    args: tuple[str, ...] = ()
    url: str | None = None
    env_keys: tuple[str, ...] = ()

    @property
    def transport(self) -> str:
        """How the host talks to this server, inferred from the definition."""
        if self.command:
            return TRANSPORT_STDIO
        if self.url:
            return TRANSPORT_REMOTE
        return TRANSPORT_UNKNOWN

    @property
    def endpoint(self) -> str:
        """The command line or URL the host would use to reach the server."""
        if self.command:
            return " ".join((self.command, *self.args))
        return self.url or ""


@dataclass
class ParseResult:
    """Servers read from a config, plus any problems found along the way.

    A result can hold both: one broken server entry does not discard its
    valid siblings.
    """

    servers: list[MCPServer] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def parse_config_file(path: Path, host: str = HOST_UNKNOWN) -> ParseResult:
    """Read a host config file and extract its MCP servers.

    Never raises: unreadable or malformed input is reported as a warning.

    Args:
        path: The config file to read.
        host: The tool that owns the config, stamped on every server found in
            it. Defaults to `HOST_UNKNOWN`, for a file the caller pointed us at
            without saying who it belongs to.
    """
    result = ParseResult()

    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        result.warnings.append(f"{path}: config file not found")
        return result
    except (OSError, UnicodeDecodeError) as exc:
        result.warnings.append(f"{path}: could not read config ({exc})")
        return result

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        result.warnings.append(
            f"{path}: malformed JSON at line {exc.lineno}, column {exc.colno} ({exc.msg})"
        )
        return result

    if not isinstance(data, dict):
        result.warnings.append(f"{path}: expected a JSON object at the top level")
        return result

    servers = data.get(SERVERS_KEY)
    if servers is None:
        # A config with no servers at all is valid — nothing to scan, nothing
        # to warn about.
        return result
    if not isinstance(servers, dict):
        result.warnings.append(f"{path}: '{SERVERS_KEY}' is not a JSON object")
        return result

    for name, definition in servers.items():
        if not isinstance(definition, dict):
            result.warnings.append(
                f"{path}: server '{name}' is not a JSON object, skipped"
            )
            continue
        result.servers.append(_build_server(name, definition, path, host))

    return result


def _build_server(name: str, definition: dict, source: Path, host: str) -> MCPServer:
    """Build an MCPServer from one `mcpServers` entry.

    Fields of an unexpected type are dropped rather than rejected: a partially
    understood server is still worth reporting to the user.
    """
    command = definition.get("command")
    if not isinstance(command, str):
        command = None

    url = definition.get("url")
    if not isinstance(url, str):
        url = None

    raw_args = definition.get("args")
    args = (
        tuple(str(arg) for arg in raw_args) if isinstance(raw_args, list) else ()
    )

    # Keys only. The values are credentials and are deliberately discarded.
    raw_env = definition.get("env")
    env_keys = tuple(str(key) for key in raw_env) if isinstance(raw_env, dict) else ()

    return MCPServer(
        name=name,
        source=source,
        host=host,
        command=command,
        args=args,
        url=url,
        env_keys=env_keys,
    )
