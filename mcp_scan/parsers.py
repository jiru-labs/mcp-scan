"""Parse MCP host config files into a common server model.

All supported hosts (Claude Desktop, Claude Code, Cursor) declare their
servers under a top-level `mcpServers` object, so a single parser covers
them. A server is either local (`command` + `args`, stdio transport) or
remote (`url`).

Claude Code adds one twist: servers added with `--scope local` live inside the
same `~/.claude.json`, nested under `projects["<path>"].mcpServers` rather than
at the top level. Those are read too — a credentialed server hides there just
as well — and attributed to the same host as the top-level ones.

Environment variables are recorded by KEY ONLY. Their values are secrets and
never leave this module: they are not stored on the model, logged, or shown.

Parsing is defensive by design. A file that is missing, unreadable or
malformed yields warnings and whatever servers could still be read, never an
exception.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path

from mcp_scan.credentials import is_env_reference, redact_args, redact_url
from mcp_scan.discovery import HOST_UNKNOWN

SERVERS_KEY = "mcpServers"

#: Claude Code's local scope. Servers added with `claude mcp add --scope local`
#: are stored in `~/.claude.json` under `projects["<path>"].mcpServers`, not at
#: the top level — a place a credentialed server can hide from a scanner that
#: only reads the top. Absent for every other host and for a fresh config, so
#: its absence is silent.
PROJECTS_KEY = "projects"

TRANSPORT_STDIO = "stdio"
TRANSPORT_REMOTE = "remote"
TRANSPORT_UNKNOWN = "unknown"


@dataclass(frozen=True)
class MCPServer:
    """A single MCP server as declared in a host config.

    `host` is the tool that owns the config the server was read from, and
    `source` the config file itself. `env_keys` holds the names of the declared
    environment variables, never their values.

    `env_static_keys` names the subset of those whose value is written into the
    config file itself, rather than referenced from the real environment — the
    ones that put a secret on disk. Which name is in there is decided by
    looking at the value once, at parse time; the value is then dropped like
    every other one.
    """

    name: str
    source: Path
    host: str = HOST_UNKNOWN
    command: str | None = None
    args: tuple[str, ...] = ()
    url: str | None = None
    env_keys: tuple[str, ...] = ()
    env_static_keys: tuple[str, ...] = ()

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
        """The command line or URL the host would use to reach the server.

        Verbatim, and therefore unsafe to print: an argument can carry a
        credential inline (`--api-key=ghp_…`), and this is where it would be.
        Rules read it to judge the server; anything rendering it for a human
        wants `redacted_endpoint` instead.
        """
        if self.command:
            return " ".join((self.command, *self.args))
        return self.url or ""

    @property
    def redacted_endpoint(self) -> str:
        """The same endpoint, with any credential in it masked.

        What every report prints. The endpoint survives intact — the user needs
        to recognise the server, and to find the argument or the parameter to go
        and fix — and only the secret is replaced: `npx server --api-key=***`,
        `https://mcp.example.com/sse?api_key=***`.
        """
        if self.command:
            return " ".join((self.command, *redact_args(self.args)))
        return redact_url(self.url) if self.url else ""


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
    if servers is not None:
        if isinstance(servers, dict):
            _add_servers(servers, path, host, result)
        else:
            # A config with no top-level servers at all is valid and silent; one
            # whose `mcpServers` is the wrong type is a mistake worth flagging.
            result.warnings.append(f"{path}: '{SERVERS_KEY}' is not a JSON object")

    _add_local_scope_servers(data, path, host, result)

    return result


def _add_servers(
    servers: dict, path: Path, host: str, result: ParseResult
) -> None:
    """Build a server from each entry of one `mcpServers` mapping."""
    for name, definition in servers.items():
        if not isinstance(definition, dict):
            result.warnings.append(
                f"{path}: server '{name}' is not a JSON object, skipped"
            )
            continue
        result.servers.append(_build_server(name, definition, path, host))


def _add_local_scope_servers(
    data: dict, path: Path, host: str, result: ParseResult
) -> None:
    """Read Claude Code's local-scope servers, nested under `projects`.

    Best-effort by design: this store accumulates an entry for every project the
    user has ever opened, and a stale or hand-edited one that is not the shape we
    expect is skipped in silence rather than turned into a warning per project.
    A malformed *server* inside a well-formed project's `mcpServers` is still
    reported, exactly as one at the top level would be.
    """
    projects = data.get(PROJECTS_KEY)
    if not isinstance(projects, dict):
        return

    for project in projects.values():
        if isinstance(project, dict) and isinstance(project.get(SERVERS_KEY), dict):
            _add_servers(project[SERVERS_KEY], path, host, result)


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

    # Keys only. The values are credentials and are deliberately discarded —
    # all a value is asked, on its way out, is whether it is a secret at all.
    raw_env = definition.get("env")
    env = raw_env if isinstance(raw_env, dict) else {}
    env_keys = tuple(str(key) for key in env)
    env_static_keys = tuple(
        str(key) for key, value in env.items() if _is_written_into_the_config(value)
    )

    return MCPServer(
        name=name,
        source=source,
        host=host,
        command=command,
        args=args,
        url=url,
        env_keys=env_keys,
        env_static_keys=env_static_keys,
    )


def _is_written_into_the_config(value: object) -> bool:
    """True when an env entry pins a literal value into the config file.

    An empty value declares the variable without setting it, and a reference
    defers to the environment; both leave the config free of secrets. Anything
    else is a value sitting on disk.

    A template that only partly references the environment — `"Bearer ${TOKEN}"`
    — counts as written down. It is rare, and erring towards a finding the user
    can dismiss beats staying quiet about a secret.
    """
    if value is None:
        return False
    text = str(value).strip()
    return bool(text) and not is_env_reference(text)
