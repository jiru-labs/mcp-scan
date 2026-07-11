"""Parse MCP host config files into a common server model.

Most supported hosts (Claude Desktop, Claude Code, Cursor, Windsurf) declare
their servers under a top-level `mcpServers` object, so a single parser
covers them. A server is either local (`command` + `args`, stdio transport)
or remote (`url`).

VS Code is the odd one out: it uses `servers` instead of `mcpServers` at the
top level. Silently missing that would be worse than not discovering VS
Code's config at all — the scan would read the file, find nothing under the
key it knows, and report a false "0 servers, clean" — so the key checked is
picked by `host`, not tried generically.

Claude Code adds one twist: servers added with `--scope local` live inside the
same `~/.claude.json`, nested under `projects["<path>"].mcpServers` rather than
at the top level. Those are read too — a credentialed server hides there just
as well — and attributed to the same host as the top-level ones.

Environment variables are recorded by KEY ONLY. Their values are secrets and
never leave this module: they are not stored on the model, logged, or shown.

Each server also carries the line it was declared on, which `json.loads` throws
away — see `_ServerLines`. It is what lets a SARIF alert land on the server that
tripped the rule rather than on the top of the file.

Parsing is defensive by design. A file that is missing, unreadable or
malformed yields warnings and whatever servers could still be read, never an
exception.
"""

import bisect
import json
import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path

from mcp_scan.credentials import is_env_reference, redact_args, redact_url
from mcp_scan.discovery import HOST_UNKNOWN, HOST_VSCODE

SERVERS_KEY = "mcpServers"
#: VS Code's spelling of the same concept — see the module docstring.
VSCODE_SERVERS_KEY = "servers"

#: Claude Code's local scope. Servers added with `claude mcp add --scope local`
#: are stored in `~/.claude.json` under `projects["<path>"].mcpServers`, not at
#: the top level — a place a credentialed server can hide from a scanner that
#: only reads the top. Absent for every other host and for a fresh config, so
#: its absence is silent.
PROJECTS_KEY = "projects"

TRANSPORT_STDIO = "stdio"
TRANSPORT_REMOTE = "remote"
TRANSPORT_UNKNOWN = "unknown"

#: Everything `_ServerLines` has to look at to walk a config's structure: strings,
#: and the brackets that open and close a container. A string is one token, so a
#: brace *inside* one — an argument that carries a snippet of JSON — is read as
#: part of the string it sits in and never mistaken for structure. Numbers,
#: booleans and punctuation are skipped, being unable to contain either.
_JSON_TOKEN = re.compile(r'"(?:[^"\\]|\\.)*"|[{}\[\]]')

_NEWLINE = re.compile(r"\n")


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

    `line` is where in `source` the server was declared, 1-based, or None when
    the text it was read from does not say — which is what a report has to render
    around, rather than inventing a line the reader would trust.
    """

    name: str
    source: Path
    host: str = HOST_UNKNOWN
    command: str | None = None
    args: tuple[str, ...] = ()
    url: str | None = None
    env_keys: tuple[str, ...] = ()
    env_static_keys: tuple[str, ...] = ()
    line: int | None = None

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
class _Container:
    """One open `{` or `[` while `_ServerLines` walks a config.

    `name` is the key this container is the value of — `mcpServers` for a servers
    block — and `key`/`key_at` the last key read inside it, which is the key the
    next `{` or `[` will turn out to be the value of.
    """

    name: str | None = None
    key: str | None = None
    key_at: int = 0


def _is_a_key(raw: str, after: int) -> bool:
    """True when the string that ends at `after` is followed by a colon.

    Which is what makes a string a key rather than a value — and values are where
    the credentials are, so the difference is the one this module cares about most.
    """
    while after < len(raw) and raw[after].isspace():
        after += 1
    return after < len(raw) and raw[after] == ":"


class _ServerLines:
    """Which line each server was declared on, read back from the config's text.

    `json.loads` returns a document with no offsets in it, so the line has to come
    from a second pass over the same text. This is that pass.

    It walks the config's structure rather than pattern-matching it, because the
    shape of a server declaration — a key whose value is an object — is also the
    shape of the `env` block inside one, and of a project path in
    `~/.claude.json`. Only a key sitting *directly inside* an `mcpServers` (or
    VS Code's `servers`) block is a server, so only those are kept, wherever in
    the document that block is nested. A server called `env` then gets its own
    line rather than the `env` block of the server declared above it — which is
    the whole reason the walk exists, and what a regex got wrong.

    A name is handed out once — `take` pops the next unused line for it — so two
    servers of the same name in one file (the same server configured globally and
    again inside a project, which `~/.claude.json` allows) get a line each rather
    than both getting the first. They are handed out in the order the file lists
    them, which is the order the parser reads them in, with one exception: a
    `projects` block written *above* the top-level `mcpServers` crosses the two
    over. Both lines are then real declarations of that server in that file, so
    the cost of being wrong is a reader landing on the other one.

    Nothing here reads a value: it is keys, brackets, and the lines they fall on.
    A credential is a value, so none is ever looked at, let alone kept.
    """

    def __init__(self, raw: str) -> None:
        self._lines: defaultdict[str, deque[int]] = defaultdict(deque)

        # Where every line starts, so an offset becomes a line number by bisection
        # rather than by counting the newlines before it over and over. Found by
        # regex rather than by walking the characters: a `~/.claude.json` runs to
        # megabytes, and a scan of one should not be paid for a character at a time.
        starts = [0] + [match.end() for match in _NEWLINE.finditer(raw)]

        open_containers: list[_Container] = []

        for match in _JSON_TOKEN.finditer(raw):
            token = match.group()
            enclosing = open_containers[-1] if open_containers else _Container()

            if token in ("}", "]"):
                if open_containers:
                    open_containers.pop()
            elif token in ("{", "["):
                if (
                    token == "{"
                    and enclosing.key is not None
                    and enclosing.name in (SERVERS_KEY, VSCODE_SERVERS_KEY)
                ):
                    # An object directly inside a servers block: a declaration.
                    self._lines[enclosing.key].append(
                        bisect.bisect_right(starts, enclosing.key_at)
                    )
                # The container this opens is named by the key that introduced it,
                # which is how the objects inside it know they are servers.
                open_containers.append(_Container(name=enclosing.key))
            elif _is_a_key(raw, match.end()):
                enclosing.key = json.loads(token)
                enclosing.key_at = match.start()

    def take(self, name: str) -> int | None:
        """The next line `name` was declared on, or None once they run out."""
        lines = self._lines.get(name)
        return lines.popleft() if lines else None


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

    lines = _ServerLines(raw)

    servers_key = VSCODE_SERVERS_KEY if host == HOST_VSCODE else SERVERS_KEY
    servers = data.get(servers_key)
    if servers is not None:
        if isinstance(servers, dict):
            _add_servers(servers, path, host, result, lines)
        else:
            # A config with no top-level servers at all is valid and silent; one
            # whose servers key is the wrong type is a mistake worth flagging.
            result.warnings.append(f"{path}: '{servers_key}' is not a JSON object")

    _add_local_scope_servers(data, path, host, result, lines)

    return result


def _add_servers(
    servers: dict, path: Path, host: str, result: ParseResult, lines: _ServerLines
) -> None:
    """Build a server from each entry of one `mcpServers` mapping."""
    for name, definition in servers.items():
        if not isinstance(definition, dict):
            result.warnings.append(
                f"{path}: server '{name}' is not a JSON object, skipped"
            )
            continue
        result.servers.append(
            _build_server(name, definition, path, host, lines.take(name))
        )


def _add_local_scope_servers(
    data: dict, path: Path, host: str, result: ParseResult, lines: _ServerLines
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
            _add_servers(project[SERVERS_KEY], path, host, result, lines)


def _build_server(
    name: str, definition: dict, source: Path, host: str, line: int | None = None
) -> MCPServer:
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
        line=line,
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
