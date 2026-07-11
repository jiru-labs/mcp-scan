"""Detect risk signals in how a server is launched and how it is reached.

A server definition is a command line and a URL, and both say a lot about how
much the user is trusting. These heuristics read that definition and flag the
patterns that keep turning up in real incidents:

* `remote-code-execution` (CRITICAL) — the launch command downloads code and
  runs it (`curl … | sh`). The server is then whatever the remote host serves
  at launch time, which the user never sees and cannot review.
  Inspired by *Command Injection & Execution* and *Software Supply Chain Attacks
  & Dependency Tampering*.
* `insecure-transport` (CRITICAL) — the server is reached over plain HTTP. The
  traffic carries credentials, and it carries the tool descriptions the agent
  acts on, so anyone on the network path can both read it and rewrite it — which
  is *Tool Poisoning* handed to any party on the wire.
  Inspired by the OWASP MCP Security Cheat Sheet, "Authentication, Authorization
  & Transport Security": always use TLS for remote transports.
* `executable-in-temp-dir` (WARN) — the binary or script that gets executed sits
  in a world-writable temporary directory, where it can be replaced between
  launches and where nothing vouches for how it got there.
  Inspired by *Command Injection & Execution* and *Shadow MCP Servers*.
* `unscoped-package` (WARN) — the command resolves an unscoped, unpinned package
  from a registry at every launch. The name belongs to whoever claimed it, and
  the code behind it is whatever was published most recently.
  Inspired by *Software Supply Chain Attacks & Dependency Tampering*.

Each heuristic is deliberately conservative: it fires on the *shape* of the
definition, not on a blocklist of names, and stays quiet on the ordinary cases
(a scoped package, a pinned version, a loopback URL, a temp directory that is
merely served as data). A rule the user learns to ignore is worse than no rule.

References:
    OWASP MCP Top 10 — https://owasp.org/www-project-mcp-top-10/
        The named categories above are its own. It is a v0.1 beta and describes
        itself as a living document, so the categories are cited by name: the
        numbering (MCP01…MCP10) may still move, and the names are the stable
        part. It has no transport-security category, hence the second reference.
    OWASP MCP Security Cheat Sheet —
        https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html
"""

import ipaddress
import re
from pathlib import PurePosixPath
from urllib.parse import urlsplit

from mcp_scan.parsers import MCPServer
from mcp_scan.rules.base import Finding, Rule, Severity

#: A command that pulls something off the network. `fetch` is deliberately not
#: in here: it is a word, and it is in the name of half the servers that fetch
#: things for a living (`mcp-server-fetch`).
FETCHERS = re.compile(
    r"\b(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)\b",
    re.IGNORECASE,
)

#: An interpreter that will run whatever it is handed on stdin.
INTERPRETERS = r"(?:sh|bash|zsh|dash|ksh|fish|python3?|node|perl|ruby)"

#: What turns a download into an execution. Paired with a fetcher on the same
#: command line, each of these means the code is run sight unseen. The label
#: goes into the finding, so the message says *how* the command executes it.
EXECUTION_SINKS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(rf"\|\s*(?:sudo\s+)?{INTERPRETERS}\b", re.IGNORECASE),
        "pipes it straight into an interpreter",
    ),
    (
        re.compile(r"\b(?:eval|iex|invoke-expression)\b", re.IGNORECASE),
        "evaluates it as code",
    ),
)

#: Directories whose contents nothing vouches for: any local process can write
#: to them, and what lands there arrives without review. Matched against a path
#: normalised to lowercase forward slashes, so the Windows spellings hit too.
TEMP_DIRECTORIES: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"^(?:/private)?/(?:var/)?tmp/"),
        "a world-writable temporary directory",
    ),
    (
        re.compile(r"^/dev/shm/"),
        "shared memory, which any local process can write to",
    ),
    (
        re.compile(r"(?:^|/)(?:%temp%|\$env:temp)/|/(?:windows/temp|local/temp)/"),
        "a temporary directory",
    ),
    (
        re.compile(r"(?:^~|/)downloads/"),
        "the download directory, where anything a browser saved lands",
    ),
)

#: What makes a path in one of those directories an *executable* rather than
#: data. A server told to serve `/tmp` is doing its job; a server that *runs*
#: `/tmp/setup.sh` is running an unvetted script.
EXECUTABLE_SUFFIXES = frozenset(
    {
        ".bash",
        ".bat",
        ".bin",
        ".cmd",
        ".exe",
        ".jar",
        ".js",
        ".cjs",
        ".mjs",
        ".php",
        ".pl",
        ".ps1",
        ".py",
        ".rb",
        ".sh",
        ".ts",
        ".zsh",
    }
)

#: A URL sitting inside a command line, rather than in the `url` field.
URL_IN_ARGS = re.compile(r"\b(?:http|ws)://[^\s\"'`]+", re.IGNORECASE)

#: Schemes that carry the traffic in the clear.
PLAINTEXT_SCHEMES = frozenset({"http", "ws"})

#: Commands that resolve a package from a registry and execute it, in one step.
PACKAGE_RUNNERS = frozenset({"npx", "bunx", "pnpx"})

#: The same thing, spelled as a subcommand: `pnpm dlx …`, `npm exec …`.
RUNNER_SUBCOMMANDS = frozenset({("pnpm", "dlx"), ("yarn", "dlx"), ("npm", "exec")})

#: A version specifier that pins nothing: it re-resolves on every launch.
MOVING_TAGS = frozenset({"", "*", "latest", "next", "beta", "canary"})


class RemoteCodeExecution(Rule):
    """Flag a launch command that downloads code and executes it unseen."""

    id = "remote-code-execution"
    title = "Launch command downloads and executes remote code"
    severity = Severity.CRITICAL
    remediation = (
        "Stop piping a download into a shell. Install the server the ordinary way "
        "— a pinned package, or a repository you have checked out at a revision "
        "you have read — and launch that. If you must use the script, download it "
        "once, read it, and keep your own copy under your control; what you audit "
        "today and what the remote host serves tomorrow are not promised to be the "
        "same file, and this launcher would never tell you they had diverged."
    )

    def check(self, server: MCPServer) -> list[Finding]:
        if not server.command or not FETCHERS.search(server.endpoint):
            return []

        for pattern, sink in EXECUTION_SINKS:
            if pattern.search(server.endpoint):
                return [
                    self.finding(
                        server,
                        f"the launch command downloads code and {sink}; the server "
                        f"runs whatever the remote host serves at that moment",
                    )
                ]

        return []


class InsecureTransport(Rule):
    """Flag a server reached over an unencrypted connection."""

    id = "insecure-transport"
    title = "Server reached over an unencrypted connection"
    severity = Severity.CRITICAL
    remediation = (
        "Reach the server over `https://`. If it does not offer TLS, that is the "
        "thing to fix — or to walk away from. Plain HTTP is not only readable on "
        "the network path, it is writable: an attacker in the middle rewrites the "
        "tool descriptions your agent reads, and the agent follows them. Rotate "
        "anything the server was authorized with, since it has been going out in "
        "the clear. (A server on `127.0.0.1` never leaves your machine, and is the "
        "one fair exception.)"
    )

    def check(self, server: MCPServer) -> list[Finding]:
        return [
            self.finding(
                server,
                f"the server is reached at '{url}', in the clear; anyone on the "
                f"network path can read the traffic — credentials included — and "
                f"rewrite the tool descriptions the agent acts on",
            )
            for url in _urls_of(server)
            if _is_plaintext(url)
        ]


class ExecutableInTempDir(Rule):
    """Flag a server that executes a binary or script from a temp directory."""

    id = "executable-in-temp-dir"
    title = "Server executable lives in a world-writable directory"
    severity = Severity.WARN
    remediation = (
        "Move the executable somewhere only you can write — alongside the project "
        "it belongs to, or an installation directory owned by your user — and "
        "point the config at it there. A world-writable directory is one any other "
        "process on the machine can write to, so what runs at the next launch is "
        "whatever was last written to that path, and nothing about the config "
        "would look any different."
    )

    def check(self, server: MCPServer) -> list[Finding]:
        findings = []

        for path in _executed_paths(server):
            location = _temp_directory_of(path)
            if location is not None:
                findings.append(
                    self.finding(
                        server,
                        f"the server executes '{path}', which lives in {location}; "
                        f"what runs at the next launch is whatever was last "
                        f"written there",
                    )
                )

        return findings


class UnscopedPackage(Rule):
    """Flag a package pulled from an unowned registry namespace at every launch."""

    id = "unscoped-package"
    title = "Package resolved from an unowned namespace at every launch"
    severity = Severity.WARN
    remediation = (
        "Pin what you run. Give the package an exact version (`my-server@1.2.3`) "
        "so that the same code launches every time, and prefer a scoped package "
        "(`@vendor/my-server`) from a namespace whose owner you know. An unscoped "
        "name on a moving tag is re-resolved from the registry at every launch: "
        "you are trusting whoever controls that name at that moment, and the "
        "answer can change without you touching a thing."
    )

    def check(self, server: MCPServer) -> list[Finding]:
        package = _package_run_by(server)
        if package is None or _is_owned_or_pinned(package):
            return []

        name = package.partition("@")[0]
        return [
            self.finding(
                server,
                f"'{package}' is resolved from the registry at every launch: the name "
                f"is unscoped, so anyone may claim it, and no version pins what runs. "
                f"Pin it ('{name}@1.2.3') or use a scoped package",
            )
        ]


def _urls_of(server: MCPServer) -> list[str]:
    """Every URL the server is reached at, wherever it is declared.

    A remote server carries its URL in `url`, but a stdio server proxying a
    remote one carries it in the command line (`npx mcp-remote http://…`), and
    the traffic is just as exposed either way.
    """
    urls = [server.url] if server.url else []
    urls.extend(URL_IN_ARGS.findall(" ".join(server.args)))
    return list(dict.fromkeys(urls))


def _is_plaintext(url: str) -> bool:
    """True when a URL carries its traffic in the clear off this machine.

    A loopback URL never reaches a network, so there is no path to eavesdrop
    on: `http://localhost:3000` is how a local server is *supposed* to be
    reached, and flagging it would be noise.
    """
    parts = urlsplit(url)
    if parts.scheme.lower() not in PLAINTEXT_SCHEMES:
        return False

    try:
        host = parts.hostname
    except ValueError:
        # A malformed authority (a bad IPv6 literal, say). We cannot say who it
        # points at, and an unparseable plaintext URL is not the safer kind.
        return True

    return not _is_loopback(host)


def _is_loopback(host: str | None) -> bool:
    """True when a hostname resolves, by definition, to this machine."""
    if not host:
        return False

    name = host.lower()
    if name == "localhost" or name.endswith(".localhost"):
        return True

    try:
        return ipaddress.ip_address(name).is_loopback
    except ValueError:
        return False


def _executed_paths(server: MCPServer) -> list[str]:
    """The paths this server definition actually runs.

    The command is one by definition, whatever it is called. An argument only
    counts when it names a script or a binary: an interpreter runs the script
    it is handed, but a server handed a *directory* is being told what to
    serve, not what to execute — `server-filesystem /tmp` exposes a temp
    directory as data, which is a different question than running code from it.
    """
    paths = [server.command] if server.command else []
    paths.extend(arg for arg in server.args if _looks_executable(arg))
    return paths


def _looks_executable(arg: str) -> bool:
    """True when an argument names a script or a binary, by its suffix."""
    return PurePosixPath(_normalise(arg)).suffix in EXECUTABLE_SUFFIXES


def _temp_directory_of(path: str) -> str | None:
    """Name the untrusted directory a path lives in, or None if it lives elsewhere."""
    normalised = _normalise(path)
    for pattern, location in TEMP_DIRECTORIES:
        if pattern.search(normalised):
            return location
    return None


def _normalise(path: str) -> str:
    """A path in one spelling: lowercase, forward slashes.

    Windows writes `%TEMP%\\srv.exe` and macOS `/private/tmp/srv`; the patterns
    only have to know one of those shapes.
    """
    return path.replace("\\", "/").lower()


def _package_run_by(server: MCPServer) -> str | None:
    """The package a runner command fetches and executes, if it is one.

    `npx`, `bunx` and friends take flags before the package, so the package is
    the first argument that is not one. `--` ends the flags without naming
    anything itself.
    """
    if not server.command:
        return None

    # `/usr/local/bin/npx` and Windows' `npx.cmd` are both `npx`.
    runner = PurePosixPath(_normalise(server.command)).name
    runner = runner.removesuffix(".cmd").removesuffix(".exe")
    args = list(server.args)

    if runner in PACKAGE_RUNNERS:
        rest = args
    elif args and (runner, args[0].lower()) in RUNNER_SUBCOMMANDS:
        rest = args[1:]
    else:
        return None

    return next(
        (arg for arg in rest if arg != "--" and not arg.startswith("-")), None
    )


def _is_owned_or_pinned(package: str) -> bool:
    """True when a package spec is something other than a claimable moving name.

    Three ways out, and any one of them is enough:

    * a scope (`@modelcontextprotocol/server-git`) — the namespace has an owner,
      so the name cannot be squatted out from under the user;
    * a version (`mcp-remote@0.1.29`) — the code is pinned, so a later publish
      under that name does not change what runs. A moving tag like `@latest` is
      not a pin: it re-resolves on every launch;
    * a path or a URL (`./server.js`, `git+https://…`) — the code does not come
      from the registry namespace at all, so this rule has nothing to say about
      it. Whether *that* source is trustworthy is a different question, and one
      the other rules here are better placed to answer.
    """
    if package.startswith("@") or "://" in package or ":" in package:
        return True

    if package.startswith((".", "/", "~")) or "/" in package or "\\" in package:
        return True

    version = package.partition("@")[2].lower()
    return version not in MOVING_TAGS
