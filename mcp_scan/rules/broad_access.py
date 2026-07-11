"""Detect servers handed more of the machine than they need.

An MCP server runs with the user's own privileges, and whatever it can reach,
the agent driving it can reach too. What bounds that reach is the scope written
into the config — the directories a filesystem server is pointed at, the
commands a server is allowed to run. This module reads that scope and flags the
two ways it is routinely left wide open:

* `broad-filesystem-access` (WARN) — the server is pointed at the filesystem
  root, a whole home directory or a mounted disk. A home directory is not a
  narrow scope: it holds `~/.ssh`, `~/.aws`, every `.env` file and every private
  repository on the machine, and a prompt injection that reaches the agent
  reaches all of it.
  Inspired by *Privilege Escalation via Scope Creep* and *Context Injection &
  Over-Sharing*.
* `unrestricted-shell-access` (WARN) — the server's whole purpose is to run
  arbitrary commands. It turns any prompt injection the agent swallows into
  code execution as the user, and no other rule here can bound it: the danger is
  not in how the server is configured but in what it is.
  Inspired by *Privilege Escalation via Scope Creep* and *Command Injection &
  Execution*.

Both findings carry the fix, because both have one and it is the same one:
narrow the scope. A filesystem server takes a list of directories, so it can be
given the project instead of the home; a shell server can be dropped in favour
of a server scoped to the task it was doing.

Neither rule reads a filesystem. A path is judged on its shape alone, as
written in the config: the scan is read-only, it must run the same way on a
machine that does not have these directories, and asking the disk would tell us
nothing about the risk anyway.

References:
    OWASP MCP Top 10 — https://owasp.org/www-project-mcp-top-10/
        The named categories above are its own. It is a v0.1 beta and describes
        itself as a living document, so the categories are cited by name: the
        numbering (MCP01…MCP10) may still move, and the names are the stable
        part.
"""

import re
from pathlib import PurePosixPath

from mcp_scan.parsers import MCPServer
from mcp_scan.rules.base import Finding, Rule, Severity

#: What a config writes when it means "the user's home directory". Normalised to
#: `~` before a path is judged, so each spelling reaches the same verdict.
HOME_REFERENCES = ("~", "${home}", "$home", "%userprofile%", "${userprofile}")

#: A path that hands over a whole tree rather than a working directory. The
#: label goes into the finding: it has to say what the path actually contains,
#: because `/Users/demo` reads harmless until someone spells out what is in it.
#: Matched against a path normalised to lowercase forward slashes with `~`
#: substituted in, so the Windows and shell spellings hit the same patterns.
BROAD_PATHS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"^/$"), "the entire filesystem"),
    (re.compile(r"^[a-z]:$"), "an entire disk"),
    (
        re.compile(r"^~$|^(?:[a-z]:)?/(?:users|home)/[^/]+$"),
        "a whole home directory — every SSH key, cloud credential, .env file "
        "and private repository in it",
    ),
    (
        re.compile(r"^(?:[a-z]:)?/(?:users|home)$"),
        "every home directory on the machine",
    ),
    (re.compile(r"^/volumes/[^/]+$"), "an entire mounted disk"),
    (re.compile(r"^/(?:volumes|mnt|media)$"), "every mounted disk"),
)

#: The flags that bind a host directory into a container, where the host side is
#: the scope actually granted: `-v /:/host` mounts the whole machine.
VOLUME_FLAGS = frozenset({"-v", "--volume"})

#: The same mount, spelled the long way: `--mount type=bind,source=/,target=…`.
MOUNT_SOURCE = re.compile(r"(?:^|,)\s*(?:source|src)=([^,]+)", re.IGNORECASE)

#: A word that says a program's job is to run whatever it is told to run.
SHELL_WORDS = frozenset(
    {
        "bash",
        "cmd",
        "command",
        "commander",
        "commands",
        "console",
        "exec",
        "iterm",
        "powershell",
        "shell",
        "shells",
        "subprocess",
        "terminal",
        "tmux",
        "zsh",
    }
)

#: An interpreter, named on its own. It is how a config *launches* a server —
#: `bash -c …`, `cmd.exe /c …` — not a server that hands the agent a shell, so
#: the shell word in its name means nothing here. A compound name that merely
#: contains one (`mcp-shell-server`) is a different matter, and is the thing
#: this rule is looking for.
SHELL_BINARIES = frozenset(
    {"bash", "cmd", "csh", "dash", "fish", "ksh", "powershell", "pwsh", "sh", "zsh"}
)

#: Commands that resolve a package from a registry and execute it in one step:
#: what runs is the package, not the runner, so that is the name to judge.
PACKAGE_RUNNERS = frozenset({"npx", "bunx", "pnpx", "uvx"})

#: The same thing, spelled as a subcommand: `pnpm dlx …`, `pipx run …`.
RUNNER_SUBCOMMANDS = frozenset(
    {("pnpm", "dlx"), ("yarn", "dlx"), ("npm", "exec"), ("pipx", "run")}
)


class BroadFilesystemAccess(Rule):
    """Flag a server pointed at a root, a home directory or a whole disk."""

    id = "broad-filesystem-access"
    title = "Server granted access to a whole filesystem, home or disk"
    severity = Severity.WARN

    def check(self, server: MCPServer) -> list[Finding]:
        findings = []

        for path in _granted_paths(server):
            scope = _broad_scope_of(path)
            if scope is not None:
                findings.append(
                    self.finding(
                        server,
                        f"the server is given '{path}', which is {scope}; grant it "
                        f"the directories it works in instead, one by one "
                        f"('~/code/my-app')",
                    )
                )

        return findings


class UnrestrictedShellAccess(Rule):
    """Flag a server whose job is to run arbitrary commands for the agent."""

    id = "unrestricted-shell-access"
    title = "Server gives the agent an unrestricted shell"
    severity = Severity.WARN

    def check(self, server: MCPServer) -> list[Finding]:
        return [
            self.finding(
                server,
                f"'{program}' runs any command the agent composes, as you, so a "
                f"prompt injection in anything the agent reads becomes code "
                f"execution. Restrict it to an allow-list of the commands you need, "
                f"or use a server scoped to the task (git, filesystem)",
            )
            for program in _programs_run_by(server)
            if _is_a_shell(program)
        ]


def _granted_paths(server: MCPServer) -> list[str]:
    """The paths this server definition hands over, as written in the config.

    A directory a server is given is almost always a bare argument
    (`server-filesystem ~/code`), sometimes the value of a flag
    (`--root=/`), and in a containerised server the host half of a volume
    mount (`-v /:/host`) — the mount is what decides what the container can
    reach, so it is the scope that counts.
    """
    paths: list[str] = []
    expects_volume = False

    for arg in server.args:
        if expects_volume:
            paths.append(_mount_source(arg))
            expects_volume = False
            continue

        flag, separator, value = arg.partition("=")

        if arg.lower() in VOLUME_FLAGS:
            expects_volume = True
        elif flag.lower() in VOLUME_FLAGS and separator:
            paths.append(_mount_source(value))
        elif MOUNT_SOURCE.search(arg):
            paths.extend(MOUNT_SOURCE.findall(arg))
        elif separator:
            paths.append(value)
        else:
            paths.append(arg)

    return list(dict.fromkeys(path for path in paths if path))


def _mount_source(spec: str) -> str:
    """The host side of a `-v host:container[:ro]` mount.

    A read-only mount is not a narrower scope for this rule's purpose: what
    leaks a private key is reading it.
    """
    if re.match(r"^[A-Za-z]:[\\/]", spec):
        # A Windows host path brings a colon of its own: `C:\Users\demo:/data`.
        drive, _, rest = spec.partition(":")
        return f"{drive}:{rest.partition(':')[0]}"
    return spec.partition(":")[0]


def _broad_scope_of(path: str) -> str | None:
    """Name what a path hands over, or None when it hands over a directory."""
    normalised = _normalise(path)
    for pattern, scope in BROAD_PATHS:
        if pattern.fullmatch(normalised):
            return scope
    return None


def _normalise(path: str) -> str:
    """A path in one spelling: lowercase, forward slashes, `~` for the home.

    `$HOME`, `%USERPROFILE%` and `~` all name the same directory, and `C:\\` and
    `/` the same kind of scope; the patterns only have to know one of each.
    """
    text = path.strip().strip("\"'").replace("\\", "/").lower()

    for reference in HOME_REFERENCES:
        if text == reference or text.startswith(f"{reference}/"):
            text = f"~{text[len(reference):]}"
            break

    # A trailing slash is a spelling, not a scope: `/tmp/` is `/tmp`. Root is
    # nothing but its slash, and keeps it.
    return text if text == "/" else text.rstrip("/")


def _programs_run_by(server: MCPServer) -> list[str]:
    """The programs this server definition actually runs, by name.

    The command is one, unless it is a bare interpreter — then it is only the
    launcher, and the program is what it was handed. A package runner is the
    same story: `uvx mcp-shell-server` runs the package, not `uvx`.
    """
    if not server.command:
        return []

    binary = _binary_name(server.command)
    programs = [] if binary in SHELL_BINARIES else [binary]

    package = _package_run_by(binary, server.args)
    if package is not None:
        programs.append(package)

    return programs


def _binary_name(command: str) -> str:
    """The name of the binary a command runs: `/usr/local/bin/npx` is `npx`."""
    name = PurePosixPath(command.replace("\\", "/").lower()).name
    return name.removesuffix(".cmd").removesuffix(".exe")


def _package_run_by(binary: str, args: tuple[str, ...]) -> str | None:
    """The package a runner command fetches and executes, if it is one.

    Runners take flags before the package, so the package is the first argument
    that is not one. `--` ends the flags without naming anything itself.
    """
    if binary in PACKAGE_RUNNERS:
        rest = list(args)
    elif args and (binary, args[0].lower()) in RUNNER_SUBCOMMANDS:
        rest = list(args[1:])
    else:
        return None

    return next((arg for arg in rest if arg != "--" and not arg.startswith("-")), None)


def _is_a_shell(program: str) -> bool:
    """True when a program's name says it runs whatever it is asked to.

    Judged word by word, so `mcp-shell-server`, `@example/desktop-commander` and
    `iterm-mcp` are caught while `@modelcontextprotocol/server-filesystem` — and
    a package whose name merely contains the letters, like `marshall-mcp` — are
    left alone.
    """
    words = re.split(r"[^a-z0-9]+", program.lower())
    return any(word in SHELL_WORDS for word in words)
