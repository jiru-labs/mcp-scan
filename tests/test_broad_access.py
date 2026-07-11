"""Tests for the broad-access rules.

Both rules fire on ordinary-looking configs — a filesystem server with a path,
a package run by a runner — so the negative cases carry the weight: what they
leave alone is what decides whether the user keeps reading the output. Each rule
is also checked for the recommendation it owes the user: a finding that says a
scope is too wide and does not say what to narrow it to is half a finding.
"""

from pathlib import Path

import pytest

from mcp_config_audit.parsers import MCPServer, parse_config_file
from mcp_config_audit.rules import Severity, run_rules
from mcp_config_audit.rules.broad_access import BroadFilesystemAccess, UnrestrictedShellAccess

FILESYSTEM_SERVER = "@modelcontextprotocol/server-filesystem"


def _server(
    *,
    command: str | None = None,
    args: tuple[str, ...] = (),
    url: str | None = None,
) -> MCPServer:
    return MCPServer(
        name="example",
        source=Path("/home/demo/.cursor/mcp.json"),
        host="cursor",
        command=command,
        args=args,
        url=url,
    )


def _filesystem_server(*paths: str) -> MCPServer:
    return _server(command="npx", args=("-y", FILESYSTEM_SERVER, *paths))


class TestBroadFilesystemAccess:
    """WARN: the server was handed a whole tree instead of a directory."""

    @pytest.mark.parametrize(
        "path",
        [
            # The filesystem root, and its Windows equivalent.
            "/",
            "C:\\",
            "C:/",
            # A home directory, however it is spelled.
            "~",
            "~/",
            "$HOME",
            "${HOME}",
            "%USERPROFILE%",
            "/home/demo",
            "/Users/demo",
            "C:\\Users\\demo",
            # Every home directory at once.
            "/home",
            "/Users",
            # A mounted disk, and every mount point on the machine.
            "/Volumes/Macintosh HD",
            "/Volumes",
            "/mnt",
            "/media",
        ],
    )
    def test_flags_a_path_that_hands_over_a_whole_tree(self, path: str) -> None:
        findings = BroadFilesystemAccess().check(_filesystem_server(path))

        assert len(findings) == 1
        assert findings[0].severity is Severity.WARN
        assert findings[0].rule_id == "broad-filesystem-access"
        assert path in findings[0].message

    def test_flags_a_host_directory_mounted_whole_into_a_container(self) -> None:
        """A container reaches exactly what is mounted into it."""
        server = _server(
            command="docker",
            args=("run", "-i", "--rm", "-v", "/:/host", "ghcr.io/example/mcp-server"),
        )

        findings = BroadFilesystemAccess().check(server)

        assert len(findings) == 1
        assert "/" in findings[0].message

    @pytest.mark.parametrize(
        "args",
        [
            ("run", "--volume", "/Users/demo:/data", "ghcr.io/example/mcp-server"),
            ("run", "--volume=/Users/demo:/data:ro", "ghcr.io/example/mcp-server"),
            ("run", "--mount", "type=bind,source=/Users/demo,target=/data"),
            ("run", "--mount", "type=bind,src=/Users/demo,dst=/data,readonly"),
        ],
    )
    def test_reads_the_host_side_of_a_mount_however_it_is_spelled(
        self, args: tuple[str, ...]
    ) -> None:
        findings = BroadFilesystemAccess().check(_server(command="docker", args=args))

        assert len(findings) == 1
        assert "/Users/demo" in findings[0].message

    def test_flags_a_path_passed_as_the_value_of_a_flag(self) -> None:
        server = _server(command="mcp-server-fs", args=("--root=/",))

        assert len(BroadFilesystemAccess().check(server)) == 1

    def test_flags_every_broad_path_the_server_is_given(self) -> None:
        """A server takes a list of directories, and each one is its own grant."""
        server = _filesystem_server("/Users/demo", "/Volumes/Backup", "~/code/my-app")

        findings = BroadFilesystemAccess().check(server)

        assert len(findings) == 2

    def test_reports_one_path_once_however_many_times_it_appears(self) -> None:
        server = _filesystem_server("~", "~")

        assert len(BroadFilesystemAccess().check(server)) == 1

    def test_the_finding_says_what_is_in_scope_and_how_to_narrow_it(self) -> None:
        findings = BroadFilesystemAccess().check(_filesystem_server("/Users/demo"))

        message = findings[0].message
        # What the scope actually contains, and the shape of a scope that would
        # not have been flagged.
        assert "SSH key" in message
        assert "~/code/my-app" in message

    @pytest.mark.parametrize(
        "path",
        [
            "/Users/demo/code/my-app",
            "/home/demo/notes",
            "~/code",
            "$HOME/code",
            "C:\\Users\\demo\\code",
            # A directory that only looks like a home: it is one level too deep,
            # and one level too shallow is a name, not a tree.
            "/opt/homebrew",
            "/var/lib/mcp",
            # A mount point below the disk, rather than the disk itself.
            "/Volumes/Backup/mcp",
            "/mnt/data/notes",
        ],
    )
    def test_ignores_a_path_scoped_to_a_directory(self, path: str) -> None:
        assert BroadFilesystemAccess().check(_filesystem_server(path)) == []

    @pytest.mark.parametrize(
        ("command", "args"),
        [
            # An argument that is not a path at all.
            ("npx", ("-y", "@example/mcp-server", "--readonly")),
            ("docker", ("run", "-i", "--rm", "ghcr.io/example/mcp-server")),
            # A container path, mounted from a directory: what the container
            # calls it says nothing about what the host gave it.
            ("docker", ("run", "-v", "/Users/demo/code:/", "ghcr.io/example/srv")),
        ],
    )
    def test_ignores_a_server_that_was_handed_no_broad_path(
        self, command: str, args: tuple[str, ...]
    ) -> None:
        assert BroadFilesystemAccess().check(_server(command=command, args=args)) == []

    def test_a_remote_server_is_given_no_paths_to_flag(self) -> None:
        assert BroadFilesystemAccess().check(_server(url="https://mcp.example.com")) == []


class TestUnrestrictedShellAccess:
    """WARN: the server's job is to run whatever the agent composes."""

    @pytest.mark.parametrize(
        ("command", "args"),
        [
            ("uvx", ("mcp-shell-server",)),
            ("npx", ("-y", "mcp-server-commands")),
            ("npx", ("-y", "@example/desktop-commander")),
            ("npx", ("-y", "iterm-mcp")),
            ("pnpm", ("dlx", "@example/mcp-terminal")),
            ("pipx", ("run", "mcp-bash-server")),
            # A shell server installed as a binary, rather than fetched.
            ("/usr/local/bin/mcp-shell-server", ()),
        ],
    )
    def test_flags_a_server_that_runs_arbitrary_commands(
        self, command: str, args: tuple[str, ...]
    ) -> None:
        findings = UnrestrictedShellAccess().check(_server(command=command, args=args))

        assert len(findings) == 1
        assert findings[0].severity is Severity.WARN
        assert findings[0].rule_id == "unrestricted-shell-access"

    def test_the_finding_names_the_server_and_what_to_do_about_it(self) -> None:
        findings = UnrestrictedShellAccess().check(
            _server(command="uvx", args=("mcp-shell-server",))
        )

        message = findings[0].message
        assert "mcp-shell-server" in message
        assert "allow-list" in message

    @pytest.mark.parametrize(
        ("command", "args"),
        [
            # A shell as the *launcher* of a server is how configs start one:
            # the command line is fixed, and the agent cannot add to it.
            ("sh", ("-c", "node /opt/mcp/index.js")),
            ("bash", ("/opt/mcp/start.sh",)),
            ("cmd.exe", ("/c", "C:\\mcp\\start.bat")),
            # Servers scoped to a task, whatever they are made of.
            ("npx", ("-y", FILESYSTEM_SERVER, "~/code")),
            ("uvx", ("mcp-server-postgres", "--readonly")),
            ("docker", ("run", "-i", "--rm", "ghcr.io/github/github-mcp-server")),
            # A name that merely contains the letters of one.
            ("npx", ("-y", "marshall-mcp")),
            ("npx", ("-y", "@example/seashell-notes")),
            # A runner given no package to run.
            ("npx", ()),
        ],
    )
    def test_ignores_a_server_that_is_not_a_shell(
        self, command: str, args: tuple[str, ...]
    ) -> None:
        assert UnrestrictedShellAccess().check(_server(command=command, args=args)) == []

    def test_a_remote_server_runs_no_command_to_flag(self) -> None:
        assert UnrestrictedShellAccess().check(_server(url="https://mcp.example.com")) == []


class TestOnARealConfig:
    """The rules, on a config file, through the parser that feeds them."""

    def test_flags_each_over_scoped_server_and_leaves_the_scoped_one_alone(
        self, broad_access_config: Path
    ) -> None:
        servers = parse_config_file(broad_access_config).servers

        result = run_rules(servers)

        assert [(f.rule_id, f.server.name) for f in result.findings] == [
            ("broad-filesystem-access", "docker-root-mount"),
            ("broad-filesystem-access", "filesystem-root"),
            ("broad-filesystem-access", "home-directory"),
            ("unrestricted-shell-access", "shell"),
        ]
        assert result.warnings == []

    def test_flags_the_home_directory_an_everyday_config_hands_over(
        self, sample_config: Path
    ) -> None:
        """The default install: a filesystem server pointed at the whole home."""
        servers = parse_config_file(sample_config).servers

        result = run_rules(servers)

        assert [
            (f.rule_id, f.server.name)
            for f in result.findings
            if f.rule_id == BroadFilesystemAccess.id
        ] == [("broad-filesystem-access", "filesystem")]
