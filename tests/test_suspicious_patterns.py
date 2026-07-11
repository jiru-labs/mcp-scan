"""Tests for the suspicious-pattern rules.

Every heuristic is tested from both sides. The negative cases carry the weight:
these rules fire on ordinary-looking command lines, so what they leave alone is
what decides whether a user keeps reading the output.
"""

from pathlib import Path

import pytest

from mcp_scan.parsers import MCPServer, parse_config_file
from mcp_scan.rules import Severity, run_rules
from mcp_scan.rules.suspicious_patterns import (
    ExecutableInTempDir,
    InsecureTransport,
    RemoteCodeExecution,
    UnscopedPackage,
)


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


class TestRemoteCodeExecution:
    """CRITICAL: the launch command downloads code and runs it."""

    @pytest.mark.parametrize(
        "script",
        [
            "curl -sSL https://example.com/install.sh | sh",
            "curl https://example.com/i.sh|bash",
            "wget -qO- https://example.com/i.sh | sudo bash",
            "curl -s https://example.com/setup.py | python3",
            "curl -sSL https://example.com/x.js | node",
            'eval "$(curl -fsSL https://example.com/env)"',
            "iex (iwr https://example.com/install.ps1).Content",
        ],
    )
    def test_flags_a_command_that_downloads_and_executes(self, script: str) -> None:
        server = _server(command="sh", args=("-c", script))

        findings = RemoteCodeExecution().check(server)

        assert len(findings) == 1
        assert findings[0].severity is Severity.CRITICAL
        assert findings[0].rule_id == "remote-code-execution"

    def test_flags_it_once_however_many_ways_it_executes(self) -> None:
        """One command line that downloads and runs code is one problem."""
        server = _server(
            command="sh",
            args=(
                "-c",
                'curl -s https://example.com/a | sh; '
                'eval "$(curl -s https://example.com/b)"',
            ),
        )

        assert len(RemoteCodeExecution().check(server)) == 1

    @pytest.mark.parametrize(
        ("command", "args"),
        [
            # A download that goes to a file, not to an interpreter. Whether the
            # file is then run is a question for the other rules here.
            ("curl", ("-o", "/opt/mcp/server.js", "https://example.com/server.js")),
            # A pipe, but into a tool that reads data rather than running it.
            ("sh", ("-c", "curl -s https://example.com/api | jq .")),
            # An interpreter, but nothing was downloaded for it to run.
            ("sh", ("-c", "node /opt/mcp/server.js | tee /var/log/mcp.log")),
            # `curl` in the name of a package is not `curl` the command.
            ("npx", ("-y", "@example/curl-mcp-server")),
            ("node", ("/opt/mcp/index.js",)),
        ],
    )
    def test_ignores_a_command_that_does_not_execute_what_it_downloads(
        self, command: str, args: tuple[str, ...]
    ) -> None:
        assert RemoteCodeExecution().check(_server(command=command, args=args)) == []

    def test_a_remote_server_has_no_launch_command_to_flag(self) -> None:
        assert RemoteCodeExecution().check(_server(url="https://example.com/mcp")) == []


class TestInsecureTransport:
    """CRITICAL: the server is reached in the clear."""

    @pytest.mark.parametrize(
        "url",
        [
            "http://mcp.example.com/sse",
            "http://203.0.113.10:8080/mcp",
            "ws://mcp.example.com/socket",
        ],
    )
    def test_flags_a_plaintext_url(self, url: str) -> None:
        findings = InsecureTransport().check(_server(url=url))

        assert len(findings) == 1
        assert findings[0].severity is Severity.CRITICAL
        assert findings[0].rule_id == "insecure-transport"
        assert url in findings[0].message

    def test_flags_a_plaintext_url_passed_on_the_command_line(self) -> None:
        """A stdio server proxying a remote one puts the URL in its args."""
        server = _server(
            command="npx", args=("-y", "mcp-remote", "http://mcp.example.com/sse")
        )

        findings = InsecureTransport().check(server)

        assert len(findings) == 1
        assert "http://mcp.example.com/sse" in findings[0].message

    def test_reports_one_url_once_however_many_times_it_appears(self) -> None:
        server = _server(
            url="http://mcp.example.com/sse",
            args=("--endpoint", "http://mcp.example.com/sse"),
        )

        assert len(InsecureTransport().check(server)) == 1

    @pytest.mark.parametrize(
        "url",
        [
            "https://mcp.example.com/sse",
            "wss://mcp.example.com/socket",
            # Loopback never reaches a network, so there is no path to listen on.
            "http://localhost:3000/sse",
            "http://127.0.0.1:8080/mcp",
            "http://[::1]:3000/mcp",
            "http://mcp.localhost:3000/sse",
        ],
    )
    def test_ignores_a_url_that_is_encrypted_or_never_leaves_the_machine(
        self, url: str
    ) -> None:
        assert InsecureTransport().check(_server(url=url)) == []

    def test_ignores_a_local_server_that_reaches_nothing(self) -> None:
        server = _server(command="npx", args=("-y", "@example/mcp-server"))

        assert InsecureTransport().check(server) == []


class TestExecutableInTempDir:
    """WARN: the code that runs was left in a directory anyone can write to."""

    @pytest.mark.parametrize(
        ("command", "args"),
        [
            ("/tmp/mcp-server", ()),
            ("/var/tmp/mcp-server", ()),
            ("node", ("/tmp/mcp/index.js",)),
            ("python3", ("/private/tmp/server.py",)),
            ("sh", ("/dev/shm/start.sh",)),
            ("/home/demo/Downloads/mcp-server", ()),
            ("node", ("/Users/demo/Downloads/server.js",)),
            ("cmd.exe", ("/c", "%TEMP%\\mcp-server.exe")),
            ("powershell", ("-File", "C:\\Windows\\Temp\\start.ps1")),
        ],
    )
    def test_flags_an_executable_under_a_temporary_directory(
        self, command: str, args: tuple[str, ...]
    ) -> None:
        findings = ExecutableInTempDir().check(_server(command=command, args=args))

        assert len(findings) == 1
        assert findings[0].severity is Severity.WARN
        assert findings[0].rule_id == "executable-in-temp-dir"

    def test_flags_every_temporary_path_the_command_runs(self) -> None:
        server = _server(command="/tmp/runner", args=("/tmp/plugin.js",))

        assert len(ExecutableInTempDir().check(server)) == 2

    def test_ignores_a_temporary_directory_the_server_merely_serves(self) -> None:
        """`server-filesystem /tmp` exposes a directory as data. It runs nothing."""
        server = _server(
            command="npx",
            args=("-y", "@modelcontextprotocol/server-filesystem", "/tmp", "/var/tmp"),
        )

        assert ExecutableInTempDir().check(server) == []

    @pytest.mark.parametrize(
        ("command", "args"),
        [
            ("/usr/local/bin/mcp-server", ()),
            ("node", ("/home/demo/mcp/index.js",)),
            ("npx", ("-y", "@example/mcp-server")),
            # A user's own `~/tmp` is not the world-writable one.
            ("node", ("/home/demo/tmp-notes/index.js",)),
            # Nor is a project directory that merely has the word in its path.
            ("node", ("/opt/temporal/server.js",)),
        ],
    )
    def test_ignores_an_executable_that_lives_somewhere_ordinary(
        self, command: str, args: tuple[str, ...]
    ) -> None:
        assert ExecutableInTempDir().check(_server(command=command, args=args)) == []


class TestUnscopedPackage:
    """WARN: the package name is unowned and the version is unpinned."""

    @pytest.mark.parametrize(
        ("command", "args"),
        [
            ("npx", ("-y", "mcp-example-server")),
            ("npx", ("mcp-example-server",)),
            ("bunx", ("mcp-example-server",)),
            ("pnpx", ("mcp-example-server",)),
            ("pnpm", ("dlx", "mcp-example-server")),
            ("yarn", ("dlx", "mcp-example-server")),
            ("npm", ("exec", "mcp-example-server")),
            ("/usr/local/bin/npx", ("-y", "mcp-example-server")),
            ("npx.cmd", ("-y", "mcp-example-server")),
            # A moving tag re-resolves on every launch; it pins nothing.
            ("npx", ("-y", "mcp-example-server@latest")),
        ],
    )
    def test_flags_an_unscoped_unpinned_package(
        self, command: str, args: tuple[str, ...]
    ) -> None:
        findings = UnscopedPackage().check(_server(command=command, args=args))

        assert len(findings) == 1
        assert findings[0].severity is Severity.WARN
        assert findings[0].rule_id == "unscoped-package"
        assert "mcp-example-server" in findings[0].message

    def test_names_the_package_and_how_to_pin_it(self) -> None:
        server = _server(command="npx", args=("-y", "mcp-example-server@latest"))

        message = UnscopedPackage().check(server)[0].message

        assert "mcp-example-server@latest" in message
        assert "mcp-example-server@1.2.3" in message

    @pytest.mark.parametrize(
        ("command", "args"),
        [
            # A scope has an owner: the name cannot be claimed out from under you.
            ("npx", ("-y", "@modelcontextprotocol/server-git")),
            # A version pins what runs, whoever owns the name tomorrow.
            ("npx", ("-y", "mcp-example-server@0.1.29")),
            ("npx", ("-y", "mcp-example-server@1.2.3-beta.1")),
            # Local code does not come from the registry at all.
            ("npx", ("./local/server.js",)),
            ("npx", ("/opt/mcp/server.js",)),
            # Neither does a git spec.
            ("npx", ("github:example/mcp-server",)),
            # Not a package runner: nothing is resolved from a registry.
            ("node", ("server.js",)),
            ("docker", ("run", "-i", "--rm", "ghcr.io/example/mcp-server")),
            # PyPI has no scopes at all, so the heuristic does not transfer.
            ("uvx", ("mcp-server-postgres",)),
            # A runner given no package to run.
            ("npx", ()),
            ("npx", ("--help",)),
        ],
    )
    def test_ignores_a_package_that_is_owned_pinned_or_not_from_a_registry(
        self, command: str, args: tuple[str, ...]
    ) -> None:
        assert UnscopedPackage().check(_server(command=command, args=args)) == []


class TestOnARealConfig:
    """The rules, on a config file, through the parser that feeds them."""

    def test_flags_each_suspicious_server_and_leaves_the_clean_one_alone(
        self, suspicious_config: Path
    ) -> None:
        servers = parse_config_file(suspicious_config).servers

        result = run_rules(servers)

        assert [(f.rule_id, f.server.name) for f in result.findings] == [
            # Worst first: what runs foreign code, then what is left to the wire.
            ("remote-code-execution", "installer"),
            ("insecure-transport", "plaintext-remote"),
            ("executable-in-temp-dir", "dropped-in-tmp"),
            ("unscoped-package", "unscoped-runner"),
        ]
        assert result.warnings == []

    def test_an_ordinary_config_produces_no_suspicious_pattern_findings(
        self, sample_config: Path
    ) -> None:
        """The everyday config: scoped packages, a container, an HTTPS URL.

        It has credentials in it, and those rules fire. None of these may.
        """
        servers = parse_config_file(sample_config).servers

        result = run_rules(servers)

        suspicious = {
            RemoteCodeExecution.id,
            InsecureTransport.id,
            ExecutableInTempDir.id,
            UnscopedPackage.id,
        }
        assert [f for f in result.findings if f.rule_id in suspicious] == []
