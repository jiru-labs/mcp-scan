"""Tests for the static-credential rules."""

from pathlib import Path

import pytest

from mcp_audit.parsers import MCPServer, parse_config_file
from mcp_audit.rules import Severity, run_rules
from mcp_audit.rules.static_credentials import (
    StaticCredentialInArgs,
    StaticCredentialInEnv,
    StaticCredentialInUrl,
)

# A GitHub token, an OpenAI-style key and a JWT, in the shape the real ones come
# in. None is a live credential; all of them must stay out of every finding.
FAKE_GITHUB_TOKEN = "ghp_FAKEfixtureTOKENdoNotUse0123456789"
FAKE_API_KEY = "sk-FAKEfixtureKEYdoNotUse0123456789"
FAKE_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJGQUtFIn0.FAKEfixtureSIGNATURE"


def _server(
    *,
    args: tuple[str, ...] = (),
    env_keys: tuple[str, ...] = (),
    env_static_keys: tuple[str, ...] = (),
) -> MCPServer:
    return MCPServer(
        name="github",
        source=Path("/home/demo/.cursor/mcp.json"),
        host="cursor",
        command="npx",
        args=args,
        env_keys=env_keys,
        env_static_keys=env_static_keys,
    )


class TestStaticCredentialInEnv:
    """WARN: a credential hardcoded in an `env` entry."""

    def test_flags_an_env_var_that_names_a_secret_and_holds_a_value(self) -> None:
        server = _server(
            env_keys=("GITHUB_TOKEN",), env_static_keys=("GITHUB_TOKEN",)
        )

        findings = StaticCredentialInEnv().check(server)

        assert len(findings) == 1
        assert findings[0].severity is Severity.WARN
        assert findings[0].rule_id == "static-credential-in-env"
        assert "GITHUB_TOKEN" in findings[0].message

    def test_flags_every_hardcoded_credential_separately(self) -> None:
        server = _server(
            env_keys=("GITHUB_TOKEN", "AWS_SECRET"),
            env_static_keys=("GITHUB_TOKEN", "AWS_SECRET"),
        )

        findings = StaticCredentialInEnv().check(server)

        assert [f.message.split("'")[1] for f in findings] == [
            "GITHUB_TOKEN",
            "AWS_SECRET",
        ]

    def test_ignores_an_env_var_that_holds_no_value_in_the_config(self) -> None:
        """Declared, but left for the environment to fill in: nothing on disk."""
        server = _server(env_keys=("GITHUB_TOKEN",), env_static_keys=())

        assert StaticCredentialInEnv().check(server) == []

    def test_ignores_a_hardcoded_value_that_is_not_a_credential(self) -> None:
        server = _server(env_keys=("LOG_LEVEL",), env_static_keys=("LOG_LEVEL",))

        assert StaticCredentialInEnv().check(server) == []

    def test_a_clean_server_is_not_flagged(self) -> None:
        assert StaticCredentialInEnv().check(_server()) == []


class TestStaticCredentialInArgs:
    """CRITICAL: a credential passed inline on the command line."""

    def test_flags_a_credential_attached_to_a_flag(self) -> None:
        server = _server(args=("-y", "server", f"--api-key={FAKE_API_KEY}"))

        findings = StaticCredentialInArgs().check(server)

        assert len(findings) == 1
        assert findings[0].severity is Severity.CRITICAL
        assert findings[0].rule_id == "static-credential-in-args"
        # Where it is, and what carries it — never what it is.
        assert "argument 3" in findings[0].message
        assert "--api-key" in findings[0].message
        assert FAKE_API_KEY not in findings[0].message

    def test_flags_a_credential_in_the_argument_after_its_flag(self) -> None:
        server = _server(args=("--token", FAKE_GITHUB_TOKEN))

        findings = StaticCredentialInArgs().check(server)

        assert len(findings) == 1
        assert "argument 2" in findings[0].message

    @pytest.mark.parametrize(
        ("token", "named"),
        [
            (FAKE_GITHUB_TOKEN, "a GitHub token"),
            (FAKE_API_KEY, "an API key"),
            (FAKE_JWT, "a JWT"),
            ("xoxb-1234567890-FAKEfixture", "a Slack token"),
            ("AKIAFAKEFIXTURE01234", "an AWS access key id"),
        ],
    )
    def test_flags_a_bare_token_by_the_shape_of_it(
        self, token: str, named: str
    ) -> None:
        """No flag names it, but the token gives itself away."""
        server = _server(args=("--header", token))

        findings = StaticCredentialInArgs().check(server)

        assert len(findings) == 1
        assert named in findings[0].message
        assert token not in findings[0].message

    def test_flags_a_credential_carried_in_a_header_argument(self) -> None:
        server = _server(args=("--header", f"Authorization: Bearer {FAKE_JWT}"))

        findings = StaticCredentialInArgs().check(server)

        assert len(findings) == 1
        assert FAKE_JWT not in findings[0].message

    def test_flags_an_env_style_assignment_in_the_args(self) -> None:
        server = _server(args=("env", f"GITHUB_TOKEN={FAKE_GITHUB_TOKEN}", "npx"))

        findings = StaticCredentialInArgs().check(server)

        assert len(findings) == 1
        assert "argument 2" in findings[0].message

    def test_flags_each_credential_in_a_command_line_that_carries_several(
        self,
    ) -> None:
        server = _server(
            args=("--api-key", FAKE_API_KEY, f"--token={FAKE_GITHUB_TOKEN}")
        )

        findings = StaticCredentialInArgs().check(server)

        assert [f.message.split()[1] for f in findings] == ["2", "3"]

    def test_a_flag_and_its_value_are_one_finding_not_two(self) -> None:
        """`--api-key ghp_…` is one leaked credential, however it is spelled."""
        server = _server(args=("--api-key", FAKE_GITHUB_TOKEN))

        assert len(StaticCredentialInArgs().check(server)) == 1

    def test_ignores_a_flag_whose_value_comes_from_the_environment(self) -> None:
        server = _server(args=("--api-key=${API_KEY}", "--token", "$GITHUB_TOKEN"))

        assert StaticCredentialInArgs().check(server) == []

    def test_ignores_a_flag_that_is_not_given_a_value(self) -> None:
        """`--token` followed by another flag took its value from elsewhere."""
        server = _server(args=("--token", "--verbose"))

        assert StaticCredentialInArgs().check(server) == []

    def test_ignores_an_ordinary_command_line(self) -> None:
        server = _server(
            args=(
                "-y",
                "@modelcontextprotocol/server-filesystem",
                "/Users/demo",
                "--readonly",
                "--ssh-key-path=/home/demo/.ssh/id_ed25519",
                "https://notes.example.com/mcp",
                "ghcr.io/github/github-mcp-server",
            )
        )

        assert StaticCredentialInArgs().check(server) == []

    def test_a_clean_server_is_not_flagged(self) -> None:
        assert StaticCredentialInArgs().check(_server()) == []


class TestStaticCredentialInUrl:
    """CRITICAL: a credential written into a remote server's URL."""

    def _remote(self, url: str) -> MCPServer:
        return MCPServer(
            name="notes",
            source=Path("/home/demo/.cursor/mcp.json"),
            host="cursor",
            url=url,
        )

    def test_flags_a_credential_in_a_query_parameter(self) -> None:
        server = self._remote(f"https://mcp.example.com/sse?api_key={FAKE_API_KEY}")

        findings = StaticCredentialInUrl().check(server)

        assert len(findings) == 1
        assert findings[0].severity is Severity.CRITICAL
        assert findings[0].rule_id == "static-credential-in-url"
        # Which parameter to go and fix — never what is in it.
        assert "api_key" in findings[0].message
        assert FAKE_API_KEY not in findings[0].message

    def test_flags_a_password_in_the_authority(self) -> None:
        server = self._remote(f"https://demo:{FAKE_API_KEY}@mcp.example.com/mcp")

        findings = StaticCredentialInUrl().check(server)

        assert len(findings) == 1
        assert FAKE_API_KEY not in findings[0].message

    def test_flags_each_credential_a_url_carries(self) -> None:
        server = self._remote(
            f"https://demo:{FAKE_API_KEY}@mcp.example.com/sse?token={FAKE_GITHUB_TOKEN}"
        )

        assert len(StaticCredentialInUrl().check(server)) == 2

    def test_ignores_a_url_whose_credential_comes_from_the_environment(self) -> None:
        server = self._remote("https://mcp.example.com/sse?api_key=${API_KEY}")

        assert StaticCredentialInUrl().check(server) == []

    def test_ignores_an_ordinary_url(self) -> None:
        server = self._remote("https://mcp.example.com/sse?region=eu&version=2")

        assert StaticCredentialInUrl().check(server) == []

    def test_a_local_server_has_no_url_to_flag(self) -> None:
        assert StaticCredentialInUrl().check(_server()) == []


class TestOnARealConfig:
    """The rules, on a config file, through the parser that feeds them."""

    def test_reports_every_credential_and_leaves_the_clean_servers_alone(
        self, credentials_config: Path
    ) -> None:
        servers = parse_config_file(credentials_config).servers

        result = run_rules(servers)

        assert [(f.rule_id, f.server.name) for f in result.findings] == [
            # Worst first: what leaves the config file, before what stays in it.
            ("static-credential-in-args", "args-inline"),
            ("static-credential-in-url", "url-inline"),
            ("static-credential-in-env", "env-hardcoded"),
        ]
        assert result.warnings == []

    def test_no_finding_reports_a_credential_value(
        self, credentials_config: Path, credentials_secrets: list[str]
    ) -> None:
        """A finding says where the credential is. It never says what it is.

        The server a finding carries still holds its own `args`, credential and
        all — that is the command line, and dropping it would leave the user
        unable to act on the finding. What a finding *reports* is its message,
        and no credential may reach one.
        """
        servers = parse_config_file(credentials_config).servers

        result = run_rules(servers)

        assert credentials_secrets  # the fixture must actually carry secrets
        reported = " ".join(f"{f.title} {f.message}" for f in result.findings)
        assert reported  # ...and the rules must actually have reported them
        for secret in credentials_secrets:
            assert secret not in reported
