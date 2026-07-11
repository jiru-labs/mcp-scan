"""Tests for the static-credential rules."""

from pathlib import Path

import pytest

from mcp_scan.parsers import MCPServer, parse_config_file
from mcp_scan.rules import Severity, run_rules
from mcp_scan.rules.static_credentials import (
    StaticCredentialInArgs,
    StaticCredentialInEnv,
    names_a_secret,
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


class TestNamesASecret:
    """The shared name test, which decides what both rules even look at."""

    @pytest.mark.parametrize(
        "name",
        [
            "GITHUB_TOKEN",
            "API_KEY",
            "APIKEY",
            "AWS_SECRET",
            "DB_PASSWORD",
            "--api-key",
            "X-Api-Key",
            "Authorization",
        ],
    )
    def test_a_name_ending_in_a_secret_word_names_a_secret(self, name: str) -> None:
        assert names_a_secret(name)

    @pytest.mark.parametrize(
        "name",
        [
            # A path to a secret is not a secret, and neither is a switch that
            # merely mentions one.
            "SSH_KEY_PATH",
            "TOKEN_FILE",
            "AUTH_MODE",
            "--verbose",
            "LOG_LEVEL",
            "HOME",
            # `PWD` is the working directory, not a password.
            "PWD",
        ],
    )
    def test_a_name_that_only_mentions_a_secret_does_not_name_one(
        self, name: str
    ) -> None:
        assert not names_a_secret(name)


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


class TestOnARealConfig:
    """The rules, on a config file, through the parser that feeds them."""

    def test_reports_both_credentials_and_leaves_the_clean_server_alone(
        self, credentials_config: Path
    ) -> None:
        servers = parse_config_file(credentials_config).servers

        result = run_rules(servers)

        assert [(f.rule_id, f.server.name) for f in result.findings] == [
            # Worst first: the command line before the config file.
            ("static-credential-in-args", "args-inline"),
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
