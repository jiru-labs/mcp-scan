"""Tests for the shared credential vocabulary and the redaction it backs."""

import pytest

from mcp_config_audit.credentials import (
    REDACTED,
    credentials_in,
    credentials_in_url,
    names_a_secret,
    redact_args,
    redact_url,
)

# A GitHub token, an OpenAI-style key and a JWT, in the shape the real ones come
# in. None is a live credential; all of them must stay out of every rendering.
FAKE_GITHUB_TOKEN = "ghp_FAKEfixtureTOKENdoNotUse0123456789"
FAKE_API_KEY = "sk-FAKEfixtureKEYdoNotUse0123456789"
FAKE_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJGQUtFIn0.FAKEfixtureSIGNATURE"


class TestNamesASecret:
    """The name test, which decides what the rules and the renderer look at."""

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


class TestRedactArgs:
    """A command line rendered safe: the secret gone, the rest of it intact."""

    def test_masks_the_value_attached_to_a_flag(self) -> None:
        args = ("-y", "server", f"--api-key={FAKE_API_KEY}")

        assert redact_args(args) == ("-y", "server", "--api-key=***")

    def test_masks_the_value_in_the_argument_after_its_flag(self) -> None:
        """The flag stays: it is what tells the user which argument to fix."""
        args = ("--token", FAKE_GITHUB_TOKEN, "--verbose")

        assert redact_args(args) == ("--token", REDACTED, "--verbose")

    def test_masks_an_env_style_assignment(self) -> None:
        args = ("env", f"GITHUB_TOKEN={FAKE_GITHUB_TOKEN}", "npx")

        assert redact_args(args) == ("env", "GITHUB_TOKEN=***", "npx")

    @pytest.mark.parametrize(
        "token",
        [
            FAKE_GITHUB_TOKEN,
            FAKE_API_KEY,
            FAKE_JWT,
            "xoxb-1234567890-FAKEfixture",
            "AKIAFAKEFIXTURE01234",
        ],
    )
    def test_masks_a_bare_token_no_flag_names(self, token: str) -> None:
        """No flag gives it away, so the whole argument goes."""
        assert redact_args(("--header", token)) == ("--header", REDACTED)

    def test_masks_only_the_token_inside_a_header_argument(self) -> None:
        """The header keeps its name — all that is secret is the token in it."""
        args = ("--header", f"Authorization: Bearer {FAKE_JWT}")

        assert redact_args(args) == ("--header", "Authorization:***")

    def test_masks_a_bearer_token_and_keeps_the_text_around_it(self) -> None:
        args = ("--header", f"X-Custom: Bearer {FAKE_JWT} (staging)")

        assert redact_args(args) == ("--header", "X-Custom: *** (staging)")

    def test_masks_every_credential_in_a_command_line_that_carries_several(
        self,
    ) -> None:
        args = ("--api-key", FAKE_API_KEY, f"--token={FAKE_GITHUB_TOKEN}")

        assert redact_args(args) == ("--api-key", REDACTED, "--token=***")

    def test_masks_a_credential_inside_a_url_passed_as_an_argument(self) -> None:
        """A proxy server puts the remote URL in its args, secrets and all.

        The URL is masked by the same walk a remote server's `url` field is —
        the password in `user:password@`, the token in a query parameter — so a
        stdio server cannot smuggle out through its command line what a remote
        server could not through its endpoint.
        """
        password = "hunter2secret"
        args = (
            "mcp-remote",
            f"https://user:{password}@host.example.com/sse?api_key={FAKE_API_KEY}",
        )

        redacted = redact_args(args)

        rendered = " ".join(redacted)
        assert password not in rendered
        assert FAKE_API_KEY not in rendered
        assert redacted[1] == "https://user:***@host.example.com/sse?api_key=***"

    def test_names_a_url_credential_without_quoting_the_secret(self) -> None:
        """The label is printed too, so it must not slice the URL on a colon.

        Splitting `https://user:password@host/?token=x` on its first `:` would
        put the userinfo into the flag name and quote the password there. The URL
        walk names it — `a password` — and echoes none of it.
        """
        password = "hunter2secret"
        (credential,) = credentials_in(
            (f"https://user:{password}@host.example.com/?token=x",)
        )

        assert credential is not None
        assert password not in credential.label
        assert credential.label == "a password"

    def test_leaves_a_flag_whose_value_comes_from_the_environment_alone(self) -> None:
        """`${API_KEY}` is the fix, not the leak: masking it would hide that."""
        args = ("--api-key=${API_KEY}", "--token", "$GITHUB_TOKEN")

        assert redact_args(args) == args

    def test_leaves_an_ordinary_command_line_untouched(self) -> None:
        args = (
            "-y",
            "@modelcontextprotocol/server-filesystem",
            "/Users/demo",
            "--readonly",
            "--ssh-key-path=/home/demo/.ssh/id_ed25519",
            "https://notes.example.com/mcp",
            "ghcr.io/github/github-mcp-server",
        )

        assert redact_args(args) == args

    def test_no_secret_survives_redaction(self) -> None:
        """The guarantee itself, stated once: nothing of the value comes back."""
        args = (
            "--api-key",
            FAKE_API_KEY,
            f"--token={FAKE_GITHUB_TOKEN}",
            f"Authorization: Bearer {FAKE_JWT}",
        )

        rendered = " ".join(redact_args(args))

        for secret in (FAKE_API_KEY, FAKE_GITHUB_TOKEN, FAKE_JWT):
            assert secret not in rendered

    def test_redacts_nothing_when_there_are_no_args(self) -> None:
        assert redact_args(()) == ()


class TestUrlCredentials:
    """A remote server has no arguments — its whole endpoint is one URL."""

    def test_names_and_masks_a_credential_in_a_query_parameter(self) -> None:
        url = f"https://mcp.example.com/sse?api_key={FAKE_API_KEY}"

        assert credentials_in_url(url) == ["the value of 'api_key'"]
        assert redact_url(url) == "https://mcp.example.com/sse?api_key=***"

    def test_masks_only_the_credentialed_parameter(self) -> None:
        """The rest of the query is what tells the user which server this is."""
        url = f"https://mcp.example.com/sse?region=eu&token={FAKE_GITHUB_TOKEN}&v=2"

        assert redact_url(url) == "https://mcp.example.com/sse?region=eu&token=***&v=2"

    def test_names_and_masks_a_password_in_the_authority(self) -> None:
        url = f"https://demo:{FAKE_API_KEY}@mcp.example.com/mcp"

        assert credentials_in_url(url) == ["a password"]
        assert redact_url(url) == "https://demo:***@mcp.example.com/mcp"

    def test_names_a_password_without_quoting_the_user_it_belongs_to(self) -> None:
        """A URL can carry the token *as* the username. Naming it would echo it."""
        url = f"https://{FAKE_GITHUB_TOKEN}:x-oauth-basic@mcp.example.com/mcp"

        assert FAKE_GITHUB_TOKEN not in " ".join(credentials_in_url(url))
        assert FAKE_GITHUB_TOKEN not in redact_url(url)

    def test_masks_a_token_that_gives_itself_away_by_its_shape(self) -> None:
        """No parameter name says it is a secret. The token says so itself."""
        url = f"https://mcp.example.com/sse?t={FAKE_JWT}"

        assert credentials_in_url(url) == ["a JWT"]
        assert redact_url(url) == "https://mcp.example.com/sse?t=***"

    def test_masks_a_token_sitting_in_the_path(self) -> None:
        url = f"https://mcp.example.com/{FAKE_GITHUB_TOKEN}/sse"

        assert credentials_in_url(url) == ["a GitHub token"]
        assert redact_url(url) == "https://mcp.example.com/***/sse"

    def test_reports_one_credential_found_two_ways_only_once(self) -> None:
        """A named parameter that is *also* a token by shape is one secret."""
        url = f"https://mcp.example.com/sse?api_key={FAKE_API_KEY}"

        assert len(credentials_in_url(url)) == 1
        assert redact_url(url).count(REDACTED) == 1

    def test_names_and_masks_every_credential_a_url_carries(self) -> None:
        url = (
            f"https://demo:{FAKE_API_KEY}@mcp.example.com/sse"
            f"?token={FAKE_GITHUB_TOKEN}&region=eu"
        )

        assert credentials_in_url(url) == ["a password", "the value of 'token'"]
        assert redact_url(url) == "https://demo:***@mcp.example.com/sse?token=***&region=eu"

    def test_leaves_a_parameter_read_from_the_environment_alone(self) -> None:
        url = "https://mcp.example.com/sse?api_key=${EXAMPLE_API_KEY}"

        assert credentials_in_url(url) == []
        assert redact_url(url) == url

    def test_leaves_an_ordinary_url_alone(self) -> None:
        url = "https://mcp.example.com/sse?region=eu&version=2#section"

        assert credentials_in_url(url) == []
        assert redact_url(url) == url

    def test_masks_by_position_not_by_search_and_replace(self) -> None:
        """A one-character secret must not blank every `x` in the hostname.

        Masking by searching for the value would rewrite the URL wherever the
        value happened to occur — and the shorter the secret, the more of the
        URL it would take with it.
        """
        url = "https://x.example.com/x?api_key=x&box=x"

        assert redact_url(url) == "https://x.example.com/x?api_key=***&box=x"

    def test_no_secret_survives_redaction(self) -> None:
        url = (
            f"https://demo:{FAKE_API_KEY}@mcp.example.com/{FAKE_GITHUB_TOKEN}/sse"
            f"?token={FAKE_JWT}"
        )

        redacted = redact_url(url)

        for secret in (FAKE_API_KEY, FAKE_GITHUB_TOKEN, FAKE_JWT):
            assert secret not in redacted
            assert secret not in " ".join(credentials_in_url(url))


class TestDetectionAndRedactionAgree:
    """The invariant the module exists for.

    A credential the scanner is able to *name* is one it is able to *mask*, and
    the other way round — they are the same walk of the command line. Were they
    to drift apart, the harmful direction is a credential that no rule flags and
    no renderer hides, so it is worth pinning down.
    """

    @pytest.mark.parametrize(
        "args",
        [
            ("--api-key", FAKE_API_KEY),
            (f"--api-key={FAKE_API_KEY}",),
            (f"GITHUB_TOKEN={FAKE_GITHUB_TOKEN}",),
            ("--header", FAKE_JWT),
            ("--header", f"Authorization: Bearer {FAKE_JWT}"),
            ("-y", "@example/server", "--verbose"),
            ("--api-key=${API_KEY}",),
        ],
    )
    def test_an_argument_is_masked_exactly_when_it_is_flagged(
        self, args: tuple[str, ...]
    ) -> None:
        flagged = [credential is not None for credential in credentials_in(args)]
        masked = [
            redacted != original
            for original, redacted in zip(args, redact_args(args), strict=True)
        ]

        assert flagged == masked

    @pytest.mark.parametrize(
        "url",
        [
            f"https://mcp.example.com/sse?api_key={FAKE_API_KEY}",
            f"https://demo:{FAKE_API_KEY}@mcp.example.com/mcp",
            f"https://mcp.example.com/{FAKE_GITHUB_TOKEN}/sse",
            "https://mcp.example.com/sse?api_key=${API_KEY}",
            "https://mcp.example.com/sse?region=eu",
        ],
    )
    def test_a_url_is_masked_exactly_when_it_is_flagged(self, url: str) -> None:
        assert bool(credentials_in_url(url)) == (redact_url(url) != url)
