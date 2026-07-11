"""Tests for the shared credential vocabulary and the redaction it backs."""

import pytest

from mcp_scan.credentials import REDACTED, credentials_in, names_a_secret, redact_args

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
