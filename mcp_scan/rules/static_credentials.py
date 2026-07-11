"""Detect credentials written into a config instead of referenced from it.

A config that pins a secret leaks it twice over: the file sits on disk, readable
by anything running as the user, and it is routinely committed to a repository.
Where the secret sits decides how bad that is, so this module ships two rules:

* `static-credential-in-env` (WARN) — a credential in an `env` entry. The blast
  radius is the config file and wherever it gets copied.
* `static-credential-in-args` (CRITICAL) — a credential on the server's command
  line. That one is *also* in the process table, where every other process on
  the machine can read it straight out of `ps`, and in whatever shell history
  or process log recorded the spawn.

The fix for both is the same: keep the value in the environment (or a secret
manager) and let the config reference it — `"GITHUB_TOKEN": "${GITHUB_TOKEN}"`.

Neither rule ever handles a credential value. The env rule cannot: the parser
keeps names only. The args rule has to look at an argument to judge it, and
reports only where the value is and what flag it hides behind — never the value.
"""

import re

from mcp_scan.parsers import MCPServer, is_env_reference
from mcp_scan.rules.base import Finding, Rule, Severity

#: The trailing word that makes a name read as the name of a secret. Only the
#: last word is looked at, which keeps `API_KEY`, `--api-key` and `X-Api-Key`
#: in, and leaves `SSH_KEY_PATH` (a path to a key) and `AUTH_MODE` alone.
SECRET_WORDS = frozenset(
    {
        "APIKEY",
        "AUTH",
        "AUTHORIZATION",
        "CREDENTIAL",
        "CREDENTIALS",
        "KEY",
        "KEYS",
        "PASSWD",
        "PASSWORD",
        "PAT",
        "SECRET",
        "SECRETS",
        "TOKEN",
        "TOKENS",
    }
)

#: What splits an argument into a name and the value it carries: `--api-key=…`,
#: `API_KEY=…`, and the `Authorization: …` of a header passed on the command line.
VALUE_SEPARATORS = ("=", ":")

#: An argument that is a credential outright, whatever it is called or wherever
#: it sits. The label names the credential in the finding, so the value never
#: has to be quoted to say what was found.
CREDENTIAL_SHAPES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{16,}"), "a GitHub token"),
    (re.compile(r"xox[abprs]-[A-Za-z0-9-]{10,}"), "a Slack token"),
    (re.compile(r"sk-[A-Za-z0-9_-]{16,}"), "an API key"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "an AWS access key id"),
    (re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+"), "a JWT"),
)

#: A credential riding inside a longer argument, rather than being the whole of it.
EMBEDDED_CREDENTIALS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bbearer\s+[A-Za-z0-9._~+/-]{12,}", re.IGNORECASE), "a bearer token"),
)


class StaticCredentialInEnv(Rule):
    """Flag an `env` entry whose value is hardcoded in the config file."""

    id = "static-credential-in-env"
    title = "Credential hardcoded in an environment variable"
    severity = Severity.WARN

    def check(self, server: MCPServer) -> list[Finding]:
        return [
            self.finding(
                server,
                f"environment variable '{key}' has its value hardcoded in the config; "
                f"reference it from the environment instead",
            )
            for key in server.env_static_keys
            if names_a_secret(key)
        ]


class StaticCredentialInArgs(Rule):
    """Flag a credential passed inline on the server's command line."""

    id = "static-credential-in-args"
    title = "Credential hardcoded in a command argument"
    severity = Severity.CRITICAL

    def check(self, server: MCPServer) -> list[Finding]:
        findings = []
        # A flag whose value the *next* argument carries: `--api-key sk-…`.
        pending_flag: str | None = None

        for position, arg in enumerate(server.args, start=1):
            credential = _credential_in(arg) or _value_behind(pending_flag, arg)
            if credential is not None:
                findings.append(
                    self.finding(
                        server,
                        f"argument {position} of the command holds {credential}; "
                        f"every process on the machine can read it from `ps`",
                    )
                )
            pending_flag = arg if _is_secret_flag(arg) else None

        return findings


def names_a_secret(name: str) -> bool:
    """True when a name reads as the name of a credential.

    Judged on the last word alone: `API_KEY` and `--api-key` name a secret,
    while `SSH_KEY_PATH` and `TOKEN_FILE` name where one is kept.
    """
    words = [word for word in re.split(r"[^A-Za-z0-9]+", name.upper()) if word]
    return bool(words) and words[-1] in SECRET_WORDS


def _credential_in(arg: str) -> str | None:
    """Name the credential an argument carries, or None if it carries none.

    What comes back goes straight into a finding, so it names the credential by
    the flag it hides behind or the kind of token it is — never by its value.
    """
    for separator in VALUE_SEPARATORS:
        name, found, value = arg.partition(separator)
        if found and names_a_secret(name) and _holds_a_secret(value):
            return f"the value of '{name.strip()}'"

    for pattern, label in EMBEDDED_CREDENTIALS:
        if pattern.search(arg):
            return label

    for pattern, label in CREDENTIAL_SHAPES:
        if pattern.fullmatch(arg.strip()):
            return label

    return None


def _value_behind(pending_flag: str | None, arg: str) -> str | None:
    """Name the credential `arg` carries for the flag before it, if it does.

    `--api-key sk-…` splits a secret across two arguments, and the second one on
    its own says nothing. A flag followed by another flag (`--api-key --debug`)
    is one whose value came from somewhere else, and carries nothing.
    """
    if pending_flag is None or arg.startswith("-") or not _holds_a_secret(arg):
        return None
    return f"the value of '{pending_flag}'"


def _is_secret_flag(arg: str) -> bool:
    """True when an argument is a bare flag still waiting for its value.

    `--api-key=sk-…` already carries its own; it is not waiting for anything.
    """
    return (
        arg.startswith("-")
        and not any(separator in arg for separator in VALUE_SEPARATORS)
        and names_a_secret(arg)
    )


def _holds_a_secret(value: str) -> bool:
    """True when a value is a credential rather than a placeholder for one."""
    text = value.strip()
    return bool(text) and not is_env_reference(text)
