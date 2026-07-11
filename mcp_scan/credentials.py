"""What a credential looks like, and how to say so without repeating it.

A config can carry a secret in two places: an `env` entry, whose value the
parser drops on the way in, and a command argument, which it cannot — the
argument *is* the command line, and a report that hides it leaves the user
unable to act on what they are told. So an argument reaches both the rules and
the terminal, and this module is what stands between the two.

It answers one question — *does this argument carry a credential, and what is
it called?* — and hands back an answer that never contains the value:

* a `label` naming the credential by the flag it hides behind or the kind of
  token it is, which is what a finding reports;
* a `redacted` rendering of the argument with the value masked, which is what
  the terminal and the exported report print.

Both come from a single walk of the command line, and that is the point. Were
detection and redaction to judge an argument separately, they could disagree,
and the way they would disagree is the dangerous way round: a credential the
scanner is too blunt to flag is one it would also print. Sharing the judgment
means anything found is also masked.

Nothing here reads a value out loud. The closest it comes is deciding whether
one is a real secret or a `${TOKEN}` pointing at the environment, which is the
difference between a finding and a clean bill of health.
"""

import re
from collections.abc import Sequence
from dataclasses import dataclass

#: What replaces a credential wherever one is printed. The name it hangs off is
#: kept — `--api-key=***` tells the user which argument to go and fix, which a
#: blanked-out line would not.
REDACTED = "***"

#: A value that is nothing but a pointer at the real environment: `$TOKEN`,
#: `${TOKEN}`, or the `${env:TOKEN}` form Cursor and VS Code use.
ENV_REFERENCE = re.compile(r"\$\{[^{}]+\}|\$[A-Za-z_][A-Za-z0-9_]*")

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


@dataclass(frozen=True)
class Credential:
    """A credential found in a command argument — named, and never quoted.

    `label` says what was found (`the value of '--api-key'`, `a GitHub token`)
    and goes into a finding. `redacted` is the argument as it may be printed,
    with the value masked and everything around it left intact.
    """

    label: str
    redacted: str


def credentials_in(args: Sequence[str]) -> list[Credential | None]:
    """Walk a command line, naming the credential each argument carries.

    One entry per argument, `None` where the argument carries nothing, so a
    caller can pair the answers back up with the arguments they came from — the
    rules to number them, the renderer to swap them in.
    """
    found: list[Credential | None] = []

    # A flag whose value the *next* argument carries: `--api-key sk-…`.
    pending_flag: str | None = None

    for arg in args:
        found.append(_credential_in(arg) or _value_behind(pending_flag, arg))
        pending_flag = arg if _is_secret_flag(arg) else None

    return found


def redact_args(args: Sequence[str]) -> tuple[str, ...]:
    """A command line safe to print: every credential in it masked, in place.

    The command line is what the user came to see, so all that goes is the
    secret itself — `--api-key=ghp_…` prints as `--api-key=***`, and the
    arguments around it are untouched.
    """
    return tuple(
        credential.redacted if credential is not None else arg
        for arg, credential in zip(args, credentials_in(args))
    )


def names_a_secret(name: str) -> bool:
    """True when a name reads as the name of a credential.

    Judged on the last word alone: `API_KEY` and `--api-key` name a secret,
    while `SSH_KEY_PATH` and `TOKEN_FILE` name where one is kept.
    """
    words = [word for word in re.split(r"[^A-Za-z0-9]+", name.upper()) if word]
    return bool(words) and words[-1] in SECRET_WORDS


def is_env_reference(value: str) -> bool:
    """True when a value only points at an environment variable, and holds none.

    A config that says `"GITHUB_TOKEN": "${GITHUB_TOKEN}"` pins no secret to
    disk: the host expands the reference from the environment it was launched
    with. The credential rules treat such a value as the fix, not the problem,
    and the renderer has nothing to hide in one.
    """
    return ENV_REFERENCE.fullmatch(value.strip()) is not None


def _credential_in(arg: str) -> Credential | None:
    """Name the credential an argument carries, or None if it carries none."""
    for separator in VALUE_SEPARATORS:
        name, found, value = arg.partition(separator)
        if found and names_a_secret(name) and _holds_a_secret(value):
            return Credential(
                label=f"the value of '{name.strip()}'",
                redacted=f"{name}{separator}{REDACTED}",
            )

    for pattern, label in EMBEDDED_CREDENTIALS:
        if pattern.search(arg):
            # Only the token goes: whatever the argument wrapped it in is the
            # user's own text, and says which argument this is.
            return Credential(label=label, redacted=pattern.sub(REDACTED, arg))

    for pattern, label in CREDENTIAL_SHAPES:
        if pattern.fullmatch(arg.strip()):
            return Credential(label=label, redacted=REDACTED)

    return None


def _value_behind(pending_flag: str | None, arg: str) -> Credential | None:
    """Name the credential `arg` carries for the flag before it, if it does.

    `--api-key sk-…` splits a secret across two arguments, and the second one on
    its own says nothing. A flag followed by another flag (`--api-key --debug`)
    is one whose value came from somewhere else, and carries nothing.

    The whole argument is the value, so the whole argument goes; the flag before
    it stays, and is what names the credential in both the finding and the
    printed command line.
    """
    if pending_flag is None or arg.startswith("-") or not _holds_a_secret(arg):
        return None
    return Credential(label=f"the value of '{pending_flag}'", redacted=REDACTED)


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
