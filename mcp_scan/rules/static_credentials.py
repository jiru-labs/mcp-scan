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
`mcp_scan.credentials` gives it back a label — where the value is and what flag
it hides behind — never the value.
"""

from mcp_scan.credentials import credentials_in, names_a_secret
from mcp_scan.parsers import MCPServer
from mcp_scan.rules.base import Finding, Rule, Severity


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
        return [
            self.finding(
                server,
                f"argument {position} of the command holds {credential.label}; "
                f"every process on the machine can read it from `ps`",
            )
            for position, credential in enumerate(
                credentials_in(server.args), start=1
            )
            if credential is not None
        ]
