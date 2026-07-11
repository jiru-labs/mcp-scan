"""Detect credentials written into a config instead of referenced from it.

A config that pins a secret leaks it twice over: the file sits on disk, readable
by anything running as the user, and it is routinely committed to a repository.
Where the secret sits decides how bad that is, so this module ships three rules:

* `static-credential-in-env` (WARN) — a credential in an `env` entry. The blast
  radius is the config file and wherever it gets copied.
* `static-credential-in-args` (CRITICAL) — a credential on the server's command
  line. That one is *also* in the process table, where every other process on
  the machine can read it straight out of `ps`, and in whatever shell history
  or process log recorded the spawn.
* `static-credential-in-url` (CRITICAL) — a credential in a remote server's URL,
  as a query parameter or in the `user:password@` before the host. That one
  *travels*: it goes out in the request line, lands in the access log at the far
  end and in every proxy in between, and gets pasted wherever the URL gets
  pasted.

The fix for all three is the same: keep the value in the environment (or a
secret manager) and let the config reference it — `"${GITHUB_TOKEN}"`.

No rule here ever handles a credential value. The env rule cannot: the parser
keeps names only. The other two have to look at an argument or a URL to judge
it, and `mcp_scan.credentials` gives them back a label — where the value is, and
what flag or parameter it hides behind — never the value itself.
"""

from mcp_scan.credentials import credentials_in, credentials_in_url, names_a_secret
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


class StaticCredentialInUrl(Rule):
    """Flag a credential written into the URL of a remote server."""

    id = "static-credential-in-url"
    title = "Credential hardcoded in a server URL"
    severity = Severity.CRITICAL

    def check(self, server: MCPServer) -> list[Finding]:
        if not server.url:
            return []

        return [
            self.finding(
                server,
                f"the server's URL carries {label}; a URL travels — it goes out "
                f"in the request line, into the access log at the other end, and "
                f"into every place the URL is pasted",
            )
            for label in credentials_in_url(server.url)
        ]
