"""The interface every detection rule implements.

A rule inspects one server at a time and returns a finding for each problem it
sees. Rules are pure: they read the parsed `MCPServer` model, never the config
file, never the network, and never the values behind `env_keys`.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import IntEnum
from typing import ClassVar

from mcp_audit.parsers import MCPServer


class Severity(IntEnum):
    """How much a finding should worry the user.

    Ordered from least to most serious, so findings sort worst-first on the
    value itself.
    """

    INFO = 1
    WARN = 2
    CRITICAL = 3

    def __str__(self) -> str:
        return self.name


@dataclass(frozen=True)
class Finding:
    """One rule's verdict on one server.

    Carries the server it fired on, so the report can name the server, its host
    and the config file it was declared in without a second lookup.

    `message` is what is wrong with *this* server — which variable, which
    argument, which path. `remediation` is how to fix that class of problem, and
    is the same for every finding a given rule makes; a report groups by it to
    tell the user what to actually go and do.
    """

    rule_id: str
    title: str
    severity: Severity
    server: MCPServer
    message: str
    remediation: str = ""


class Rule(ABC):
    """Base class for detection rules.

    A rule is a file in this package that subclasses `Rule`, fills in `id`,
    `title` and `severity`, and implements `check`. Nothing else registers it:
    the engine discovers every rule in the package on its own.
    """

    #: Stable, human-readable identifier, e.g. `static-credentials`.
    id: ClassVar[str] = ""
    #: What the rule looks for, phrased as the problem it reports.
    title: ClassVar[str] = ""
    #: Severity of the findings this rule produces.
    severity: ClassVar[Severity] = Severity.INFO
    #: How to fix what this rule finds, addressed to the user and phrased as an
    #: instruction. Every shipped rule defines one — a finding the user cannot
    #: act on is a finding that wastes their afternoon — and `test_rules` holds
    #: the package to that. It defaults to empty only so that a throwaway rule
    #: in a test need not write a paragraph of advice about nothing.
    remediation: ClassVar[str] = ""

    def __init_subclass__(cls, **kwargs: object) -> None:
        """Reject a rule that would report itself as a blank row."""
        super().__init_subclass__(**kwargs)
        if not cls.id or not cls.title:
            raise ValueError(f"rule {cls.__name__} must define an id and a title")

    @abstractmethod
    def check(self, server: MCPServer) -> list[Finding]:
        """Report every problem this rule finds in `server`.

        Returns an empty list when the server is clean, which is the common
        case. A rule may return several findings for one server.
        """

    def finding(self, server: MCPServer, message: str | None = None) -> Finding:
        """Build a finding for `server`, stamped with this rule's identity.

        Args:
            server: The server the rule fired on.
            message: What is wrong with *this* server, in the user's terms.
                Defaults to the rule's title, for a rule whose title already
                says everything there is to say.
        """
        return Finding(
            rule_id=self.id,
            title=self.title,
            severity=self.severity,
            server=server,
            message=message if message is not None else self.title,
            remediation=self.remediation,
        )
