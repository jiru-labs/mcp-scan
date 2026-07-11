"""The rule engine: discover the rules, run them, collect the findings.

Rules are discovered, not registered. Every module in this package is imported
and searched for `Rule` subclasses, so a new detection is a new file here and
nothing else — the engine, the CLI and this module stay untouched.

Running rules is defensive: a rule that raises is reported as a warning and the
scan carries on with the rest.
"""

import importlib
import inspect
import pkgutil
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from types import ModuleType

from mcp_scan.parsers import MCPServer
from mcp_scan.rules.base import Finding, Rule, Severity

__all__ = [
    "Finding",
    "Rule",
    "ScanResult",
    "Severity",
    "load_rules",
    "run_rules",
]


@dataclass
class ScanResult:
    """What a scan produced: findings, plus any rule that misbehaved.

    Findings are sorted worst-first. Warnings never replace findings — a broken
    rule does not invalidate the ones that ran.
    """

    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def load_rules(package: ModuleType | None = None) -> list[Rule]:
    """Instantiate every rule defined in a rules package.

    Args:
        package: The package to search. Defaults to this one; tests pass their
            own to check that dropping a file in is all it takes.
    """
    package = package if package is not None else importlib.import_module(__name__)
    rules = [rule_class() for module in _modules_in(package) for rule_class in _rules_in(module)]
    return sorted(rules, key=lambda rule: rule.id)


def run_rules(
    servers: Sequence[MCPServer], rules: Sequence[Rule] | None = None
) -> ScanResult:
    """Check every server against every rule.

    Args:
        servers: The servers to scan.
        rules: The rules to run. Defaults to every rule in this package.
    """
    rules = load_rules() if rules is None else rules

    result = ScanResult()
    for server in servers:
        for rule in rules:
            try:
                result.findings.extend(rule.check(server))
            except Exception as exc:  # noqa: BLE001 — one bad rule must not end the scan
                result.warnings.append(
                    f"rule '{rule.id}' failed on server '{server.name}': {exc}"
                )

    result.findings.sort(key=_worst_first)
    return result


def _modules_in(package: ModuleType) -> Iterator[ModuleType]:
    """Import and yield every module in `package`."""
    for module in pkgutil.iter_modules(package.__path__):
        yield importlib.import_module(f"{package.__name__}.{module.name}")


def _rules_in(module: ModuleType) -> Iterator[type[Rule]]:
    """Yield the rule classes a module defines.

    Only classes *defined* in the module count: a module importing `Rule`, or a
    rule from a sibling module, must not register it a second time. `Rule`
    itself is abstract, and so is skipped along with any other partial base.
    """
    for _, member in inspect.getmembers(module, inspect.isclass):
        if (
            issubclass(member, Rule)
            and member.__module__ == module.__name__
            and not inspect.isabstract(member)
        ):
            yield member


def _worst_first(finding: Finding) -> tuple[int, str, str]:
    """Sort key: severity descending, then a stable order within a severity."""
    return (-finding.severity, finding.server.name, finding.rule_id)
