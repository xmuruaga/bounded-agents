"""
apc_parameters — Parameter-level validation for tool invocations.

Addresses the gap where APC knows *which* tool is called but not
*what data flows through its parameters*. An agent can exfiltrate
data by encoding it in parameters of legitimate tools (e.g. putting
confidential data in a calendar event title).

Parameter validators are registered per-tool and checked by the PDP
as an additional condition. Validators are declarative rules, not
model-evaluated — they run in infrastructure.

Usage:
    from apc.parameters import ParameterPolicy, ParameterValidator

    policy = ParameterPolicy()
    policy.add_rule("send_email", "to", AllowlistRule({"*@company.com"}))
    policy.add_rule("send_email", "body", MaxLengthRule(10000))
    policy.add_rule("create_calendar_event", "title", DenyPatternRule(
        patterns=["SSN", r"\\d{3}-\\d{2}-\\d{4}"],
        reason="potential PII in calendar title",
    ))

    validator = ParameterValidator(policy)
    result = validator.validate("send_email", {"to": "attacker@evil.com", "body": "data"})
    # result.valid == False, result.violations == ["to: value not in allowlist"]
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Protocol


# ---------------------------------------------------------------------------
# Validation Rule Protocol
# ---------------------------------------------------------------------------

class ValidationRule(Protocol):
    """Protocol for parameter validation rules."""

    def validate(self, value: Any) -> RuleResult:
        """Validate a parameter value. Returns pass/fail with reason."""
        ...


@dataclass(frozen=True)
class RuleResult:
    """Result of a single rule evaluation."""
    valid: bool
    reason: str = ""


# ---------------------------------------------------------------------------
# Built-in Rules
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AllowlistRule:
    """Parameter value must match one of the allowed patterns.

    Supports glob-style matching: "*@company.com" matches "alice@company.com".
    """

    allowed_patterns: frozenset[str]

    def validate(self, value: Any) -> RuleResult:
        str_value = str(value)
        for pattern in self.allowed_patterns:
            regex = re.escape(pattern).replace(r"\*", ".*")
            if re.fullmatch(regex, str_value):
                return RuleResult(valid=True)
        return RuleResult(
            valid=False,
            reason=f"value '{str_value}' not in allowlist",
        )


@dataclass(frozen=True)
class DenylistRule:
    """Parameter value must NOT match any denied pattern."""

    denied_patterns: frozenset[str]
    reason: str = "value matches denylist"

    def validate(self, value: Any) -> RuleResult:
        str_value = str(value)
        for pattern in self.denied_patterns:
            regex = re.escape(pattern).replace(r"\*", ".*")
            if re.fullmatch(regex, str_value):
                return RuleResult(valid=False, reason=self.reason)
        return RuleResult(valid=True)


@dataclass(frozen=True)
class DenyPatternRule:
    """Parameter value must not contain any of the specified regex patterns.

    Useful for detecting PII, secrets, or encoded data in parameters.
    """

    patterns: tuple[str, ...]
    reason: str = "value contains prohibited pattern"

    def validate(self, value: Any) -> RuleResult:
        str_value = str(value)
        for pattern in self.patterns:
            if re.search(pattern, str_value, re.IGNORECASE):
                return RuleResult(valid=False, reason=self.reason)
        return RuleResult(valid=True)


@dataclass(frozen=True)
class MaxLengthRule:
    """Parameter string value must not exceed max_length characters.

    Prevents data exfiltration via oversized parameters.
    """

    max_length: int

    def validate(self, value: Any) -> RuleResult:
        str_value = str(value)
        if len(str_value) > self.max_length:
            return RuleResult(
                valid=False,
                reason=f"length {len(str_value)} exceeds max {self.max_length}",
            )
        return RuleResult(valid=True)


@dataclass(frozen=True)
class TypeRule:
    """Parameter value must be of the expected type."""

    expected_type: type
    type_name: str = ""

    def validate(self, value: Any) -> RuleResult:
        if not isinstance(value, self.expected_type):
            name = self.type_name or self.expected_type.__name__
            return RuleResult(
                valid=False,
                reason=f"expected type {name}, got {type(value).__name__}",
            )
        return RuleResult(valid=True)


@dataclass(frozen=True)
class RangeRule:
    """Numeric parameter must be within [min_value, max_value]."""

    min_value: float = float("-inf")
    max_value: float = float("inf")

    def validate(self, value: Any) -> RuleResult:
        try:
            num = float(value)
        except (TypeError, ValueError):
            return RuleResult(valid=False, reason=f"not a number: {value!r}")
        if num < self.min_value or num > self.max_value:
            return RuleResult(
                valid=False,
                reason=f"value {num} outside range [{self.min_value}, {self.max_value}]",
            )
        return RuleResult(valid=True)


# ---------------------------------------------------------------------------
# Parameter Policy
# ---------------------------------------------------------------------------

class ParameterPolicy:
    """Declarative parameter validation policy.

    Maps (tool_name, parameter_name) → list of validation rules.
    Rules are conjunctive: all must pass for the parameter to be valid.
    """

    def __init__(self) -> None:
        self._rules: dict[str, dict[str, list[ValidationRule]]] = {}

    def add_rule(
        self, tool_name: str, param_name: str, rule: ValidationRule,
    ) -> None:
        """Register a validation rule for a tool parameter."""
        if tool_name not in self._rules:
            self._rules[tool_name] = {}
        if param_name not in self._rules[tool_name]:
            self._rules[tool_name][param_name] = []
        self._rules[tool_name][param_name].append(rule)

    def get_rules(
        self, tool_name: str, param_name: str,
    ) -> list[ValidationRule]:
        """Get all rules for a specific tool parameter."""
        return self._rules.get(tool_name, {}).get(param_name, [])

    def has_rules(self, tool_name: str) -> bool:
        """Check if any rules are registered for a tool."""
        return tool_name in self._rules and len(self._rules[tool_name]) > 0

    @property
    def tool_names(self) -> frozenset[str]:
        return frozenset(self._rules.keys())


# ---------------------------------------------------------------------------
# Parameter Validator
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ParameterValidationResult:
    """Result of parameter validation for a tool invocation."""

    valid: bool
    violations: tuple[str, ...] = ()


class ParameterValidator:
    """Validates tool parameters against a ParameterPolicy.

    Integrated into the PDP as an optional additional check.
    When a ParameterPolicy is configured, the PDP calls validate()
    before admitting the action.
    """

    def __init__(self, policy: ParameterPolicy) -> None:
        self._policy = policy

    def validate(
        self, tool_name: str, parameters: dict[str, Any],
    ) -> ParameterValidationResult:
        """Validate all parameters of a tool invocation.

        Only parameters with registered rules are checked.
        Parameters without rules pass by default (open-world assumption).
        """
        if not self._policy.has_rules(tool_name):
            return ParameterValidationResult(valid=True)

        violations: list[str] = []
        for param_name, value in parameters.items():
            rules = self._policy.get_rules(tool_name, param_name)
            for rule in rules:
                result = rule.validate(value)
                if not result.valid:
                    violations.append(f"{param_name}: {result.reason}")

        return ParameterValidationResult(
            valid=len(violations) == 0,
            violations=tuple(violations),
        )
