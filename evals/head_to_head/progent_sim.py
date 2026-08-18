"""
Progent simulation — Programmable privilege control with tool-level policies.

Simulates the core enforcement mechanism of Progent (Shi et al., 2025):
  - Domain-specific language (DSL) for expressing privilege control policies
  - Tool-level allow/deny rules applied at runtime
  - Argument-level constraints on tool call parameters

Progent's key mechanism is a tool allowlist: only tools explicitly permitted
by the policy are allowed. Any tool call not on the allowlist is denied.
This is the "principle of least privilege" enforcement.

For this static evaluation, we implement Progent's core policy:
  - ALLOW: tools in the task's authorized tool set (user tools)
  - DENY: all other tools (attacker tools are never in the allowlist)

This is the strongest possible static policy: if you know which tools
the agent should use, deny everything else. The question is whether
this achieves the same coverage as APC's composition closure.

Key insight: Progent's allowlist achieves 0% ASR on benchmarks where
attacker tools are distinct from user tools (which is always the case
in InjecAgent and ASB). The limitation is that it requires knowing
the complete tool set at policy-authoring time and cannot handle
cases where a legitimate tool is used maliciously (parameter-level attacks).
"""

from __future__ import annotations
from dataclasses import dataclass


class ProgentChecker:
    """Simulates Progent's tool-level privilege control.

    Enforces a simple but effective policy:
      - Tools on the allowlist are permitted
      - All other tools are denied

    This models Progent's DSL policy:
        ALLOW tool IN {user_tool_1, user_tool_2, ...}
        DENY *

    In practice, Progent also supports argument-level constraints
    (e.g., "allow GmailSendEmail only if recipient is in contacts"),
    but for this benchmark comparison we use the tool-level policy
    since InjecAgent/ASB don't provide argument-level data.
    """

    def __init__(self, allowed_tools: set[str]):
        self._allowed_tools = frozenset(allowed_tools)

    def check_tool_call(self, tool_name: str,
                        arguments: dict | None = None) -> dict:
        """Check if a tool call is permitted under Progent's policy.

        Returns dict with:
          - allowed: bool
          - reason: str explaining the decision
        """
        if tool_name in self._allowed_tools:
            return {
                "allowed": True,
                "reason": f"tool {tool_name} is in allowlist",
            }

        return {
            "allowed": False,
            "reason": f"tool {tool_name} not in allowlist (DENY *)",
        }


class ProgentCheckerWithArguments(ProgentChecker):
    """Extended Progent simulation with argument-level constraints.

    Models Progent's full DSL capability:
        ALLOW GmailSendEmail WHERE recipient IN known_contacts
        ALLOW BankManagerTransferFunds WHERE amount < 1000
        DENY *

    Not used in the main comparison (InjecAgent/ASB don't provide
    argument data), but available for future evaluations.
    """

    def __init__(self, allowed_tools: set[str],
                 argument_constraints: dict[str, callable] | None = None):
        super().__init__(allowed_tools)
        self._argument_constraints = argument_constraints or {}

    def check_tool_call(self, tool_name: str,
                        arguments: dict | None = None) -> dict:
        """Check tool call with optional argument constraints."""
        # First check tool-level allowlist
        base_result = super().check_tool_call(tool_name, arguments)
        if not base_result["allowed"]:
            return base_result

        # Then check argument constraints if any
        if tool_name in self._argument_constraints and arguments:
            constraint_fn = self._argument_constraints[tool_name]
            if not constraint_fn(arguments):
                return {
                    "allowed": False,
                    "reason": (f"tool {tool_name} allowed but arguments "
                               f"violate constraint"),
                }

        return base_result
