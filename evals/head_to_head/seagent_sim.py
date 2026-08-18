"""
SEAgent simulation — ABAC-based MAC with information flow tracking.

Simulates the core enforcement mechanism of SEAgent (Ji et al., 2026):
  - Attribute-Based Access Control (ABAC) policies on tool attributes
  - Information flow graph tracking data provenance across tool calls
  - Mandatory Access Control (MAC) rules preventing sensitive data flows
    to external/harmful sinks

SEAgent classifies each tool call by attributes (action type, sensitivity,
data category) and maintains an information flow graph. When a tool call
would create a prohibited information flow (e.g., sensitive data → external
channel), the call is denied.

Key insight: SEAgent's information flow tracking is functionally equivalent
to APC's composition closure for the attack patterns in InjecAgent/ASB,
because both track "what happened before" and deny based on the sequence.
The difference is in the abstraction level:
  - SEAgent: attribute-level policies on individual tool calls + flow graph
  - APC: action-class-level composition restrictions with formal guarantees

For this static evaluation, we implement SEAgent's ABAC rules as described
in the paper: deny tool calls where the information flow graph shows
sensitive data reaching an external/harmful sink.
"""

from __future__ import annotations
from dataclasses import dataclass, field


# ── ABAC Policy Rules ──────────────────────────────────────────────────

# SEAgent's MAC rules: (source_sensitivity, target_action) → deny
# These encode the information flow restrictions from the SEAgent paper.
# If sensitive data has been read, subsequent actions that could exfiltrate
# or cause harm are denied.
FLOW_DENY_RULES: list[tuple[str, str]] = [
    # Sensitive data → external channel (data exfiltration)
    ("confidential", "send_external"),
    ("confidential", "transfer"),
    ("confidential", "physical"),
    # Sensitive data → harmful execution
    ("confidential", "execute_harmful"),
    ("confidential", "delete"),
    ("confidential", "write"),
    # Internal data → external channel
    ("internal", "send_external"),
    ("internal", "transfer"),
    ("internal", "execute_harmful"),
    ("internal", "delete"),
    ("internal", "write"),
]

# SEAgent also uses action-type-based rules: certain action types are
# inherently harmful and denied when any sensitive data is in the session.
# This models SEAgent's "mandatory access control" layer where the
# information flow graph prevents tainted data from reaching sinks.
HARMFUL_ACTION_TYPES = frozenset([
    "send_external", "transfer", "physical",
    "execute_harmful", "delete",
])

# SEAgent additionally tracks whether the session involves sensitive
# *action types* (not just data sensitivity). If the agent has performed
# a read_sensitive action, subsequent harmful actions are denied even
# if the tool profile doesn't explicitly mark sensitivity.
SENSITIVE_ACTION_TYPES = frozenset([
    "read_sensitive", "read_external",
])


@dataclass
class FlowNode:
    """A node in the information flow graph."""
    tool_name: str
    action_type: str
    sensitivity: str
    data_category: str


class SEAgentChecker:
    """Simulates SEAgent's ABAC + information flow enforcement.

    Tracks the information flow graph across tool calls in a session.
    When a new tool call is proposed, checks:
      1. Tool authorization: is this tool type permitted?
      2. Information flow: would this create a prohibited flow?

    The flow check is the key mechanism: if any previous tool call
    read sensitive data, and the proposed tool would send data externally
    or cause harm, the call is denied.
    """

    def __init__(self):
        self._flow_graph: list[FlowNode] = []
        self._max_sensitivity: str = "public"  # highest sensitivity seen
        self._has_sensitive_action: bool = False  # any read_sensitive in session
        self._sensitivity_order = {"public": 0, "internal": 1, "confidential": 2}

    def record_tool_call(self, tool_name: str, action_type: str,
                         profile: dict) -> None:
        """Record a tool call in the information flow graph."""
        sensitivity = profile.get("sensitivity", "public")
        data_category = profile.get("data", "general")

        node = FlowNode(
            tool_name=tool_name,
            action_type=action_type,
            sensitivity=sensitivity,
            data_category=data_category,
        )
        self._flow_graph.append(node)

        # Update max sensitivity
        if self._sensitivity_order.get(sensitivity, 0) > \
           self._sensitivity_order.get(self._max_sensitivity, 0):
            self._max_sensitivity = sensitivity

        # Track sensitive action types
        if action_type in SENSITIVE_ACTION_TYPES:
            self._has_sensitive_action = True

    def check_tool_call(self, tool_name: str, action_type: str,
                        profile: dict) -> dict:
        """Check if a tool call is permitted under SEAgent's ABAC rules.

        Returns dict with:
          - allowed: bool
          - reason: str explaining the decision
        """
        sensitivity = profile.get("sensitivity", "public")

        # Rule 1: Information flow check (data sensitivity)
        # If sensitive data has been accessed, deny flows to harmful sinks
        for source_sens, target_action in FLOW_DENY_RULES:
            if (self._sensitivity_order.get(self._max_sensitivity, 0) >=
                self._sensitivity_order.get(source_sens, 0) and
                action_type == target_action):
                return {
                    "allowed": False,
                    "reason": (f"ABAC flow deny: {self._max_sensitivity} data "
                               f"in session → {action_type} blocked "
                               f"(rule: {source_sens} → {target_action})"),
                }

        # Rule 2: Action-type flow check
        # If a sensitive action (read_sensitive) was performed, deny
        # harmful actions regardless of the tool's own sensitivity label.
        # This models SEAgent's information flow graph: data read by
        # read_sensitive is tainted, and tainted data cannot flow to sinks.
        if (self._has_sensitive_action and
            action_type in HARMFUL_ACTION_TYPES):
            return {
                "allowed": False,
                "reason": (f"ABAC action flow deny: session contains "
                           f"read_sensitive action → {action_type} blocked"),
            }

        # Rule 3: Cross-domain check
        # If the tool is marked as cross-domain and sensitive data exists
        if (profile.get("cross_domain", False) and
            self._max_sensitivity in ("confidential", "internal")):
            return {
                "allowed": False,
                "reason": (f"ABAC cross-domain deny: {tool_name} is cross-domain "
                           f"and session contains {self._max_sensitivity} data"),
            }

        # Rule 4: Irreversibility check with sensitive context
        # If the tool has irreversible effects and sensitive data is in context
        if (profile.get("irreversible", False) and
            self._max_sensitivity == "confidential"):
            return {
                "allowed": False,
                "reason": (f"ABAC irreversibility deny: {tool_name} is irreversible "
                           f"and session contains confidential data"),
            }

        return {"allowed": True, "reason": "permitted"}
