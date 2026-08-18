"""
APC scope configurations for InjecAgent evaluation.

Three conditions:
  - complete:   X covers all exfiltration paths (read_sensitive → send_external)
  - incomplete: X deliberately missing the key pair (validates Theorem 5.1)
  - none:       No APC enforcement (baseline)
"""

from __future__ import annotations

import sys
from pathlib import Path

# Add the APC library to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from apc.core import Scope, DelegationBudgetSpec
from apc.compose import (
    ActionClassMapping,
    CompositionChecker,
    KTupleRestriction,
    RestrictionTemplate,
    compile_templates,
)


# All action types used in InjecAgent
ALL_ACTIONS = frozenset([
    "read", "read_sensitive", "read_external",
    "write", "delete", "execute",
    "send_external", "transfer", "physical",
])

# Class mapping: action types map to themselves (no abstraction needed)
CLASS_MAPPING = ActionClassMapping.from_dict({a: a for a in ALL_ACTIONS})


def get_composition_restrictions_complete():
    """Complete X — blocks all exfiltration and harmful compositions."""
    templates = [
        # Core exfiltration: read sensitive → send external
        RestrictionTemplate.deny_compose("read_sensitive", "send_external"),
        RestrictionTemplate.deny_compose("read", "send_external"),
        # Read → harmful actions
        RestrictionTemplate.deny_compose("read_sensitive", "transfer"),
        RestrictionTemplate.deny_compose("read_sensitive", "physical"),
        RestrictionTemplate.deny_compose("read_sensitive", "execute"),
        RestrictionTemplate.deny_compose("read_sensitive", "delete"),
        RestrictionTemplate.deny_compose("read_sensitive", "write"),
        # External read → send
        RestrictionTemplate.deny_compose("read_external", "send_external"),
    ]
    return compile_templates(templates)


def get_composition_restrictions_incomplete():
    """Incomplete X — deliberately missing (read_sensitive, send_external).

    This allows the core data stealing attack to succeed,
    validating the completeness caveat of Theorem 5.1.
    """
    templates = [
        # Missing: (read_sensitive, send_external) — the key pair!
        RestrictionTemplate.deny_compose("read", "send_external"),
        RestrictionTemplate.deny_compose("read_sensitive", "transfer"),
        RestrictionTemplate.deny_compose("read_sensitive", "physical"),
        # Also missing some others to make the gap realistic
    ]
    return compile_templates(templates)


def make_checker(condition: str) -> CompositionChecker | None:
    """Create a CompositionChecker for the given condition."""
    if condition == "none":
        return None

    if condition == "complete":
        restrictions = get_composition_restrictions_complete()
    elif condition == "incomplete":
        restrictions = get_composition_restrictions_incomplete()
    else:
        raise ValueError(f"Unknown condition: {condition}")

    return CompositionChecker(
        restrictions=restrictions,
        class_mapping=CLASS_MAPPING,
    )
