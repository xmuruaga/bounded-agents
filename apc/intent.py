"""
apc_intent — Intent binding (Condition 6).

Closes the gap between authorization (what an agent *may* do)
and intent (what an agent *should* do for the declared task).

Intent specification Ψ is attached to the Authorization Envelope
at session initialization. Conformance is evaluated by infrastructure,
not by the model.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from apc.core import glob_match as _glob_match


class IntentEnforcementMode(Enum):
    """Graduated enforcement modes, declared in the envelope."""

    STRICT = "strict"   # non-conformance → deny
    WARN = "warn"       # non-conformance → admit + elevated logging
    AUDIT = "audit"     # non-conformance → admit + deviation flag


@dataclass(frozen=True)
class IntentSpec:
    """Structured intent declaration Ψ.

    Attached to the Authorization Envelope at session initialization.
    Not modifiable by the agent.

    Intent can be specified at two granularity levels:
    - Coarse: permitted_resource_patterns + permitted_action_sequences
      (checked independently — any permitted action on any permitted resource)
    - Fine: action_resource_map — per-action resource patterns
      (e.g. (("read", ("docs:compensation/*",)), ("send_internal", ("email:team-hr@*",))))

    When action_resource_map is present, it takes precedence over the
    coarse-grained patterns for actions that appear in the map.
    Actions not in the map fall back to coarse-grained checks.
    """

    task_objective: str
    permitted_resource_patterns: tuple[str, ...] = ()
    permitted_action_sequences: tuple[str, ...] = ()
    negative_constraints: tuple[str, ...] = ()
    enforcement_mode: IntentEnforcementMode = IntentEnforcementMode.STRICT
    action_resource_map: tuple[tuple[str, tuple[str, ...]], ...] = ()

    def resource_matches(self, resource: str) -> bool:
        """Check if a resource matches any permitted pattern.

        Empty patterns = no resource constraint (all permitted by intent).
        """
        if not self.permitted_resource_patterns:
            return True
        return any(
            _glob_match(pattern, resource)
            for pattern in self.permitted_resource_patterns
        )

    def action_permitted(self, action_type: str) -> bool:
        """Check if an action type is in the permitted sequence.

        Empty sequences = no action constraint (all permitted by intent).
        """
        if not self.permitted_action_sequences:
            return True
        return action_type in self.permitted_action_sequences

    def resource_excluded(self, resource: str) -> bool:
        """Check if a resource matches any negative constraint."""
        return any(
            _glob_match(pattern, resource)
            for pattern in self.negative_constraints
        )

    def action_resource_permitted(self, action_type: str, resource: str) -> bool | None:
        """Check fine-grained action→resource mapping.

        Returns True/False if the action is in the map, None if not
        (caller should fall back to coarse-grained checks).
        """
        arm = dict(self.action_resource_map)
        if not arm or action_type not in arm:
            return None  # not mapped — fall back
        patterns = arm[action_type]
        return any(_glob_match(p, resource) for p in patterns)


# ---------------------------------------------------------------------------
# Intent Conformance Evaluation
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class IntentCheckResult:
    """Result of intent conformance evaluation."""

    conforms: bool
    enforcement_mode: IntentEnforcementMode
    admitted: bool  # final decision after applying enforcement mode
    deviations: tuple[str, ...] = ()

    @property
    def requires_logging(self) -> bool:
        return not self.conforms and self.enforcement_mode in (
            IntentEnforcementMode.WARN, IntentEnforcementMode.AUDIT,
        )


class IntentChecker:
    """Infrastructure-side intent conformance evaluator.

    Evaluates whether a proposed action is consistent with the
    declared intent specification. The model does not participate
    in this evaluation.
    """

    def __init__(self, intent_spec: IntentSpec | None = None) -> None:
        self._spec = intent_spec

    @property
    def has_intent(self) -> bool:
        return self._spec is not None

    def check(self, action_type: str, target_resource: str) -> IntentCheckResult:
        """Evaluate intent conformance for a proposed action.

        If no intent spec is present, Condition 6 is trivially satisfied
        (Rule 9: "If no intent specification is present, Condition 6
        is trivially satisfied").

        Evaluation order:
        1. Negative constraints (strongest signal — always checked)
        2. Fine-grained action→resource map (if action is mapped)
        3. Coarse-grained resource patterns + action sequences (fallback)
        """
        if self._spec is None:
            return IntentCheckResult(
                conforms=True,
                enforcement_mode=IntentEnforcementMode.STRICT,
                admitted=True,
            )

        deviations: list[str] = []

        # 1. Check negative constraints first (strongest signal)
        if self._spec.resource_excluded(target_resource):
            deviations.append(
                f"resource '{target_resource}' matches negative constraint"
            )

        # 2. Check fine-grained action→resource map
        fine_result = self._spec.action_resource_permitted(action_type, target_resource)
        if fine_result is not None:
            # Action is in the map — use fine-grained check
            if not fine_result:
                deviations.append(
                    f"resource '{target_resource}' not permitted for action '{action_type}' "
                    f"(action-resource map)"
                )
            # Also check action is permitted (map presence implies action is allowed,
            # but we still check permitted_action_sequences if defined)
            if not self._spec.action_permitted(action_type):
                deviations.append(
                    f"action '{action_type}' not in permitted sequences"
                )
        else:
            # 3. Fallback to coarse-grained checks
            if not self._spec.resource_matches(target_resource):
                deviations.append(
                    f"resource '{target_resource}' outside permitted patterns"
                )
            if not self._spec.action_permitted(action_type):
                deviations.append(
                    f"action '{action_type}' not in permitted sequences"
                )

        conforms = len(deviations) == 0
        mode = self._spec.enforcement_mode

        # Apply graduated enforcement
        if conforms:
            admitted = True
        elif mode == IntentEnforcementMode.STRICT:
            admitted = False
        else:
            # WARN and AUDIT: admit with deviation tracking
            admitted = True

        return IntentCheckResult(
            conforms=conforms,
            enforcement_mode=mode,
            admitted=admitted,
            deviations=tuple(deviations),
        )

