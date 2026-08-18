"""Tests for apc_intent — Intent binding (Condition 6)."""

import time

from apc.intent import (
    IntentChecker,
    IntentEnforcementMode,
    IntentSpec,
)
from apc.core import glob_match as _glob_match
from apc.approval import ApprovalStore
from apc.budget import BudgetState
from apc.calibrate import ImpactWeights
from apc.compose import CompositionChecker
from apc.core import (
    AuthorizationEnvelope,
    DelegationBudgetSpec,
    ExecutionRole,
    Principal,
    Scope,
)
from apc.pdp import EvidenceSink, PolicyDecisionPoint, ProposedAction

KEY = b"test-signing-key-for-reference-impl"


class TestGlobMatch:
    def test_exact_match(self):
        assert _glob_match("docs:contracts", "docs:contracts")

    def test_wildcard_suffix(self):
        assert _glob_match("docs:contracts/*", "docs:contracts/2025-Q4")

    def test_wildcard_all(self):
        assert _glob_match("*", "anything:at:all")

    def test_no_match(self):
        assert not _glob_match("docs:contracts/*", "docs:personnel/ceo")

    def test_prefix_wildcard(self):
        assert _glob_match("*/secret", "any/secret")


class TestIntentSpec:
    def test_empty_patterns_permit_all_resources(self):
        spec = IntentSpec(task_objective="test")
        assert spec.resource_matches("anything")

    def test_empty_sequences_permit_all_actions(self):
        spec = IntentSpec(task_objective="test")
        assert spec.action_permitted("anything")

    def test_resource_pattern_match(self):
        spec = IntentSpec(
            task_objective="summarize Q4 contracts",
            permitted_resource_patterns=("docs:contracts/2025-Q4/*",),
        )
        assert spec.resource_matches("docs:contracts/2025-Q4/acme")
        assert not spec.resource_matches("docs:personnel/ceo")

    def test_action_sequence_match(self):
        spec = IntentSpec(
            task_objective="summarize",
            permitted_action_sequences=("read", "summarize"),
        )
        assert spec.action_permitted("read")
        assert spec.action_permitted("summarize")
        assert not spec.action_permitted("delete")

    def test_negative_constraint(self):
        spec = IntentSpec(
            task_objective="review contracts",
            negative_constraints=("docs:personnel/*",),
        )
        assert spec.resource_excluded("docs:personnel/ceo-compensation")
        assert not spec.resource_excluded("docs:contracts/acme")


class TestIntentChecker:
    def test_no_intent_trivially_satisfied(self):
        checker = IntentChecker(intent_spec=None)
        assert not checker.has_intent
        result = checker.check("read", "docs:anything")
        assert result.conforms
        assert result.admitted

    def test_conforming_action(self):
        spec = IntentSpec(
            task_objective="summarize Q4 contracts",
            permitted_resource_patterns=("docs:contracts/*",),
            permitted_action_sequences=("read", "summarize"),
        )
        checker = IntentChecker(intent_spec=spec)
        assert checker.has_intent
        result = checker.check("read", "docs:contracts/acme")
        assert result.conforms
        assert result.admitted
        assert len(result.deviations) == 0

    def test_strict_denies_non_conforming(self):
        spec = IntentSpec(
            task_objective="summarize Q4 contracts",
            permitted_resource_patterns=("docs:contracts/*",),
            enforcement_mode=IntentEnforcementMode.STRICT,
        )
        checker = IntentChecker(intent_spec=spec)
        result = checker.check("read", "docs:personnel/ceo")
        assert not result.conforms
        assert not result.admitted

    def test_warn_admits_non_conforming(self):
        spec = IntentSpec(
            task_objective="summarize Q4 contracts",
            permitted_resource_patterns=("docs:contracts/*",),
            enforcement_mode=IntentEnforcementMode.WARN,
        )
        checker = IntentChecker(intent_spec=spec)
        result = checker.check("read", "docs:personnel/ceo")
        assert not result.conforms
        assert result.admitted  # warn mode admits
        assert result.requires_logging

    def test_audit_admits_non_conforming(self):
        spec = IntentSpec(
            task_objective="summarize Q4 contracts",
            permitted_resource_patterns=("docs:contracts/*",),
            enforcement_mode=IntentEnforcementMode.AUDIT,
        )
        checker = IntentChecker(intent_spec=spec)
        result = checker.check("read", "docs:personnel/ceo")
        assert not result.conforms
        assert result.admitted  # audit mode admits
        assert result.requires_logging

    def test_negative_constraint_overrides(self):
        spec = IntentSpec(
            task_objective="review all docs",
            permitted_resource_patterns=("docs:*",),
            negative_constraints=("docs:personnel/*",),
            enforcement_mode=IntentEnforcementMode.STRICT,
        )
        checker = IntentChecker(intent_spec=spec)
        # Resource matches permitted pattern but also matches negative
        result = checker.check("read", "docs:personnel/ceo")
        assert not result.conforms
        assert not result.admitted

    def test_action_not_in_sequence(self):
        spec = IntentSpec(
            task_objective="read and summarize",
            permitted_action_sequences=("read", "summarize"),
            enforcement_mode=IntentEnforcementMode.STRICT,
        )
        checker = IntentChecker(intent_spec=spec)
        result = checker.check("delete", "docs:anything")
        assert not result.conforms
        assert "delete" in result.deviations[0]

    def test_multiple_deviations(self):
        spec = IntentSpec(
            task_objective="read contracts",
            permitted_resource_patterns=("docs:contracts/*",),
            permitted_action_sequences=("read",),
            negative_constraints=("docs:personnel/*",),
            enforcement_mode=IntentEnforcementMode.STRICT,
        )
        checker = IntentChecker(intent_spec=spec)
        result = checker.check("delete", "docs:personnel/ceo")
        assert not result.conforms
        assert len(result.deviations) == 3  # negative + resource + action

    def test_conforming_requires_no_logging(self):
        spec = IntentSpec(
            task_objective="read contracts",
            permitted_resource_patterns=("docs:contracts/*",),
            enforcement_mode=IntentEnforcementMode.WARN,
        )
        checker = IntentChecker(intent_spec=spec)
        result = checker.check("read", "docs:contracts/acme")
        assert result.conforms
        assert not result.requires_logging


class TestActionResourceMap:
    """Fine-grained action→resource intent mapping."""

    def test_mapped_action_permitted_resource(self):
        spec = IntentSpec(
            task_objective="read compensation, send to HR team",
            action_resource_map=(
                ("read", ("docs:compensation/*",)),
                ("send_internal", ("email:team-hr@company.com",)),
            ),
        )
        checker = IntentChecker(intent_spec=spec)
        result = checker.check("read", "docs:compensation/bands.xlsx")
        assert result.conforms
        assert result.admitted

    def test_mapped_action_wrong_resource_denied(self):
        """read is mapped to docs:compensation/* — reading personnel is denied."""
        spec = IntentSpec(
            task_objective="read compensation, send to HR team",
            action_resource_map=(
                ("read", ("docs:compensation/*",)),
                ("send_internal", ("email:team-hr@company.com",)),
            ),
        )
        checker = IntentChecker(intent_spec=spec)
        result = checker.check("read", "docs:personnel/ceo.pdf")
        assert not result.conforms
        assert not result.admitted
        assert "action-resource map" in result.deviations[0]

    def test_mapped_send_to_wrong_recipient_denied(self):
        """send_internal mapped to team-hr — sending to attacker is denied."""
        spec = IntentSpec(
            task_objective="send summary to HR team",
            action_resource_map=(
                ("send_internal", ("email:team-hr@company.com",)),
            ),
        )
        checker = IntentChecker(intent_spec=spec)
        result = checker.check("send_internal", "email:random@company.com")
        assert not result.conforms
        assert not result.admitted

    def test_unmapped_action_falls_back_to_coarse(self):
        """summarize is not in the map — falls back to coarse patterns."""
        spec = IntentSpec(
            task_objective="read and summarize compensation",
            permitted_resource_patterns=("docs:compensation/*",),
            permitted_action_sequences=("read", "summarize"),
            action_resource_map=(
                ("read", ("docs:compensation/*",)),
            ),
        )
        checker = IntentChecker(intent_spec=spec)
        # summarize not in map → falls back to coarse check
        result = checker.check("summarize", "docs:compensation/bands.xlsx")
        assert result.conforms
        assert result.admitted

    def test_unmapped_action_coarse_denies(self):
        """Unmapped action on wrong resource denied by coarse patterns."""
        spec = IntentSpec(
            task_objective="read compensation",
            permitted_resource_patterns=("docs:compensation/*",),
            action_resource_map=(
                ("read", ("docs:compensation/*",)),
            ),
        )
        checker = IntentChecker(intent_spec=spec)
        result = checker.check("summarize", "docs:personnel/ceo.pdf")
        assert not result.conforms

    def test_negative_constraint_overrides_map(self):
        """Negative constraints take precedence over action-resource map."""
        spec = IntentSpec(
            task_objective="read compensation",
            negative_constraints=("docs:compensation/secret/*",),
            action_resource_map=(
                ("read", ("docs:compensation/*",)),
            ),
        )
        checker = IntentChecker(intent_spec=spec)
        result = checker.check("read", "docs:compensation/secret/plan.pdf")
        assert not result.conforms
        assert any("negative constraint" in d for d in result.deviations)

    def test_empty_map_uses_coarse_only(self):
        """Empty action_resource_map = backward compatible coarse behavior."""
        spec = IntentSpec(
            task_objective="read contracts",
            permitted_resource_patterns=("docs:contracts/*",),
            permitted_action_sequences=("read",),
        )
        checker = IntentChecker(intent_spec=spec)
        result = checker.check("read", "docs:contracts/acme")
        assert result.conforms

    def test_map_with_multiple_patterns(self):
        """Action mapped to multiple resource patterns."""
        spec = IntentSpec(
            task_objective="read compensation and benefits",
            action_resource_map=(
                ("read", ("docs:compensation/*", "docs:benefits/*")),
            ),
        )
        checker = IntentChecker(intent_spec=spec)
        assert checker.check("read", "docs:compensation/x").conforms
        assert checker.check("read", "docs:benefits/y").conforms
        assert not checker.check("read", "docs:personnel/z").conforms

    def test_mapped_action_not_in_permitted_sequences(self):
        """Action is in action_resource_map but not in permitted_action_sequences."""
        spec = IntentSpec(
            task_objective="summarize compensation",
            permitted_action_sequences=("summarize",),
            action_resource_map=(
                ("read", ("docs:compensation/*",)),
            ),
        )
        checker = IntentChecker(intent_spec=spec)
        result = checker.check("read", "docs:compensation/bands.xlsx")
        assert not result.conforms
        assert any("not in permitted sequences" in d for d in result.deviations)


class TestIntentInPDP:
    """Integration: intent binding as Condition 6 in the admissibility predicate."""

    def _setup(self):
        principal = Principal(
            "user:analyst", ExecutionRole.AS_USER,
            Scope(
                frozenset({"docs:contracts/acme", "docs:personnel/ceo"}),
                frozenset({"read", "summarize"}),
                frozenset({"confidential"}),
            ),
        )
        spec = DelegationBudgetSpec(3, 1.0, 5, "confidential", True, 100.0)
        env = AuthorizationEnvelope(
            "env-intent", "session-intent", principal, principal.role_scope,
            spec, expires_at=time.time() + 3600,
        )
        env.sign(KEY)
        return principal, spec, env

    def test_admitted_with_conforming_intent(self):
        principal, spec, env = self._setup()
        intent = IntentSpec(
            task_objective="summarize acme contract",
            permitted_resource_patterns=("docs:contracts/*",),
            permitted_action_sequences=("read", "summarize"),
            enforcement_mode=IntentEnforcementMode.STRICT,
        )
        pdp = PolicyDecisionPoint(
            signing_key=KEY, impact_weights=ImpactWeights(0.4, 0.3, 0.3),
            approval_threshold=0.5, approval_store=ApprovalStore(),
            evidence_sink=EvidenceSink(),
        )
        budget = BudgetState(spec=spec)
        checker = CompositionChecker(restrictions=frozenset())
        intent_checker = IntentChecker(intent_spec=intent)

        action = ProposedAction(
            action_type="read", target_resource="docs:contracts/acme",
            parameters={}, actor_principal_id="user:analyst",
            task_session_id="session-intent", policy_version="1.0",
            sensitivity_class="confidential", blast_radius=0.05,
        )
        decision = pdp.evaluate(
            action, env, budget, checker, intent_checker=intent_checker,
        )
        assert decision.admitted
        assert decision.condition_results["intent_binding"].passed

    def test_denied_with_strict_intent_violation(self):
        principal, spec, env = self._setup()
        intent = IntentSpec(
            task_objective="summarize acme contract",
            permitted_resource_patterns=("docs:contracts/*",),
            enforcement_mode=IntentEnforcementMode.STRICT,
        )
        pdp = PolicyDecisionPoint(
            signing_key=KEY, impact_weights=ImpactWeights(0.4, 0.3, 0.3),
            approval_threshold=0.5, approval_store=ApprovalStore(),
            evidence_sink=EvidenceSink(),
        )
        budget = BudgetState(spec=spec)
        checker = CompositionChecker(restrictions=frozenset())
        intent_checker = IntentChecker(intent_spec=intent)

        # Within scope but outside intent
        action = ProposedAction(
            action_type="read", target_resource="docs:personnel/ceo",
            parameters={}, actor_principal_id="user:analyst",
            task_session_id="session-intent", policy_version="1.0",
            sensitivity_class="confidential", blast_radius=0.05,
        )
        decision = pdp.evaluate(
            action, env, budget, checker, intent_checker=intent_checker,
        )
        assert not decision.admitted
        assert not decision.condition_results["intent_binding"].passed

    def test_admitted_without_intent_checker(self):
        """No intent checker = Condition 6 trivially satisfied."""
        principal, spec, env = self._setup()
        pdp = PolicyDecisionPoint(
            signing_key=KEY, impact_weights=ImpactWeights(0.4, 0.3, 0.3),
            approval_threshold=0.5, approval_store=ApprovalStore(),
            evidence_sink=EvidenceSink(),
        )
        budget = BudgetState(spec=spec)
        checker = CompositionChecker(restrictions=frozenset())

        action = ProposedAction(
            action_type="read", target_resource="docs:contracts/acme",
            parameters={}, actor_principal_id="user:analyst",
            task_session_id="session-intent", policy_version="1.0",
            sensitivity_class="confidential", blast_radius=0.05,
        )
        decision = pdp.evaluate(action, env, budget, checker)
        assert decision.admitted

    def test_warn_mode_admits_with_deviation(self):
        principal, spec, env = self._setup()
        intent = IntentSpec(
            task_objective="summarize acme contract",
            permitted_resource_patterns=("docs:contracts/*",),
            enforcement_mode=IntentEnforcementMode.WARN,
        )
        pdp = PolicyDecisionPoint(
            signing_key=KEY, impact_weights=ImpactWeights(0.4, 0.3, 0.3),
            approval_threshold=0.5, approval_store=ApprovalStore(),
            evidence_sink=EvidenceSink(),
        )
        budget = BudgetState(spec=spec)
        checker = CompositionChecker(restrictions=frozenset())
        intent_checker = IntentChecker(intent_spec=intent)

        action = ProposedAction(
            action_type="read", target_resource="docs:personnel/ceo",
            parameters={}, actor_principal_id="user:analyst",
            task_session_id="session-intent", policy_version="1.0",
            sensitivity_class="confidential", blast_radius=0.05,
        )
        decision = pdp.evaluate(
            action, env, budget, checker, intent_checker=intent_checker,
        )
        assert decision.admitted  # warn mode admits
        assert "deviation" in decision.condition_results["intent_binding"].detail
