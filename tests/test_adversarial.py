"""
Tests for adversarial scenarios from Section 7 of the paper.

7.1 Threshold Gaming (Action Decomposition)
7.2 Envelope Reasoning
7.3 Evidence Forgery under Orchestrator Compromise
7.4 Scope Pollution via Nested Delegation
7.5 Budget Evasion through Session Splitting
"""

import time

from apc.approval import ApprovalStore
from apc.budget import ActionCost, BudgetState
from apc.compose import CompositionChecker
from apc.core import (
    AuthorizationEnvelope,
    DelegationBudgetSpec,
    ExecutionRole,
    Principal,
    Scope,
)
from apc.pdp import EvidenceSink, PolicyDecisionPoint, ProposedAction
from apc.calibrate import ImpactWeights

KEY = b"test-signing-key-for-reference-impl"


def _env(principal, budget_spec):
    env = AuthorizationEnvelope(
        envelope_id="env-adv",
        task_session_id="session-adv",
        originating_principal=principal,
        effective_scope=principal.role_scope,
        budget_spec=budget_spec,
        expires_at=time.time() + 3600,
    )
    env.sign(KEY)
    return env


class TestThresholdGaming:
    """7.1 — Agent decomposes high-impact action into k sub-actions."""

    def test_cumulative_budget_catches_decomposition(self):
        """Many small blast-radius actions exhaust the cumulative budget."""
        spec = DelegationBudgetSpec(
            max_delegation_depth=5,
            max_blast_radius=0.3,
            max_irreversible_effects=2,
            max_sensitivity_class="confidential",
            cross_domain_composition=True,
            max_cost=100.0,
        )
        budget = BudgetState(spec=spec)

        # Agent tries 10 actions each with 0.05 blast radius
        # Total = 0.5 which exceeds 0.3 budget
        admitted = 0
        for i in range(10):
            result = budget.consume(ActionCost(blast_radius=0.05))
            if result.allowed:
                admitted += 1
            else:
                break

        assert admitted == 6  # 6 * 0.05 = 0.30, 7th would be 0.35 > 0.30
        assert budget.is_exhausted

    def test_irreversible_count_catches_decomposition(self):
        spec = DelegationBudgetSpec(
            max_delegation_depth=5,
            max_blast_radius=1.0,
            max_irreversible_effects=3,
            max_sensitivity_class="regulated",
            cross_domain_composition=True,
            max_cost=1000.0,
        )
        budget = BudgetState(spec=spec)

        for _ in range(3):
            result = budget.consume(ActionCost(irreversible_effects=1))
            assert result.allowed

        result = budget.consume(ActionCost(irreversible_effects=1))
        assert not result.allowed


class TestEnvelopeReasoning:
    """7.2 — Model reasons about scope to construct boundary-pushing requests."""

    def test_scope_enforced_regardless_of_reasoning(self):
        """Even if agent 'knows' the scope, enforcement is infrastructure-side."""
        principal = Principal(
            "user:bob", ExecutionRole.AS_USER,
            Scope(frozenset({"docs:public"}), frozenset({"read"}), frozenset({"public"})),
        )
        spec = DelegationBudgetSpec(3, 1.0, 5, "public", True, 100.0)
        env = _env(principal, spec)
        budget = BudgetState(spec=spec)
        checker = CompositionChecker(restrictions=frozenset())
        pdp = PolicyDecisionPoint(
            signing_key=KEY,
            impact_weights=ImpactWeights(0.4, 0.3, 0.3),
            approval_threshold=0.5,
            approval_store=ApprovalStore(),
            evidence_sink=EvidenceSink(),
        )

        # Agent tries to access confidential resource not in scope
        action = ProposedAction(
            action_type="read",
            target_resource="docs:confidential-merger",
            parameters={},
            actor_principal_id="user:bob",
            task_session_id="session-adv",
            policy_version="1.0",
            sensitivity_class="public",
        )
        decision = pdp.evaluate(action, env, budget, checker)
        assert not decision.admitted


class TestEvidenceForgery:
    """7.3 — Compromised orchestrator tries to suppress evidence."""

    def test_action_denied_when_evidence_unavailable(self):
        """If evidence sink is down, action is denied (Rule 7)."""
        principal = Principal(
            "user:bob", ExecutionRole.AS_USER,
            Scope(frozenset({"docs:x"}), frozenset({"read"}), frozenset({"public"})),
        )
        spec = DelegationBudgetSpec(3, 1.0, 5, "confidential", True, 100.0)
        env = _env(principal, spec)
        budget = BudgetState(spec=spec)
        checker = CompositionChecker(restrictions=frozenset())

        sink = EvidenceSink()
        sink.set_available(False)  # simulates compromised/unavailable evidence

        pdp = PolicyDecisionPoint(
            signing_key=KEY,
            impact_weights=ImpactWeights(0.4, 0.3, 0.3),
            approval_threshold=0.5,
            approval_store=ApprovalStore(),
            evidence_sink=sink,
        )

        action = ProposedAction(
            action_type="read", target_resource="docs:x", parameters={},
            actor_principal_id="user:bob", task_session_id="session-adv",
            policy_version="1.0", sensitivity_class="public",
        )
        decision = pdp.evaluate(action, env, budget, checker)
        assert not decision.admitted


class TestScopePollution:
    """7.4 — Mid-chain principal tries to widen scope via forged envelope."""

    def test_narrowing_cannot_widen_scope(self):
        """Child scope is always ⊑ parent scope."""
        parent_principal = Principal(
            "user:alice", ExecutionRole.AS_USER,
            Scope(frozenset({"docs:x"}), frozenset({"read"}), frozenset({"public"})),
        )
        spec = DelegationBudgetSpec(3, 1.0, 5, "confidential", True, 100.0)
        parent_env = _env(parent_principal, spec)

        # Malicious agent claims wider scope
        malicious_agent = Principal(
            "agent:evil", ExecutionRole.ON_BEHALF_OF,
            Scope(
                frozenset({"docs:x", "db:production", "email:external"}),
                frozenset({"read", "write", "delete", "send"}),
                frozenset({"public", "confidential", "regulated"}),
            ),
        )
        child_env = parent_env.narrow(malicious_agent, KEY)

        # Despite claiming wide scope, narrowing constrains to parent
        assert child_env.effective_scope.resources == frozenset({"docs:x"})
        assert child_env.effective_scope.actions == frozenset({"read"})
        assert child_env.effective_scope.data_classifications == frozenset({"public"})

    def test_forged_envelope_fails_signature(self):
        """Envelope modified after signing fails verification."""
        principal = Principal(
            "user:alice", ExecutionRole.AS_USER,
            Scope(frozenset({"docs:x"}), frozenset({"read"}), frozenset({"public"})),
        )
        spec = DelegationBudgetSpec(3, 1.0, 5, "confidential", True, 100.0)
        env = _env(principal, spec)

        # Tamper with scope after signing (bypass seal to simulate attacker)
        object.__setattr__(env, 'effective_scope', Scope(
            frozenset({"docs:x", "db:production"}),
            frozenset({"read", "delete"}),
            frozenset({"public", "regulated"}),
        ))
        assert not env.verify(KEY)


class TestBudgetEvasionSessionSplitting:
    """7.5 — Agent splits workflow across sessions to reset budget."""

    def test_separate_sessions_have_independent_budgets(self):
        """This is the honest limitation — sessions are independent.
        Mitigation: task-level budget binding (documented in paper)."""
        spec = DelegationBudgetSpec(3, 0.3, 2, "confidential", True, 100.0)

        # Session 1
        budget1 = BudgetState(spec=spec)
        budget1.consume(ActionCost(blast_radius=0.25))
        assert budget1.remaining_blast_radius < 0.1

        # Session 2 — fresh budget (the attack)
        budget2 = BudgetState(spec=spec)
        assert budget2.remaining_blast_radius == 0.3

        # This demonstrates the limitation: cross-session budget requires
        # task-level binding, which is an infrastructure concern.
