"""Tests for apc_pdp — Policy Decision Point (admissibility predicate)."""

import time

from apc.approval import ApprovalStore, compute_action_hash
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


def _make_env(principal, budget_spec):
    env = AuthorizationEnvelope(
        envelope_id="env-pdp",
        task_session_id="session-pdp",
        originating_principal=principal,
        effective_scope=principal.role_scope,
        budget_spec=budget_spec,
        expires_at=time.time() + 3600,
    )
    env.sign(KEY)
    return env


def _make_pdp(approval_store=None, evidence_sink=None, threshold=0.5):
    return PolicyDecisionPoint(
        signing_key=KEY,
        impact_weights=ImpactWeights(alpha=0.4, beta=0.3, gamma=0.3),
        approval_threshold=threshold,
        approval_store=approval_store or ApprovalStore(),
        evidence_sink=evidence_sink or EvidenceSink(),
    )


class TestAdmissibilityPredicate:
    """Six-condition conjunctive check."""

    def test_simple_admit(self):
        principal = Principal(
            "user:bob", ExecutionRole.AS_USER,
            Scope(frozenset({"docs:x"}), frozenset({"read"}), frozenset({"public"})),
        )
        budget_spec = DelegationBudgetSpec(3, 1.0, 5, "confidential", True, 100.0)
        env = _make_env(principal, budget_spec)
        budget = BudgetState(spec=budget_spec)
        checker = CompositionChecker(restrictions=frozenset())
        pdp = _make_pdp()

        action = ProposedAction(
            action_type="read",
            target_resource="docs:x",
            parameters={"format": "pdf"},
            actor_principal_id="user:bob",
            task_session_id="session-pdp",
            policy_version="1.0",
            sensitivity_class="public",
        )
        decision = pdp.evaluate(action, env, budget, checker)
        assert decision.admitted

    def test_deny_identity_not_in_chain(self):
        principal = Principal(
            "user:bob", ExecutionRole.AS_USER,
            Scope(frozenset({"docs:x"}), frozenset({"read"}), frozenset({"public"})),
        )
        budget_spec = DelegationBudgetSpec(3, 1.0, 5, "confidential", True, 100.0)
        env = _make_env(principal, budget_spec)
        budget = BudgetState(spec=budget_spec)
        checker = CompositionChecker(restrictions=frozenset())
        pdp = _make_pdp()

        action = ProposedAction(
            action_type="read",
            target_resource="docs:x",
            parameters={},
            actor_principal_id="user:eve",  # not in chain
            task_session_id="session-pdp",
            policy_version="1.0",
            sensitivity_class="public",
        )
        decision = pdp.evaluate(action, env, budget, checker)
        assert not decision.admitted
        assert "identity_binding" in decision.condition_results
        assert not decision.condition_results["identity_binding"].passed

    def test_deny_resource_out_of_scope(self):
        principal = Principal(
            "user:bob", ExecutionRole.AS_USER,
            Scope(frozenset({"docs:x"}), frozenset({"read"}), frozenset({"public"})),
        )
        budget_spec = DelegationBudgetSpec(3, 1.0, 5, "confidential", True, 100.0)
        env = _make_env(principal, budget_spec)
        budget = BudgetState(spec=budget_spec)
        checker = CompositionChecker(restrictions=frozenset())
        pdp = _make_pdp()

        action = ProposedAction(
            action_type="read",
            target_resource="db:production",  # not in scope
            parameters={},
            actor_principal_id="user:bob",
            task_session_id="session-pdp",
            policy_version="1.0",
            sensitivity_class="public",
        )
        decision = pdp.evaluate(action, env, budget, checker)
        assert not decision.admitted

    def test_deny_composition_violation(self):
        principal = Principal(
            "user:bob", ExecutionRole.AS_USER,
            Scope(
                frozenset({"docs:x", "email:ext"}),
                frozenset({"read", "send"}),
                frozenset({"public", "confidential"}),
                frozenset({("read", "send")}),
            ),
        )
        budget_spec = DelegationBudgetSpec(3, 1.0, 5, "confidential", True, 100.0)
        env = _make_env(principal, budget_spec)
        budget = BudgetState(spec=budget_spec)
        checker = CompositionChecker(restrictions=env.effective_scope.composition_restrictions)
        pdp = _make_pdp()

        # First action: read (admitted)
        a1 = ProposedAction(
            action_type="read", target_resource="docs:x", parameters={},
            actor_principal_id="user:bob", task_session_id="session-pdp",
            policy_version="1.0", sensitivity_class="public",
        )
        d1 = pdp.evaluate(a1, env, budget, checker)
        assert d1.admitted

        # Second action: send (should be denied — composition violation)
        a2 = ProposedAction(
            action_type="send", target_resource="email:ext", parameters={},
            actor_principal_id="user:bob", task_session_id="session-pdp",
            policy_version="1.0", sensitivity_class="public",
        )
        d2 = pdp.evaluate(a2, env, budget, checker)
        assert not d2.admitted
        assert not d2.condition_results["composition_closure"].passed

    def test_deny_context_session_mismatch(self):
        principal = Principal(
            "user:bob", ExecutionRole.AS_USER,
            Scope(frozenset({"docs:x"}), frozenset({"read"}), frozenset({"public"})),
        )
        budget_spec = DelegationBudgetSpec(3, 1.0, 5, "confidential", True, 100.0)
        env = _make_env(principal, budget_spec)
        budget = BudgetState(spec=budget_spec)
        checker = CompositionChecker(restrictions=frozenset())
        pdp = _make_pdp()

        action = ProposedAction(
            action_type="read", target_resource="docs:x", parameters={},
            actor_principal_id="user:bob",
            task_session_id="different-session",  # mismatch
            policy_version="1.0",
            sensitivity_class="public",
        )
        decision = pdp.evaluate(action, env, budget, checker)
        assert not decision.admitted

    def test_deny_high_impact_without_approval(self):
        principal = Principal(
            "user:bob", ExecutionRole.AS_USER,
            Scope(frozenset({"db:prod"}), frozenset({"delete"}), frozenset({"confidential"})),
        )
        budget_spec = DelegationBudgetSpec(3, 1.0, 5, "confidential", True, 100.0)
        env = _make_env(principal, budget_spec)
        budget = BudgetState(spec=budget_spec)
        checker = CompositionChecker(restrictions=frozenset())
        pdp = _make_pdp(threshold=0.3)

        action = ProposedAction(
            action_type="delete", target_resource="db:prod", parameters={},
            actor_principal_id="user:bob", task_session_id="session-pdp",
            policy_version="1.0", sensitivity_class="confidential",
            irreversibility_score=1.0, blast_radius_score=0.8, sensitivity_score=0.9,
        )
        decision = pdp.evaluate(action, env, budget, checker)
        assert not decision.admitted
        assert not decision.condition_results["approval_binding"].passed

    def test_admit_high_impact_with_valid_approval(self):
        store = ApprovalStore()
        principal = Principal(
            "user:bob", ExecutionRole.AS_USER,
            Scope(frozenset({"db:prod"}), frozenset({"delete"}), frozenset({"confidential"})),
        )
        budget_spec = DelegationBudgetSpec(3, 1.0, 5, "confidential", True, 100.0)
        env = _make_env(principal, budget_spec)
        budget = BudgetState(spec=budget_spec)
        checker = CompositionChecker(restrictions=frozenset())
        pdp = _make_pdp(approval_store=store, threshold=0.3)

        params = {"table": "users"}
        token = store.issue(
            token_id="tok-pdp-1",
            action_type="delete",
            target_resource="db:prod",
            parameters=params,
            scope_snapshot={},
            approver_id="user:admin",
            policy_version="1.0",
            task_session_id="session-pdp",
        )

        action = ProposedAction(
            action_type="delete", target_resource="db:prod", parameters=params,
            actor_principal_id="user:bob", task_session_id="session-pdp",
            policy_version="1.0", sensitivity_class="confidential",
            irreversibility_score=1.0, blast_radius_score=0.8, sensitivity_score=0.9,
        )
        decision = pdp.evaluate(action, env, budget, checker, approval_token_id="tok-pdp-1")
        assert decision.admitted

    def test_deny_evidence_sink_unavailable(self):
        sink = EvidenceSink()
        sink.set_available(False)
        principal = Principal(
            "user:bob", ExecutionRole.AS_USER,
            Scope(frozenset({"docs:x"}), frozenset({"read"}), frozenset({"public"})),
        )
        budget_spec = DelegationBudgetSpec(3, 1.0, 5, "confidential", True, 100.0)
        env = _make_env(principal, budget_spec)
        budget = BudgetState(spec=budget_spec)
        checker = CompositionChecker(restrictions=frozenset())
        pdp = _make_pdp(evidence_sink=sink)

        action = ProposedAction(
            action_type="read", target_resource="docs:x", parameters={},
            actor_principal_id="user:bob", task_session_id="session-pdp",
            policy_version="1.0", sensitivity_class="public",
        )
        decision = pdp.evaluate(action, env, budget, checker)
        assert not decision.admitted

    def test_deny_expired_envelope(self):
        principal = Principal(
            "user:bob", ExecutionRole.AS_USER,
            Scope(frozenset({"docs:x"}), frozenset({"read"}), frozenset({"public"})),
        )
        budget_spec = DelegationBudgetSpec(3, 1.0, 5, "confidential", True, 100.0)
        env = AuthorizationEnvelope(
            envelope_id="env-expired",
            task_session_id="session-pdp",
            originating_principal=principal,
            effective_scope=principal.role_scope,
            budget_spec=budget_spec,
            expires_at=time.time() - 1,  # already expired
        )
        env.sign(KEY)
        budget = BudgetState(spec=budget_spec)
        checker = CompositionChecker(restrictions=frozenset())
        pdp = _make_pdp()

        action = ProposedAction(
            action_type="read", target_resource="docs:x", parameters={},
            actor_principal_id="user:bob", task_session_id="session-pdp",
            policy_version="1.0", sensitivity_class="public",
        )
        decision = pdp.evaluate(action, env, budget, checker)
        assert not decision.admitted
        assert "envelope expired" in decision.denial_reasons

    def test_evidence_committed_on_admit(self):
        sink = EvidenceSink()
        principal = Principal(
            "user:bob", ExecutionRole.AS_USER,
            Scope(frozenset({"docs:x"}), frozenset({"read"}), frozenset({"public"})),
        )
        budget_spec = DelegationBudgetSpec(3, 1.0, 5, "confidential", True, 100.0)
        env = _make_env(principal, budget_spec)
        budget = BudgetState(spec=budget_spec)
        checker = CompositionChecker(restrictions=frozenset())
        pdp = _make_pdp(evidence_sink=sink)

        action = ProposedAction(
            action_type="read", target_resource="docs:x", parameters={},
            actor_principal_id="user:bob", task_session_id="session-pdp",
            policy_version="1.0", sensitivity_class="public",
        )
        pdp.evaluate(action, env, budget, checker)
        assert len(sink.packages) == 1
        assert sink.packages[0]["action_type"] == "read"

    def test_deny_evidence_commit_failure_post_admission(self):
        """C5: if evidence commit fails after admission, action is denied.

        Paper §5 C5: 'Implementations SHOULD treat evidence commit failure
        as an execution failure requiring rollback or compensating control.'
        """
        sink = EvidenceSink()
        principal = Principal(
            "user:bob", ExecutionRole.AS_USER,
            Scope(frozenset({"docs:x"}), frozenset({"read"}), frozenset({"public"})),
        )
        budget_spec = DelegationBudgetSpec(3, 1.0, 5, "confidential", True, 100.0)
        env = _make_env(principal, budget_spec)
        budget = BudgetState(spec=budget_spec)
        checker = CompositionChecker(restrictions=frozenset())
        pdp = _make_pdp(evidence_sink=sink)

        action = ProposedAction(
            action_type="read", target_resource="docs:x", parameters={},
            actor_principal_id="user:bob", task_session_id="session-pdp",
            policy_version="1.0", sensitivity_class="public",
        )

        # Sink is available for Rule 7 check, but we make it fail on commit
        # by disabling it after the availability check passes.
        # We achieve this by monkey-patching commit to fail.
        original_commit = sink.commit
        def failing_commit(package):
            return False
        sink.commit = failing_commit

        decision = pdp.evaluate(action, env, budget, checker)
        assert not decision.admitted
        assert "evidence commit failed post-admission" in decision.denial_reasons
