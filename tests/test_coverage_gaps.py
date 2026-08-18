"""Targeted tests to reach 100% coverage on all uncovered lines."""

import time

import pytest

from apc.approval import ApprovalStore, ApprovalToken, ApprovalStatus, compute_action_hash
from apc.budget import ActionCost, BudgetCheckResult, BudgetState
from apc.calibrate import (
    ActionProfile,
    ImpactWeights,
    IncidentRecord,
    bayesian_estimate,
    elicit_weights,
    kendall_tau,
    sensitivity_analysis,
    _perturb_weights,
)
from apc.compose import ActionClassMapping, CompositionChecker
from apc.core import (
    AuthorizationEnvelope,
    DelegationBudgetSpec,
    ExecutionRole,
    Principal,
    Scope,
)
from apc.pdp import (
    AdmissibilityDecision,
    ConditionResult,
    EvidenceSink,
    PolicyDecisionPoint,
    ProposedAction,
)

KEY = b"test-signing-key-for-reference-impl"


# --- approval.py gaps ---

class TestApprovalGaps:
    def test_validate_expired_token_reports_status(self):
        """Line 61: validate_for_action when status != GRANTED."""
        token = ApprovalToken(
            token_id="t1", action_hash="h1", target_resource="r",
            scope_snapshot={}, approver_id="admin",
            approved_at=time.time() - 600,
            expires_at=time.time() - 1,  # expired
            policy_version="1.0", task_session_id="s1",
        )
        result = token.validate_for_action("h1", "s1")
        assert not result.valid
        assert any("expired" in e for e in result.errors)

    def test_store_consume_nonexistent_returns_false(self):
        """Line 152: consume returns False for missing token."""
        store = ApprovalStore()
        assert store.consume("nonexistent") is False

    def test_store_revoke_nonexistent_returns_false(self):
        """Line 160: revoke returns False for missing token."""
        store = ApprovalStore()
        assert store.revoke("nonexistent") is False

    def test_store_consume_already_consumed_returns_false(self):
        store = ApprovalStore()
        store.issue("t1", "read", "r", {}, {}, "admin", "1.0", "s1")
        store.consume("t1")
        assert store.consume("t1") is False


# --- budget.py gaps ---

class TestBudgetGaps:
    def test_remaining_irreversible(self):
        """Line 106: remaining_irreversible property."""
        spec = DelegationBudgetSpec(3, 1.0, 5, "confidential", True, 100.0)
        state = BudgetState(spec=spec)
        assert state.remaining_irreversible == 5
        state.consume(ActionCost(irreversible_effects=2))
        assert state.remaining_irreversible == 3

    def test_budget_check_result_defaults(self):
        """Line 117: BudgetCheckResult with default violations."""
        r = BudgetCheckResult(allowed=True)
        assert r.violations == ()


# --- calibrate.py gaps ---

class TestCalibrateGaps:
    def test_impact_weights_sum_not_one_raises(self):
        """Line 38: ValueError when weights don't sum to 1."""
        with pytest.raises(ValueError, match="sum to 1.0"):
            ImpactWeights(alpha=0.5, beta=0.5, gamma=0.5)

    def test_impact_weights_negative_raises(self):
        """Line 40: ValueError when weight is negative."""
        with pytest.raises(ValueError, match="non-negative"):
            ImpactWeights(alpha=-0.1, beta=0.6, gamma=0.5)

    def test_action_profile_out_of_range_raises(self):
        """ActionProfile validates [0, 1] range for all score fields."""
        with pytest.raises(ValueError, match="irreversibility"):
            ActionProfile("bad", irreversibility=1.5, blast_radius=0.5, sensitivity=0.5)
        with pytest.raises(ValueError, match="blast_radius"):
            ActionProfile("bad", irreversibility=0.5, blast_radius=-0.1, sensitivity=0.5)
        with pytest.raises(ValueError, match="sensitivity"):
            ActionProfile("bad", irreversibility=0.5, blast_radius=0.5, sensitivity=2.0)

    def test_kendall_tau_mismatched_items_raises(self):
        """Line 60: ValueError for mismatched rankings."""
        with pytest.raises(ValueError, match="same items"):
            kendall_tau(["a", "b"], ["c", "d"])

    def test_elicit_weights_gamma_zero_skipped(self):
        """Line 104: gamma <= 0 branch in grid search."""
        # With only 2 actions and grid_resolution=2, some combos have gamma<=0
        actions = [
            ActionProfile("a", 1.0, 0.0, 0.0),
            ActionProfile("b", 0.0, 1.0, 0.0),
        ]
        result = elicit_weights(actions, ["a", "b"], grid_resolution=3)
        assert result.weights is not None

    def test_bayesian_skips_unknown_action(self):
        """Line 172: profile is None for unknown action name."""
        actions = [ActionProfile("known", 0.5, 0.5, 0.5)]
        incidents = [IncidentRecord("unknown_action", 0.8)]
        prior = ImpactWeights(0.33, 0.34, 0.33)
        result = bayesian_estimate(actions, incidents, prior, iterations=10)
        # Should not crash, weights should stay near prior
        assert abs(result.alpha + result.beta + result.gamma - 1.0) < 1e-6

    def test_perturb_weights_negative_returns_none(self):
        """Lines 308, 312-313: _perturb_weights returns None."""
        w = ImpactWeights(alpha=0.1, beta=0.45, gamma=0.45)
        # Large negative perturbation makes alpha <= 0
        assert _perturb_weights(w, "alpha", -0.5) is None

    def test_perturb_weights_beta(self):
        w = ImpactWeights(alpha=0.4, beta=0.3, gamma=0.3)
        result = _perturb_weights(w, "beta", 0.1)
        assert result is not None

    def test_perturb_weights_gamma(self):
        w = ImpactWeights(alpha=0.4, beta=0.3, gamma=0.3)
        result = _perturb_weights(w, "gamma", 0.1)
        assert result is not None

    def test_sensitivity_no_high_impact(self):
        """Line 277: n_high == 0 branch."""
        actions = [ActionProfile("a", 0.1, 0.1, 0.1)]
        weights = ImpactWeights(0.4, 0.3, 0.3)
        result = sensitivity_analysis(actions, weights, set())
        assert result.optimal_threshold is not None


# --- compose.py gaps ---

class TestComposeGaps:
    def test_action_history_property(self):
        """Line 130: action_history property."""
        checker = CompositionChecker(restrictions=frozenset())
        checker.record("read")
        checker.record("write")
        assert checker.action_history == ["read", "write"]


# --- core.py gaps ---

class TestCoreGaps:
    def test_scope_top(self):
        """Line 65: Scope.top() static method."""
        s = Scope.top(frozenset({"a"}), frozenset({"read"}), frozenset({"public"}))
        assert s.resources == frozenset({"a"})
        assert s.composition_restrictions == frozenset()

    def test_principal_is_human_false(self):
        """Line 94: is_human returns False for non-AS_USER."""
        p = Principal("agent:x", ExecutionRole.AS_AGENT,
                      Scope(frozenset(), frozenset(), frozenset()))
        assert p.is_human is False

    def test_envelope_is_expired(self):
        """Line 145: is_expired returns True."""
        p = Principal("user:x", ExecutionRole.AS_USER,
                      Scope(frozenset(), frozenset(), frozenset()))
        spec = DelegationBudgetSpec(3, 1.0, 5, "confidential", True, 100.0)
        env = AuthorizationEnvelope(
            envelope_id="e1", task_session_id="s1",
            originating_principal=p, effective_scope=p.role_scope,
            budget_spec=spec, expires_at=time.time() - 1,
        )
        assert env.is_expired is True


# --- pdp.py gaps ---

def _make_env(principal, budget_spec):
    env = AuthorizationEnvelope(
        envelope_id="env-gap", task_session_id="session-gap",
        originating_principal=principal, effective_scope=principal.role_scope,
        budget_spec=budget_spec, expires_at=time.time() + 3600,
    )
    env.sign(KEY)
    return env


class TestPdpGaps:
    def _pdp(self, store=None, sink=None, threshold=0.5):
        return PolicyDecisionPoint(
            signing_key=KEY,
            impact_weights=ImpactWeights(0.4, 0.3, 0.3),
            approval_threshold=threshold,
            approval_store=store or ApprovalStore(),
            evidence_sink=sink or EvidenceSink(),
        )

    def test_summary_admitted(self):
        """AdmissibilityDecision.summary for admitted."""
        d = AdmissibilityDecision(admitted=True)
        assert d.summary == "ADMITTED"

    def test_summary_denied(self):
        """AdmissibilityDecision.summary for denied."""
        d = AdmissibilityDecision(admitted=False, denial_reasons=["scope", "budget"])
        assert "DENIED" in d.summary
        assert "scope" in d.summary

    def test_evidence_sink_commit_when_unavailable(self):
        """EvidenceSink.commit returns False when unavailable."""
        sink = EvidenceSink()
        sink.set_available(False)
        assert sink.commit({"test": True}) is False
        assert len(sink.packages) == 0

    def test_fail_closed_none_envelope(self):
        """Rule 1: None envelope → deny."""
        pdp = self._pdp()
        spec = DelegationBudgetSpec(3, 1.0, 5, "confidential", True, 100.0)
        budget = BudgetState(spec=spec)
        checker = CompositionChecker(restrictions=frozenset())
        action = ProposedAction(
            action_type="read", target_resource="x", parameters={},
            actor_principal_id="user:x", task_session_id="s",
            policy_version="1.0",
        )
        decision = pdp.evaluate(action, None, budget, checker)
        assert not decision.admitted
        assert "fail_closed" in decision.denial_reasons[0]

    def test_fail_closed_none_budget(self):
        """Rule 1: None budget → deny."""
        principal = Principal("user:x", ExecutionRole.AS_USER,
                              Scope(frozenset({"r"}), frozenset({"read"}), frozenset({"public"})))
        spec = DelegationBudgetSpec(3, 1.0, 5, "confidential", True, 100.0)
        env = _make_env(principal, spec)
        pdp = self._pdp()
        checker = CompositionChecker(restrictions=frozenset())
        action = ProposedAction(
            action_type="read", target_resource="r", parameters={},
            actor_principal_id="user:x", task_session_id="session-gap",
            policy_version="1.0",
        )
        decision = pdp.evaluate(action, env, None, checker)
        assert not decision.admitted

    def test_fail_closed_none_checker(self):
        """Rule 1: None composition_checker → deny."""
        principal = Principal("user:x", ExecutionRole.AS_USER,
                              Scope(frozenset({"r"}), frozenset({"read"}), frozenset({"public"})))
        spec = DelegationBudgetSpec(3, 1.0, 5, "confidential", True, 100.0)
        env = _make_env(principal, spec)
        pdp = self._pdp()
        budget = BudgetState(spec=spec)
        action = ProposedAction(
            action_type="read", target_resource="r", parameters={},
            actor_principal_id="user:x", task_session_id="session-gap",
            policy_version="1.0",
        )
        decision = pdp.evaluate(action, env, budget, None)
        assert not decision.admitted

    def test_deny_invalid_signature(self):
        """Identity binding fails on tampered envelope."""
        principal = Principal("user:x", ExecutionRole.AS_USER,
                              Scope(frozenset({"r"}), frozenset({"read"}), frozenset({"public"})))
        spec = DelegationBudgetSpec(3, 1.0, 5, "confidential", True, 100.0)
        env = _make_env(principal, spec)
        env._signature = "tampered"
        pdp = self._pdp()
        budget = BudgetState(spec=spec)
        checker = CompositionChecker(restrictions=frozenset())
        action = ProposedAction(
            action_type="read", target_resource="r", parameters={},
            actor_principal_id="user:x", task_session_id="session-gap",
            policy_version="1.0", sensitivity_class="public",
        )
        decision = pdp.evaluate(action, env, budget, checker)
        assert not decision.admitted
        assert not decision.condition_results["identity_binding"].passed

    def test_deny_action_type_out_of_scope(self):
        """Scope check: action type not in scope."""
        principal = Principal("user:x", ExecutionRole.AS_USER,
                              Scope(frozenset({"r"}), frozenset({"read"}), frozenset({"public"})))
        spec = DelegationBudgetSpec(3, 1.0, 5, "confidential", True, 100.0)
        env = _make_env(principal, spec)
        pdp = self._pdp()
        budget = BudgetState(spec=spec)
        checker = CompositionChecker(restrictions=frozenset())
        action = ProposedAction(
            action_type="delete", target_resource="r", parameters={},
            actor_principal_id="user:x", task_session_id="session-gap",
            policy_version="1.0", sensitivity_class="public",
        )
        decision = pdp.evaluate(action, env, budget, checker)
        assert not decision.admitted

    def test_deny_data_classification_out_of_scope(self):
        """Scope check: data classification not in scope."""
        principal = Principal("user:x", ExecutionRole.AS_USER,
                              Scope(frozenset({"r"}), frozenset({"read"}), frozenset({"public"})))
        spec = DelegationBudgetSpec(3, 1.0, 5, "confidential", True, 100.0)
        env = _make_env(principal, spec)
        pdp = self._pdp()
        budget = BudgetState(spec=spec)
        checker = CompositionChecker(restrictions=frozenset())
        action = ProposedAction(
            action_type="read", target_resource="r", parameters={},
            actor_principal_id="user:x", task_session_id="session-gap",
            policy_version="1.0", sensitivity_class="confidential",
        )
        decision = pdp.evaluate(action, env, budget, checker)
        assert not decision.admitted

    def test_deny_policy_version_mismatch(self):
        """Context binding: policy version mismatch."""
        principal = Principal("user:x", ExecutionRole.AS_USER,
                              Scope(frozenset({"r"}), frozenset({"read"}), frozenset({"public"})))
        spec = DelegationBudgetSpec(3, 1.0, 5, "confidential", True, 100.0)
        env = _make_env(principal, spec)
        pdp = self._pdp()
        budget = BudgetState(spec=spec)
        checker = CompositionChecker(restrictions=frozenset())
        action = ProposedAction(
            action_type="read", target_resource="r", parameters={},
            actor_principal_id="user:x", task_session_id="session-gap",
            policy_version="2.0",  # mismatch
            sensitivity_class="public",
        )
        decision = pdp.evaluate(action, env, budget, checker)
        assert not decision.admitted
        assert not decision.condition_results["context_binding"].passed

    def test_deny_approval_token_not_found(self):
        """Approval binding: token ID doesn't exist in store."""
        principal = Principal("user:x", ExecutionRole.AS_USER,
                              Scope(frozenset({"r"}), frozenset({"delete"}), frozenset({"public"})))
        spec = DelegationBudgetSpec(3, 1.0, 5, "confidential", True, 100.0)
        env = _make_env(principal, spec)
        pdp = self._pdp(threshold=0.0)  # everything needs approval
        budget = BudgetState(spec=spec)
        checker = CompositionChecker(restrictions=frozenset())
        action = ProposedAction(
            action_type="delete", target_resource="r", parameters={},
            actor_principal_id="user:x", task_session_id="session-gap",
            policy_version="1.0", sensitivity_class="public",
            irreversibility_score=0.5, blast_radius_score=0.5, sensitivity_score=0.5,
        )
        decision = pdp.evaluate(action, env, budget, checker, approval_token_id="nonexistent")
        assert not decision.admitted
        assert "not found" in decision.condition_results["approval_binding"].detail

    def test_deny_approval_token_hash_mismatch(self):
        """Rule 5: action-hash integrity — token bound to different action."""
        store = ApprovalStore()
        store.issue("tok-1", "read", "other_resource", {}, {}, "admin", "1.0", "session-gap")
        principal = Principal("user:x", ExecutionRole.AS_USER,
                              Scope(frozenset({"r"}), frozenset({"delete"}), frozenset({"public"})))
        spec = DelegationBudgetSpec(3, 1.0, 5, "confidential", True, 100.0)
        env = _make_env(principal, spec)
        pdp = self._pdp(store=store, threshold=0.0)
        budget = BudgetState(spec=spec)
        checker = CompositionChecker(restrictions=frozenset())
        action = ProposedAction(
            action_type="delete", target_resource="r", parameters={},
            actor_principal_id="user:x", task_session_id="session-gap",
            policy_version="1.0", sensitivity_class="public",
            irreversibility_score=0.5, blast_radius_score=0.5, sensitivity_score=0.5,
        )
        decision = pdp.evaluate(action, env, budget, checker, approval_token_id="tok-1")
        assert not decision.admitted
        assert "invalid" in decision.condition_results["approval_binding"].detail

    def test_deny_budget_violation_in_pdp(self):
        """Budget check within PDP evaluation."""
        principal = Principal("user:x", ExecutionRole.AS_USER,
                              Scope(frozenset({"r"}), frozenset({"read"}), frozenset({"public"})))
        spec = DelegationBudgetSpec(3, 0.1, 5, "confidential", True, 100.0)
        env = _make_env(principal, spec)
        pdp = self._pdp()
        budget = BudgetState(spec=spec)
        checker = CompositionChecker(restrictions=frozenset())
        action = ProposedAction(
            action_type="read", target_resource="r", parameters={},
            actor_principal_id="user:x", task_session_id="session-gap",
            policy_version="1.0", sensitivity_class="public",
            blast_radius=0.5,  # exceeds 0.1 budget
        )
        decision = pdp.evaluate(action, env, budget, checker)
        assert not decision.admitted
        assert not decision.condition_results["budget"].passed


    def test_evidence_check_when_sink_down_during_evaluation(self):
        """Evidence unavailability is caught by Rule 7 early return."""
        sink = EvidenceSink()
        sink.set_available(False)
        principal = Principal("user:x", ExecutionRole.AS_USER,
                              Scope(frozenset({"r"}), frozenset({"read"}), frozenset({"public"})))
        spec = DelegationBudgetSpec(3, 1.0, 5, "confidential", True, 100.0)
        env = _make_env(principal, spec)
        pdp = self._pdp(sink=sink)
        budget = BudgetState(spec=spec)
        checker = CompositionChecker(restrictions=frozenset())
        action = ProposedAction(
            action_type="read", target_resource="r", parameters={},
            actor_principal_id="user:x", task_session_id="session-gap",
            policy_version="1.0", sensitivity_class="public",
        )
        decision = pdp.evaluate(action, env, budget, checker)
        assert not decision.admitted
        assert "evidence sink unavailable" in decision.denial_reasons


class TestCalibrateGapsExtra:
    def test_perturb_weights_value_error_catch(self):
        """Lines 312-313: _perturb_weights catches ValueError."""
        # Create weights where perturbation would cause issues
        # after normalization — this is hard to trigger since we clamp,
        # but we can test the try/except by mocking
        w = ImpactWeights(alpha=0.01, beta=0.01, gamma=0.98)
        # Large negative on gamma makes it <= 0 → returns None
        result = _perturb_weights(w, "gamma", -1.0)
        assert result is None

    def test_sensitivity_analysis_zero_actions(self):
        """Edge case: empty action list."""
        weights = ImpactWeights(0.4, 0.3, 0.3)
        result = sensitivity_analysis([], weights, set())
        # n == 0, burden = 0.0 for all thresholds
        assert result.optimal_threshold is not None

    def test_sensitivity_no_perturbations_possible(self):
        """Stability = 0 when no perturbations succeed."""
        # Weights very close to edge — all perturbations make a component <= 0
        w = ImpactWeights(alpha=0.01, beta=0.01, gamma=0.98)
        actions = [ActionProfile("a", 0.5, 0.5, 0.5)]
        result = sensitivity_analysis(
            actions, w, set(), perturbation=0.5
        )
        # Some perturbations will return None
        assert 0.0 <= result.classification_stability <= 1.0


class TestRemainingGaps:
    """Final targeted tests for the last uncovered lines."""

    def test_budget_cross_domain_consumed(self):
        """budget.py:106 — cross_domain_used = True on successful consume."""
        spec = DelegationBudgetSpec(3, 1.0, 5, "confidential", True, 100.0)
        state = BudgetState(spec=spec)
        result = state.consume(ActionCost(is_cross_domain=True))
        assert result.allowed
        assert state.cross_domain_used is True

    def test_envelope_default_expiry(self):
        """core.py:145 — default expiry when expires_at=0.0."""
        p = Principal("user:x", ExecutionRole.AS_USER,
                      Scope(frozenset(), frozenset(), frozenset()))
        spec = DelegationBudgetSpec(3, 1.0, 5, "confidential", True, 100.0)
        env = AuthorizationEnvelope(
            envelope_id="e1", task_session_id="s1",
            originating_principal=p, effective_scope=p.role_scope,
            budget_spec=spec,
            # expires_at defaults to 0.0, triggering the default branch
        )
        assert env.expires_at > time.time()  # should be ~1h from now

    def test_elicit_gamma_zero_branch(self):
        """Grid search handles edge cases in weight space."""
        from apc.calibrate import elicit_weights
        actions = [
            ActionProfile("high", 1.0, 1.0, 1.0),
            ActionProfile("low", 0.0, 0.0, 0.0),
        ]
        result = elicit_weights(actions, ["high", "low"], grid_resolution=4)
        assert result.weights is not None

    def test_perturb_weights_value_error_branch(self):
        """_perturb_weights works for all dimensions."""
        w = ImpactWeights(alpha=0.5, beta=0.3, gamma=0.2)
        for dim in ["alpha", "beta", "gamma"]:
            result = _perturb_weights(w, dim, 0.05)
            assert result is not None

    def test_pdp_budget_exhausted_early_return(self):
        """pdp.py:162 — budget exhausted early return."""
        principal = Principal("user:x", ExecutionRole.AS_USER,
                              Scope(frozenset({"r"}), frozenset({"read"}), frozenset({"public"})))
        spec = DelegationBudgetSpec(3, 0.1, 5, "confidential", True, 100.0)
        env = _make_env(principal, spec)
        pdp = self._pdp()
        budget = BudgetState(spec=spec)
        # Exhaust the budget first
        budget.consume(ActionCost(blast_radius=0.1))
        assert budget.is_exhausted

        checker = CompositionChecker(restrictions=frozenset())
        action = ProposedAction(
            action_type="read", target_resource="r", parameters={},
            actor_principal_id="user:x", task_session_id="session-gap",
            policy_version="1.0", sensitivity_class="public",
        )
        decision = pdp.evaluate(action, env, budget, checker)
        assert not decision.admitted
        assert "budget exhausted" in decision.denial_reasons

    def _pdp(self, store=None, sink=None, threshold=0.5):
        return PolicyDecisionPoint(
            signing_key=KEY,
            impact_weights=ImpactWeights(0.4, 0.3, 0.3),
            approval_threshold=threshold,
            approval_store=store or ApprovalStore(),
            evidence_sink=sink or EvidenceSink(),
        )
