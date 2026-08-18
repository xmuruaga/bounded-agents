"""Tests for apc_budget — delegation budget tracker."""

from apc.budget import ActionCost, BudgetState
from apc.core import DelegationBudgetSpec


class TestBudgetCheck:
    def test_within_budget(self, budget_state):
        cost = ActionCost(blast_radius=0.1, compute_cost=10.0)
        result = budget_state.check(cost)
        assert result.allowed

    def test_blast_radius_exceeded(self, budget_state):
        cost = ActionCost(blast_radius=0.6)
        result = budget_state.check(cost)
        assert not result.allowed
        assert any("blast_radius" in v for v in result.violations)

    def test_irreversible_exceeded(self, budget_state):
        cost = ActionCost(irreversible_effects=3)
        result = budget_state.check(cost)
        assert not result.allowed

    def test_sensitivity_exceeded(self, budget_state):
        cost = ActionCost(sensitivity_class="regulated")
        result = budget_state.check(cost)
        assert not result.allowed

    def test_cross_domain_blocked(self, budget_state):
        cost = ActionCost(is_cross_domain=True)
        result = budget_state.check(cost)
        assert not result.allowed

    def test_cost_exceeded(self, budget_state):
        cost = ActionCost(compute_cost=101.0)
        result = budget_state.check(cost)
        assert not result.allowed

    def test_delegation_depth_exceeded(self, budget_state):
        cost = ActionCost(delegation_hops=4)
        result = budget_state.check(cost)
        assert not result.allowed


class TestBudgetConsumption:
    def test_consume_tracks_cumulative(self, budget_state):
        cost = ActionCost(blast_radius=0.1, compute_cost=10.0)
        budget_state.consume(cost)
        assert budget_state.cumulative_blast_radius == 0.1
        assert budget_state.cumulative_cost == 10.0

    def test_consume_rejects_when_over(self, budget_state):
        budget_state.consume(ActionCost(blast_radius=0.4))
        result = budget_state.consume(ActionCost(blast_radius=0.2))
        assert not result.allowed

    def test_remaining_decreases(self, budget_state):
        initial_br = budget_state.remaining_blast_radius
        budget_state.consume(ActionCost(blast_radius=0.1))
        assert budget_state.remaining_blast_radius < initial_br

    def test_is_exhausted(self, budget_state):
        assert not budget_state.is_exhausted
        budget_state.consume(ActionCost(blast_radius=0.5))
        assert budget_state.is_exhausted

    def test_peak_sensitivity_tracked(self, budget_state):
        budget_state.consume(ActionCost(sensitivity_class="public"))
        assert budget_state.peak_sensitivity == "public"
        budget_state.consume(ActionCost(sensitivity_class="confidential"))
        assert budget_state.peak_sensitivity == "confidential"

    def test_multiple_small_actions_exhaust_budget(self):
        """Threshold gaming defense: many small actions hit cumulative limit."""
        spec = DelegationBudgetSpec(
            max_delegation_depth=10,
            max_blast_radius=0.3,
            max_irreversible_effects=5,
            max_sensitivity_class="confidential",
            cross_domain_composition=True,
            max_cost=100.0,
        )
        state = BudgetState(spec=spec)
        for _ in range(3):
            result = state.consume(ActionCost(blast_radius=0.1))
            assert result.allowed
        # 4th should fail
        result = state.consume(ActionCost(blast_radius=0.1))
        assert not result.allowed
