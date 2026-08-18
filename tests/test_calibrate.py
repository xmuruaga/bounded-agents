"""Tests for apc_calibrate — impact calibration framework."""

from apc.calibrate import (
    ActionProfile,
    ImpactWeights,
    IncidentRecord,
    bayesian_estimate,
    elicit_weights,
    kendall_tau,
    sensitivity_analysis,
)


# Reference action set for tests
ACTIONS = [
    ActionProfile("delete_production_db", irreversibility=1.0, blast_radius=1.0, sensitivity=0.8),
    ActionProfile("send_external_email", irreversibility=0.9, blast_radius=0.5, sensitivity=0.7),
    ActionProfile("modify_config", irreversibility=0.6, blast_radius=0.4, sensitivity=0.5),
    ActionProfile("read_confidential", irreversibility=0.0, blast_radius=0.1, sensitivity=0.9),
    ActionProfile("read_public", irreversibility=0.0, blast_radius=0.05, sensitivity=0.1),
]


class TestKendallTau:
    def test_identical_rankings(self):
        r = ["a", "b", "c", "d"]
        assert kendall_tau(r, r) == 1.0

    def test_reversed_rankings(self):
        r1 = ["a", "b", "c", "d"]
        r2 = ["d", "c", "b", "a"]
        assert kendall_tau(r1, r2) == -1.0

    def test_partial_agreement(self):
        r1 = ["a", "b", "c"]
        r2 = ["a", "c", "b"]
        tau = kendall_tau(r1, r2)
        assert -1.0 <= tau <= 1.0

    def test_single_item(self):
        assert kendall_tau(["a"], ["a"]) == 1.0


class TestExpertElicitation:
    def test_consistent_ranking(self):
        expert_ranking = [
            "delete_production_db",
            "send_external_email",
            "modify_config",
            "read_confidential",
            "read_public",
        ]
        result = elicit_weights(ACTIONS, expert_ranking)
        assert result.kendall_tau >= 0.6  # should find reasonable weights
        assert abs(result.weights.alpha + result.weights.beta + result.weights.gamma - 1.0) < 1e-6

    def test_weights_sum_to_one(self):
        ranking = [a.name for a in sorted(ACTIONS, key=lambda x: x.irreversibility, reverse=True)]
        result = elicit_weights(ACTIONS, ranking)
        total = result.weights.alpha + result.weights.beta + result.weights.gamma
        assert abs(total - 1.0) < 1e-6


class TestBayesianEstimate:
    def test_converges_toward_data(self):
        prior = ImpactWeights(alpha=0.33, beta=0.34, gamma=0.33)
        incidents = [
            IncidentRecord("delete_production_db", observed_severity=0.95),
            IncidentRecord("read_public", observed_severity=0.05),
            IncidentRecord("send_external_email", observed_severity=0.7),
        ]
        posterior = bayesian_estimate(ACTIONS, incidents, prior, iterations=200)
        assert abs(posterior.alpha + posterior.beta + posterior.gamma - 1.0) < 1e-6
        # Posterior should produce scores closer to observed
        pred_delete = posterior.impact(ACTIONS[0])
        pred_read = posterior.impact(ACTIONS[4])
        assert pred_delete > pred_read

    def test_weights_remain_positive(self):
        prior = ImpactWeights(alpha=0.33, beta=0.34, gamma=0.33)
        incidents = [IncidentRecord("read_public", observed_severity=0.0)] * 50
        posterior = bayesian_estimate(ACTIONS, incidents, prior, iterations=500)
        assert posterior.alpha > 0
        assert posterior.beta > 0
        assert posterior.gamma > 0


class TestSensitivityAnalysis:
    def test_finds_valid_threshold(self):
        weights = ImpactWeights(alpha=0.4, beta=0.3, gamma=0.3)
        high_impact = {"delete_production_db", "send_external_email"}
        result = sensitivity_analysis(
            ACTIONS, weights, high_impact,
            max_false_autonomous=0.01,
            max_approval_burden=0.80,  # relaxed for small set
        )
        assert result.optimal_threshold is not None
        assert result.optimal_threshold.meets_constraints

    def test_stability_reported(self):
        weights = ImpactWeights(alpha=0.4, beta=0.3, gamma=0.3)
        high_impact = {"delete_production_db"}
        result = sensitivity_analysis(ACTIONS, weights, high_impact)
        assert 0.0 <= result.classification_stability <= 1.0

    def test_impossible_constraints_return_none(self):
        weights = ImpactWeights(alpha=0.4, beta=0.3, gamma=0.3)
        # All actions are high-impact but we want 0% approval burden
        all_high = {a.name for a in ACTIONS}
        result = sensitivity_analysis(
            ACTIONS, weights, all_high,
            max_false_autonomous=0.0,
            max_approval_burden=0.0,
        )
        # Can't have 0% false-autonomous AND 0% approval burden when all are high-impact
        assert result.optimal_threshold is None
