"""
apc_calibrate — Impact calibration framework.

Three methods:
  (i)   Expert elicitation with Kendall's τ consistency
  (ii)  Empirical Bayesian estimation from incident data
  (iii) Sensitivity analysis and threshold selection

Implementation notes for production:
  - elicit_weights() uses a grid search over the weight simplex. This is
    O(grid_resolution²) and sufficient for the typical case (5-20 action
    profiles). For larger action spaces, replace with scipy.optimize or
    a proper constrained optimizer.
  - bayesian_estimate() uses a simple gradient descent with L2 regularization.
    Production deployments with large incident datasets should consider
    scipy.optimize.minimize with method='SLSQP' and simplex constraints,
    or a proper Bayesian framework (PyMC, Stan) for posterior estimation.
  - sensitivity_analysis() performs a brute-force sweep over threshold values.
    This is intentionally simple for interpretability. The perturbation
    stability metric is a first-order approximation; production systems
    should consider bootstrap confidence intervals.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass


@dataclass(frozen=True)
class ActionProfile:
    """Impact profile for a single action type."""

    name: str
    irreversibility: float   # ρ(a) in [0, 1]
    blast_radius: float      # Bl(a) in [0, 1]
    sensitivity: float       # Se(a) in [0, 1]

    def __post_init__(self) -> None:
        for field_name in ("irreversibility", "blast_radius", "sensitivity"):
            val = getattr(self, field_name)
            if not (0.0 <= val <= 1.0):
                raise ValueError(
                    f"{field_name} must be in [0, 1], got {val}"
                )


@dataclass(frozen=True)
class ImpactWeights:
    """Weights w_ρ, w_β, w_σ for I(a) = w_ρ·ρ(a) + w_β·Bl(a) + w_σ·Se(a)."""

    alpha: float  # w_ρ — irreversibility weight
    beta: float   # w_β — blast radius weight
    gamma: float  # w_σ — sensitivity weight

    def __post_init__(self) -> None:
        total = self.alpha + self.beta + self.gamma
        if abs(total - 1.0) > 1e-6:
            raise ValueError(f"Weights must sum to 1.0, got {total:.6f}")
        if self.alpha < 0 or self.beta < 0 or self.gamma < 0:
            raise ValueError("All weights must be non-negative")

    def impact(self, profile: ActionProfile) -> float:
        return (
            self.alpha * profile.irreversibility
            + self.beta * profile.blast_radius
            + self.gamma * profile.sensitivity
        )


# ---------------------------------------------------------------------------
# (i) Expert Elicitation with Kendall's τ
# ---------------------------------------------------------------------------

def kendall_tau(ranking_a: list[str], ranking_b: list[str]) -> float:
    """Compute Kendall's τ between two rankings of the same items.

    Returns value in [-1, 1]. τ ≥ 0.8 required for consistency.
    """
    if set(ranking_a) != set(ranking_b):
        raise ValueError("Rankings must contain the same items")

    n = len(ranking_a)
    if n < 2:
        return 1.0

    pos_b = {item: i for i, item in enumerate(ranking_b)}
    b_order = [pos_b[item] for item in ranking_a]

    concordant = 0
    discordant = 0
    for i, j in itertools.combinations(range(n), 2):
        # Concordant: same relative order in both rankings
        if (b_order[i] - b_order[j]) * (i - j) > 0:
            concordant += 1
        elif (b_order[i] - b_order[j]) * (i - j) < 0:
            discordant += 1

    pairs = n * (n - 1) / 2
    return (concordant - discordant) / pairs


def elicit_weights(
    actions: list[ActionProfile],
    expert_ranking: list[str],
    grid_resolution: int = 20,
) -> ElicitationResult:
    """Derive weights via constrained optimization over expert ranking.

    Searches weight space (grid) to minimize rank-order violations.
    """
    best_weights: ImpactWeights | None = None
    best_tau = -2.0
    best_violations = float("inf")

    step = 1.0 / grid_resolution
    profile_map = {a.name: a for a in actions}

    for ai in range(1, grid_resolution):
        for bi in range(1, grid_resolution - ai):
            alpha = ai * step
            beta = bi * step
            gamma = 1.0 - alpha - beta

            w = ImpactWeights(alpha=alpha, beta=beta, gamma=gamma)
            scored = sorted(actions, key=lambda a: w.impact(a), reverse=True)
            induced_ranking = [a.name for a in scored]

            tau = kendall_tau(expert_ranking, induced_ranking)
            # Count violations
            violations = sum(
                1 for i, j in itertools.combinations(range(len(expert_ranking)), 2)
                if w.impact(profile_map[expert_ranking[i]]) < w.impact(profile_map[expert_ranking[j]])
            )

            if violations < best_violations or (violations == best_violations and tau > best_tau):
                best_violations = violations
                best_tau = tau
                best_weights = w

    assert best_weights is not None
    return ElicitationResult(
        weights=best_weights,
        kendall_tau=best_tau,
        rank_violations=int(best_violations),
        consistent=best_tau >= 0.8,
    )


@dataclass(frozen=True)
class ElicitationResult:
    weights: ImpactWeights
    kendall_tau: float
    rank_violations: int
    consistent: bool


# ---------------------------------------------------------------------------
# (ii) Empirical Bayesian Estimation
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class IncidentRecord:
    """Historical incident with observed severity."""

    action_name: str
    observed_severity: float  # normalized 0..1


def bayesian_estimate(
    actions: list[ActionProfile],
    incidents: list[IncidentRecord],
    prior: ImpactWeights,
    learning_rate: float = 0.1,
    iterations: int = 100,
) -> ImpactWeights:
    """Simple gradient-descent MLE with prior regularization.

    Minimizes Σ(I(a) - observed)² + λ·||w - prior||² over incidents.
    """
    profile_map = {a.name: a for a in actions}
    alpha, beta, gamma = prior.alpha, prior.beta, prior.gamma
    lam = 0.5  # regularization strength

    for _ in range(iterations):
        grad_a, grad_b, grad_g = 0.0, 0.0, 0.0

        for inc in incidents:
            profile = profile_map.get(inc.action_name)
            if profile is None:
                continue
            predicted = alpha * profile.irreversibility + beta * profile.blast_radius + gamma * profile.sensitivity
            error = predicted - inc.observed_severity

            grad_a += 2 * error * profile.irreversibility
            grad_b += 2 * error * profile.blast_radius
            grad_g += 2 * error * profile.sensitivity

        # Prior regularization
        grad_a += 2 * lam * (alpha - prior.alpha)
        grad_b += 2 * lam * (beta - prior.beta)
        grad_g += 2 * lam * (gamma - prior.gamma)

        alpha -= learning_rate * grad_a
        beta -= learning_rate * grad_b
        gamma -= learning_rate * grad_g

        # Project onto simplex (α + β + γ = 1, all ≥ ε)
        alpha, beta, gamma = _project_simplex(alpha, beta, gamma)

    return ImpactWeights(alpha=alpha, beta=beta, gamma=gamma)


def _project_simplex(a: float, b: float, c: float, eps: float = 0.01) -> tuple[float, float, float]:
    """Project onto the probability simplex with minimum ε per component."""
    a, b, c = max(a, eps), max(b, eps), max(c, eps)
    total = a + b + c
    return a / total, b / total, c / total


# ---------------------------------------------------------------------------
# (iii) Sensitivity Analysis and Threshold Selection
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ThresholdAnalysis:
    """Result of threshold selection analysis."""

    threshold: float
    false_autonomous_rate: float   # high-impact actions classified as autonomous
    approval_burden: float         # fraction of actions requiring approval
    meets_constraints: bool


def sensitivity_analysis(
    actions: list[ActionProfile],
    weights: ImpactWeights,
    high_impact_labels: set[str],
    max_false_autonomous: float = 0.01,
    max_approval_burden: float = 0.15,
    perturbation: float = 0.20,
    threshold_steps: int = 100,
) -> SensitivityResult:
    """Analyze threshold selection and weight stability.

    - Finds optimal θ satisfying both constraints
    - Perturbs each weight ±perturbation and reports classification stability
    """
    # Score all actions
    scores = {a.name: weights.impact(a) for a in actions}
    n = len(actions)
    n_high = len(high_impact_labels)

    # Find optimal threshold
    best: ThresholdAnalysis | None = None
    all_thresholds: list[ThresholdAnalysis] = []

    for i in range(threshold_steps + 1):
        theta = i / threshold_steps

        # Actions below threshold are autonomous
        autonomous = {name for name, s in scores.items() if s <= theta}
        approval_required = {name for name, s in scores.items() if s > theta}

        # False autonomous: high-impact actions classified as autonomous
        false_auto = len(autonomous & high_impact_labels)
        far = false_auto / n_high if n_high > 0 else 0.0

        # Approval burden: fraction of all actions requiring approval
        burden = len(approval_required) / n if n > 0 else 0.0

        meets = far <= max_false_autonomous and burden <= max_approval_burden
        ta = ThresholdAnalysis(
            threshold=theta,
            false_autonomous_rate=far,
            approval_burden=burden,
            meets_constraints=meets,
        )
        all_thresholds.append(ta)

        if meets and (best is None or burden < best.approval_burden):
            best = ta

    # Perturbation stability
    stable_count = 0
    total_perturbations = 0
    if best is not None:
        base_classification = {
            name: scores[name] > best.threshold for name in scores
        }
        for dim in ["alpha", "beta", "gamma"]:
            for direction in [-1, 1]:
                perturbed = _perturb_weights(weights, dim, direction * perturbation)
                if perturbed is None:
                    continue
                total_perturbations += 1
                perturbed_scores = {a.name: perturbed.impact(a) for a in actions}
                perturbed_class = {
                    name: perturbed_scores[name] > best.threshold for name in perturbed_scores
                }
                if perturbed_class == base_classification:
                    stable_count += 1

    stability = stable_count / total_perturbations if total_perturbations > 0 else 0.0

    return SensitivityResult(
        optimal_threshold=best,
        classification_stability=stability,
        all_thresholds=tuple(all_thresholds),
    )


def _perturb_weights(
    w: ImpactWeights, dim: str, delta: float
) -> ImpactWeights | None:
    """Perturb one weight dimension and re-normalize."""
    a, b, g = w.alpha, w.beta, w.gamma
    if dim == "alpha":
        a += delta
    elif dim == "beta":
        b += delta
    else:
        g += delta

    if a <= 0 or b <= 0 or g <= 0:
        return None
    total = a + b + g
    return ImpactWeights(alpha=a / total, beta=b / total, gamma=g / total)


@dataclass(frozen=True)
class SensitivityResult:
    optimal_threshold: ThresholdAnalysis | None
    classification_stability: float  # 0..1
    all_thresholds: tuple[ThresholdAnalysis, ...] = ()
