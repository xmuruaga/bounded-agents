"""
apc_budget — Delegation budget tracker.

Tracks all six budget dimensions incrementally per session.
Budget consumption is monotonic and enforced by infrastructure.

Thread-safe: all mutations are protected by a lock to prevent
TOCTOU races between concurrent check() and consume() calls.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any, Protocol

from apc.core import DelegationBudgetSpec, SENSITIVITY_ORDER


# ---------------------------------------------------------------------------
# Budget Persistence Backend
# ---------------------------------------------------------------------------

class BudgetBackend(Protocol):
    """Protocol for pluggable budget persistence.

    Production implementations should connect to a durable store
    (e.g. Redis, DynamoDB) to enable cross-session budget tracking
    and prevent budget evasion via session splitting.
    """

    def load(self, session_id: str) -> dict[str, Any] | None:
        """Load budget state for a session. Returns None if not found."""
        ...

    def save(self, session_id: str, state: dict[str, Any]) -> bool:
        """Persist budget state. Returns True on success."""
        ...


@dataclass
class ActionCost:
    """Cost descriptor for a single proposed action."""

    blast_radius: float = 0.0       # normalized 0..1
    irreversible_effects: int = 0
    sensitivity_class: str = "public"
    is_cross_domain: bool = False
    compute_cost: float = 0.0
    delegation_hops: int = 0


@dataclass
class BudgetState:
    """Mutable budget consumption state, tracked by infrastructure.

    Thread-safe: all state mutations are protected by a reentrant lock.
    The lock ensures that check() + consume() is atomic when called
    from the PDP's evaluate() method.

    Optionally backed by a BudgetBackend for cross-session persistence.
    """

    spec: DelegationBudgetSpec
    cumulative_blast_radius: float = 0.0
    cumulative_irreversible: int = 0
    current_delegation_depth: int = 0
    peak_sensitivity: str = "public"
    cross_domain_used: bool = False
    cumulative_cost: float = 0.0
    _history: list[ActionCost] = field(default_factory=list)
    _session_id: str = ""
    _backend: BudgetBackend | None = field(default=None, repr=False)
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    @classmethod
    def from_backend(
        cls,
        spec: DelegationBudgetSpec,
        session_id: str,
        backend: BudgetBackend,
    ) -> BudgetState:
        """Create a BudgetState backed by persistent storage.

        Loads existing state from the backend if available, enabling
        cross-session budget continuity (mitigates session-splitting attacks).
        """
        state = cls(spec=spec, _session_id=session_id, _backend=backend)
        saved = backend.load(session_id)
        if saved is not None:
            state.cumulative_blast_radius = saved.get("cumulative_blast_radius", 0.0)
            state.cumulative_irreversible = saved.get("cumulative_irreversible", 0)
            state.current_delegation_depth = saved.get("current_delegation_depth", 0)
            state.peak_sensitivity = saved.get("peak_sensitivity", "public")
            state.cross_domain_used = saved.get("cross_domain_used", False)
            state.cumulative_cost = saved.get("cumulative_cost", 0.0)
        return state
    cumulative_blast_radius: float = 0.0
    cumulative_irreversible: int = 0
    current_delegation_depth: int = 0
    peak_sensitivity: str = "public"
    cross_domain_used: bool = False
    cumulative_cost: float = 0.0
    _history: list[ActionCost] = field(default_factory=list)

    @property
    def is_exhausted(self) -> bool:
        """Check if the budget is fully consumed.

        Uses >= for continuous dimensions (blast_radius, cost) with epsilon
        tolerance, and > for discrete dimensions (irreversible, depth) to
        allow budgets of 0 to mean "none allowed" without being pre-exhausted.
        """
        with self._lock:
            return (
                self.cumulative_blast_radius >= self.spec.max_blast_radius - 1e-9
                or self.cumulative_irreversible > self.spec.max_irreversible_effects
                or self.current_delegation_depth > self.spec.max_delegation_depth
                or self.cumulative_cost >= self.spec.max_cost - 1e-9
            )

    def check(self, cost: ActionCost) -> BudgetCheckResult:
        """Check whether an action is within budget without consuming it."""
        with self._lock:
            return self._check_unlocked(cost)

    def _check_unlocked(self, cost: ActionCost) -> BudgetCheckResult:
        """Internal check without lock (caller must hold lock)."""
        violations: list[str] = []

        if self.cumulative_blast_radius + cost.blast_radius > self.spec.max_blast_radius + 1e-9:
            violations.append(
                f"blast_radius: {self.cumulative_blast_radius + cost.blast_radius:.3f} "
                f"> {self.spec.max_blast_radius}"
            )

        if self.cumulative_irreversible + cost.irreversible_effects > self.spec.max_irreversible_effects:
            violations.append(
                f"irreversible_effects: {self.cumulative_irreversible + cost.irreversible_effects} "
                f"> {self.spec.max_irreversible_effects}"
            )

        new_depth = self.current_delegation_depth + cost.delegation_hops
        if new_depth > self.spec.max_delegation_depth:
            violations.append(
                f"delegation_depth: {new_depth} > {self.spec.max_delegation_depth}"
            )

        cost_sens = SENSITIVITY_ORDER.get(cost.sensitivity_class, 0)
        max_sens = SENSITIVITY_ORDER.get(self.spec.max_sensitivity_class, 0)
        if cost_sens > max_sens:
            violations.append(
                f"sensitivity: {cost.sensitivity_class} > {self.spec.max_sensitivity_class}"
            )

        if cost.is_cross_domain and not self.spec.cross_domain_composition:
            violations.append("cross_domain_composition not allowed")

        if self.cumulative_cost + cost.compute_cost > self.spec.max_cost + 1e-9:
            violations.append(
                f"cost: {self.cumulative_cost + cost.compute_cost:.2f} "
                f"> {self.spec.max_cost}"
            )

        return BudgetCheckResult(allowed=len(violations) == 0, violations=tuple(violations))

    def consume(self, cost: ActionCost) -> BudgetCheckResult:
        """Check and consume budget for an action. Fails if over budget.

        Atomic: check + mutation happens under a single lock acquisition.
        """
        with self._lock:
            result = self._check_unlocked(cost)
            if not result.allowed:
                return result

            self.cumulative_blast_radius += cost.blast_radius
            self.cumulative_irreversible += cost.irreversible_effects
            self.current_delegation_depth += cost.delegation_hops
            self.cumulative_cost += cost.compute_cost

            cost_sens = SENSITIVITY_ORDER.get(cost.sensitivity_class, 0)
            peak_sens = SENSITIVITY_ORDER.get(self.peak_sensitivity, 0)
            if cost_sens > peak_sens:
                self.peak_sensitivity = cost.sensitivity_class

            if cost.is_cross_domain:
                self.cross_domain_used = True

            self._history.append(cost)

            # Persist to backend if available
            if self._backend is not None and self._session_id:
                self._backend.save(self._session_id, self.snapshot())

            return result

    def snapshot(self) -> dict[str, Any]:
        """Return a serializable snapshot of the current budget state."""
        return {
            "cumulative_blast_radius": self.cumulative_blast_radius,
            "cumulative_irreversible": self.cumulative_irreversible,
            "current_delegation_depth": self.current_delegation_depth,
            "peak_sensitivity": self.peak_sensitivity,
            "cross_domain_used": self.cross_domain_used,
            "cumulative_cost": self.cumulative_cost,
        }

    @property
    def remaining_blast_radius(self) -> float:
        with self._lock:
            return max(0.0, self.spec.max_blast_radius - self.cumulative_blast_radius)

    @property
    def remaining_irreversible(self) -> int:
        with self._lock:
            return max(0, self.spec.max_irreversible_effects - self.cumulative_irreversible)

    @property
    def remaining_cost(self) -> float:
        with self._lock:
            return max(0.0, self.spec.max_cost - self.cumulative_cost)


@dataclass(frozen=True)
class BudgetCheckResult:
    allowed: bool
    violations: tuple[str, ...] = ()
