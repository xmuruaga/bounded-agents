"""
apc_pdp — Policy Decision Point.

Implements the six-condition action-admissibility predicate
and the nine normative validation rules from Appendix A.5.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

from apc.approval import ApprovalStore, compute_action_hash
from apc.budget import ActionCost, BudgetState
from apc.calibrate import ActionProfile, ImpactWeights
from apc.compose import CompositionChecker
from apc.core import AuthorizationEnvelope
from apc.intent import IntentChecker
from apc.logging import apc_logger
from apc.parameters import ParameterValidator


# ---------------------------------------------------------------------------
# Proposed Action
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ProposedAction:
    """A concrete action submitted for admissibility evaluation."""

    action_type: str
    target_resource: str
    parameters: dict[str, Any]
    actor_principal_id: str
    task_session_id: str
    policy_version: str
    # Cost descriptors for budget
    blast_radius: float = 0.0
    irreversible_effects: int = 0
    sensitivity_class: str = "public"
    is_cross_domain: bool = False
    compute_cost: float = 0.0
    # Impact profile for approval check
    irreversibility_score: float = 0.0
    blast_radius_score: float = 0.0
    sensitivity_score: float = 0.0


# ---------------------------------------------------------------------------
# Evidence Sink (with integrity verification)
# ---------------------------------------------------------------------------

class EvidenceSinkBackend(Protocol):
    """Protocol for pluggable evidence storage backends.

    Production implementations should connect to append-only stores
    (e.g. Amazon QLDB, immutable S3 buckets, blockchain-backed logs).
    """

    def store(self, package: dict[str, Any]) -> bool:
        """Persist an evidence package. Returns True on success."""
        ...

    def verify_integrity(self) -> bool:
        """Verify the integrity of the evidence chain."""
        ...


class EvidenceSink:
    """Infrastructure-side evidence commitment with integrity chain.

    Each evidence package includes a hash of the previous package,
    forming a tamper-evident chain. Any deletion or modification of
    an intermediate entry breaks the chain and is detectable via
    verify_integrity().

    Production implementations should use the EvidenceSinkBackend
    protocol to connect to append-only stores.
    """

    def __init__(self, backend: EvidenceSinkBackend | None = None) -> None:
        self._available = True
        self._packages: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self._backend = backend
        self._chain_head: str = "genesis"  # hash of the previous package

    @property
    def is_available(self) -> bool:
        return self._available

    def set_available(self, available: bool) -> None:
        self._available = available

    def commit(self, package: dict[str, Any]) -> bool:
        if not self._available:
            return False
        with self._lock:
            # Build integrity chain
            package_with_chain = {
                **package,
                "committed_at": time.time(),
                "sequence_number": len(self._packages),
                "previous_hash": self._chain_head,
            }
            # Compute hash of this package for the chain
            content_hash = self._hash_package(package_with_chain)
            package_with_chain["content_hash"] = content_hash

            # Persist to backend if available
            if self._backend is not None:
                if not self._backend.store(package_with_chain):
                    return False

            self._packages.append(package_with_chain)
            self._chain_head = content_hash
            return True

    def verify_integrity(self) -> EvidenceIntegrityResult:
        """Verify the integrity of the entire evidence chain.

        Checks that each package's previous_hash matches the content_hash
        of the preceding package, and that no packages have been modified.
        """
        with self._lock:
            if not self._packages:
                return EvidenceIntegrityResult(valid=True, total_packages=0)

            expected_prev = "genesis"
            for i, pkg in enumerate(self._packages):
                # Check chain linkage
                if pkg.get("previous_hash") != expected_prev:
                    return EvidenceIntegrityResult(
                        valid=False,
                        total_packages=len(self._packages),
                        broken_at_index=i,
                        detail=f"chain break at index {i}: expected previous_hash "
                               f"'{expected_prev}', got '{pkg.get('previous_hash')}'",
                    )
                # Verify content hash
                stored_hash = pkg.get("content_hash", "")
                recomputed = self._hash_package(
                    {k: v for k, v in pkg.items() if k != "content_hash"}
                )
                if stored_hash != recomputed:
                    return EvidenceIntegrityResult(
                        valid=False,
                        total_packages=len(self._packages),
                        broken_at_index=i,
                        detail=f"content tampered at index {i}",
                    )
                expected_prev = stored_hash

            return EvidenceIntegrityResult(
                valid=True,
                total_packages=len(self._packages),
            )

    @property
    def packages(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._packages)

    @staticmethod
    def _hash_package(package: dict[str, Any]) -> str:
        """Deterministic hash of an evidence package."""
        canonical = json.dumps(package, sort_keys=True, default=str)
        return hashlib.sha256(canonical.encode()).hexdigest()


@dataclass(frozen=True)
class EvidenceIntegrityResult:
    """Result of evidence chain integrity verification."""
    valid: bool
    total_packages: int = 0
    broken_at_index: int = -1
    detail: str = ""


# ---------------------------------------------------------------------------
# Envelope Revocation Registry
# ---------------------------------------------------------------------------

class RevocationRegistry:
    """Registry of revoked envelope IDs.

    When an envelope is compromised, its ID is added to this registry.
    The PDP checks this registry before evaluating any action. This
    provides immediate invalidation without waiting for expiration.

    Production implementations should back this with a distributed
    cache (e.g. Redis) or database for cross-node consistency.
    """

    def __init__(self) -> None:
        self._revoked: dict[str, float] = {}  # envelope_id -> revocation timestamp
        self._lock = threading.Lock()

    def revoke(self, envelope_id: str, reason: str = "") -> None:
        """Revoke an envelope by ID. Takes effect immediately."""
        with self._lock:
            self._revoked[envelope_id] = time.time()

    def is_revoked(self, envelope_id: str) -> bool:
        """Check if an envelope has been revoked."""
        with self._lock:
            return envelope_id in self._revoked

    @property
    def revoked_count(self) -> int:
        with self._lock:
            return len(self._revoked)


# ---------------------------------------------------------------------------
# Rate Limiter
# ---------------------------------------------------------------------------

class RateLimiter:
    """Sliding-window rate limiter for PDP evaluations.

    Prevents brute-force probing of the admissibility predicate by
    limiting the number of evaluations per principal per time window.

    Uses a per-principal sliding window: each evaluation is timestamped,
    and evaluations older than the window are pruned on each check.
    """

    def __init__(
        self,
        max_evaluations: int = 100,
        window_seconds: float = 60.0,
    ) -> None:
        self._max_evaluations = max_evaluations
        self._window_seconds = window_seconds
        self._timestamps: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def check_and_record(self, principal_id: str) -> RateLimitResult:
        """Check if the principal is within rate limits, and record the attempt.

        Returns a result indicating whether the evaluation is allowed.
        """
        now = time.time()
        cutoff = now - self._window_seconds

        with self._lock:
            timestamps = self._timestamps.get(principal_id, [])
            # Prune old entries
            timestamps = [t for t in timestamps if t > cutoff]

            if len(timestamps) >= self._max_evaluations:
                self._timestamps[principal_id] = timestamps
                return RateLimitResult(
                    allowed=False,
                    current_count=len(timestamps),
                    max_allowed=self._max_evaluations,
                    window_seconds=self._window_seconds,
                    retry_after=timestamps[0] + self._window_seconds - now,
                )

            timestamps.append(now)
            self._timestamps[principal_id] = timestamps
            return RateLimitResult(
                allowed=True,
                current_count=len(timestamps),
                max_allowed=self._max_evaluations,
                window_seconds=self._window_seconds,
            )


@dataclass(frozen=True)
class RateLimitResult:
    """Result of a rate limit check."""
    allowed: bool
    current_count: int = 0
    max_allowed: int = 0
    window_seconds: float = 0.0
    retry_after: float = 0.0


# ---------------------------------------------------------------------------
# Admissibility Decision
# ---------------------------------------------------------------------------

@dataclass
class AdmissibilityDecision:
    admitted: bool
    condition_results: dict[str, ConditionResult] = field(default_factory=dict)
    denial_reasons: list[str] = field(default_factory=list)

    @property
    def summary(self) -> str:
        if self.admitted:
            return "ADMITTED"
        return f"DENIED: {'; '.join(self.denial_reasons)}"


@dataclass(frozen=True)
class ConditionResult:
    name: str
    passed: bool
    detail: str = ""


# ---------------------------------------------------------------------------
# Policy Decision Point
# ---------------------------------------------------------------------------

class PolicyDecisionPoint:
    """Evaluates the six-condition admissibility predicate.

    Rule 1: Fail closed — missing data → deny.
    Rule 2: Conjunctive — all six must pass.
    Rule 3: Envelope takes precedence over manifest.
    Rule 4: Temporal validity — expired → deny.
    Rule 5: Action-hash integrity for approval tokens.
    Rule 6: Budget precedence — exhausted → deny.
    Rule 7: Evidence availability — unreachable → deny.
    Rule 8: Composition check against full session history.
    Rule 9: Intent conformance — graduated enforcement.
    Rule 10: Envelope revocation — revoked → deny.
    Rule 11: Rate limiting — exceeded → deny.
    """

    def __init__(
        self,
        signing_key: bytes,
        impact_weights: ImpactWeights,
        approval_threshold: float,
        approval_store: ApprovalStore,
        evidence_sink: EvidenceSink,
        revocation_registry: RevocationRegistry | None = None,
        rate_limiter: RateLimiter | None = None,
        parameter_validator: ParameterValidator | None = None,
    ) -> None:
        self._signing_key = signing_key
        self._impact_weights = impact_weights
        self._approval_threshold = approval_threshold
        self._approval_store = approval_store
        self._evidence_sink = evidence_sink
        self._revocation_registry = revocation_registry
        self._rate_limiter = rate_limiter
        self._parameter_validator = parameter_validator
        self._lock = threading.Lock()

    def evaluate(
        self,
        action: ProposedAction,
        envelope: AuthorizationEnvelope,
        budget: BudgetState,
        composition_checker: CompositionChecker,
        approval_token_id: str | None = None,
        intent_checker: IntentChecker | None = None,
    ) -> AdmissibilityDecision:
        conditions: dict[str, ConditionResult] = {}
        denials: list[str] = []

        # --- Rule 1: Fail closed on missing data ---
        if envelope is None or budget is None or composition_checker is None:
            return AdmissibilityDecision(
                admitted=False,
                denial_reasons=["fail_closed: missing evaluation data"],
            )

        # --- Rule 11: Rate limiting ---
        if self._rate_limiter is not None:
            rate_result = self._rate_limiter.check_and_record(action.actor_principal_id)
            if not rate_result.allowed:
                return AdmissibilityDecision(
                    admitted=False,
                    denial_reasons=[
                        f"rate_limit_exceeded: {rate_result.current_count}/"
                        f"{rate_result.max_allowed} evaluations in "
                        f"{rate_result.window_seconds}s window"
                    ],
                )

        # --- Rule 10: Envelope revocation ---
        if self._revocation_registry is not None:
            if self._revocation_registry.is_revoked(envelope.envelope_id):
                return AdmissibilityDecision(
                    admitted=False,
                    denial_reasons=[f"envelope '{envelope.envelope_id}' has been revoked"],
                )

        # --- Rule 4: Temporal validity ---
        if envelope.is_expired:
            return AdmissibilityDecision(
                admitted=False,
                denial_reasons=["envelope expired"],
            )

        # --- Rule 6: Budget exhaustion ---
        if budget.is_exhausted:
            return AdmissibilityDecision(
                admitted=False,
                denial_reasons=["budget exhausted"],
            )

        # --- Rule 7: Evidence availability ---
        if not self._evidence_sink.is_available:
            return AdmissibilityDecision(
                admitted=False,
                denial_reasons=["evidence sink unavailable"],
            )

        # Thread-safe evaluation of the six conditions.
        # The lock ensures that check + record + consume is atomic,
        # preventing TOCTOU races between concurrent tool calls.
        with self._lock:
            return self._evaluate_conditions(
                action, envelope, budget, composition_checker,
                approval_token_id, intent_checker,
                conditions, denials,
            )

    def _evaluate_conditions(
        self,
        action: ProposedAction,
        envelope: AuthorizationEnvelope,
        budget: BudgetState,
        composition_checker: CompositionChecker,
        approval_token_id: str | None,
        intent_checker: IntentChecker | None,
        conditions: dict[str, ConditionResult],
        denials: list[str],
    ) -> AdmissibilityDecision:
        """Evaluate all six conditions under the PDP lock."""

        # --- Condition 1: Identity Binding ---
        c1 = self._check_identity(action, envelope)
        conditions["identity_binding"] = c1
        if not c1.passed:
            denials.append(c1.detail)

        # --- Condition 2: Scope Attenuation + Composition Closure ---
        c2a = self._check_scope(action, envelope)
        conditions["scope_attenuation"] = c2a
        if not c2a.passed:
            denials.append(c2a.detail)

        # Rule 8: Composition check against full session history
        c2b = self._check_composition(action, composition_checker)
        conditions["composition_closure"] = c2b
        if not c2b.passed:
            denials.append(c2b.detail)

        # Budget check
        c2c = self._check_budget(action, budget)
        conditions["budget"] = c2c
        if not c2c.passed:
            denials.append(c2c.detail)

        # --- Condition 3: Context and State Binding ---
        c3 = self._check_context(action, envelope)
        conditions["context_binding"] = c3
        if not c3.passed:
            denials.append(c3.detail)

        # --- Condition 4: Approval Binding ---
        c4 = self._check_approval(action, envelope, approval_token_id)
        conditions["approval_binding"] = c4
        if not c4.passed:
            denials.append(c4.detail)

        # --- Condition 5: Evidence Commitment ---
        # Note: Evidence availability is already checked by Rule 7 (early return).
        # This condition records the passing result for the decision audit trail.
        conditions["evidence_commitment"] = ConditionResult("evidence_commitment", True)

        # --- Condition 6: Intent Binding (Rule 9) ---
        c6 = self._check_intent(action, intent_checker)
        conditions["intent_binding"] = c6
        if not c6.passed:
            denials.append(c6.detail)

        # --- Parameter Validation (optional, addresses parameter-level exfiltration) ---
        c_param = self._check_parameters(action)
        if c_param is not None:
            conditions["parameter_validation"] = c_param
            if not c_param.passed:
                denials.append(c_param.detail)

        # --- Rule 2: Conjunctive evaluation ---
        admitted = len(denials) == 0

        decision = AdmissibilityDecision(
            admitted=admitted,
            condition_results=conditions,
            denial_reasons=denials,
        )

        # If admitted, commit evidence, record composition, consume budget.
        # Per paper §5 C5: implementations SHOULD treat evidence commit
        # failure as an execution failure requiring rollback or compensating
        # control where rollback is impossible.
        if admitted:
            commit_ok = self._commit_evidence(action, envelope, budget, admitted=True)
            if not commit_ok:
                apc_logger.evidence_failure(
                    envelope.task_session_id,
                    "commit failed post-admission",
                    action_type=action.action_type,
                )
                return AdmissibilityDecision(
                    admitted=False,
                    condition_results=conditions,
                    denial_reasons=["evidence commit failed post-admission"],
                )
            composition_checker.record(action.action_type, resource=action.target_resource)
            # Consume budget
            cost = ActionCost(
                blast_radius=action.blast_radius,
                irreversible_effects=action.irreversible_effects,
                sensitivity_class=action.sensitivity_class,
                is_cross_domain=action.is_cross_domain,
                compute_cost=action.compute_cost,
            )
            budget.consume(cost)
            # Consume approval token if used
            if approval_token_id:
                self._approval_store.consume(approval_token_id)

            apc_logger.admission(
                action.action_type, action.target_resource,
                action.actor_principal_id, envelope.task_session_id,
            )
        else:
            # Denied actions also produce evidence for audit completeness.
            self._commit_evidence(action, envelope, budget, admitted=False,
                                  denial_reasons=denials)
            apc_logger.denial(
                action.action_type, action.target_resource,
                action.actor_principal_id, envelope.task_session_id,
                reasons=denials,
            )

        return decision

    # --- Individual condition checks ---

    def _check_identity(
        self, action: ProposedAction, envelope: AuthorizationEnvelope
    ) -> ConditionResult:
        # Actor must be in the chain
        chain_ids = {p.principal_id for p in envelope.chain}
        if action.actor_principal_id not in chain_ids:
            return ConditionResult(
                "identity_binding", False,
                f"actor {action.actor_principal_id} not in principal chain",
            )
        # Envelope signature must verify
        if not envelope.verify(self._signing_key):
            return ConditionResult(
                "identity_binding", False, "envelope signature invalid",
            )
        return ConditionResult("identity_binding", True)

    def _check_scope(
        self, action: ProposedAction, envelope: AuthorizationEnvelope
    ) -> ConditionResult:
        scope = envelope.effective_scope
        # Rule 3: Envelope is authoritative.
        # Scope resources support hierarchical matching via contains_resource():
        # "docs:*" covers "docs:contracts/acme". For backward compatibility,
        # exact membership is checked first, then hierarchical patterns.
        if not scope.contains_resource(action.target_resource):
            return ConditionResult(
                "scope_attenuation", False,
                f"resource {action.target_resource} not in scope",
            )
        if not scope.contains_action(action.action_type):
            return ConditionResult(
                "scope_attenuation", False,
                f"action {action.action_type} not in scope",
            )
        if not scope.contains_data_classification(action.sensitivity_class):
            return ConditionResult(
                "scope_attenuation", False,
                f"data classification {action.sensitivity_class} not in scope",
            )
        return ConditionResult("scope_attenuation", True)

    def _check_composition(
        self, action: ProposedAction, checker: CompositionChecker
    ) -> ConditionResult:
        result = checker.check(action.action_type, resource=action.target_resource)
        if not result.allowed:
            details = []
            if result.violations:
                details.append(f"pair violations: {result.violations}")
            if result.k_tuple_violations:
                details.append(f"k-tuple violations: {result.k_tuple_violations}")
            return ConditionResult(
                "composition_closure", False,
                f"composition violation: {'; '.join(details)}",
            )
        return ConditionResult("composition_closure", True)

    def _check_budget(
        self, action: ProposedAction, budget: BudgetState
    ) -> ConditionResult:
        cost = ActionCost(
            blast_radius=action.blast_radius,
            irreversible_effects=action.irreversible_effects,
            sensitivity_class=action.sensitivity_class,
            is_cross_domain=action.is_cross_domain,
            compute_cost=action.compute_cost,
        )
        result = budget.check(cost)
        if not result.allowed:
            return ConditionResult(
                "budget", False,
                f"budget violation: {result.violations}",
            )
        return ConditionResult("budget", True)

    def _check_context(
        self, action: ProposedAction, envelope: AuthorizationEnvelope
    ) -> ConditionResult:
        if action.task_session_id != envelope.task_session_id:
            return ConditionResult(
                "context_binding", False,
                "task_session_id mismatch (anti-replay)",
            )
        if action.policy_version != envelope.policy_version:
            return ConditionResult(
                "context_binding", False,
                f"policy_version mismatch: {action.policy_version} vs {envelope.policy_version}",
            )
        return ConditionResult("context_binding", True)

    def _check_approval(
        self,
        action: ProposedAction,
        envelope: AuthorizationEnvelope,
        token_id: str | None,
    ) -> ConditionResult:
        profile = ActionProfile(
            name=action.action_type,
            irreversibility=action.irreversibility_score,
            blast_radius=action.blast_radius_score,
            sensitivity=action.sensitivity_score,
        )
        impact = self._impact_weights.impact(profile)

        if impact <= self._approval_threshold:
            return ConditionResult("approval_binding", True, "below threshold")

        # High impact — need approval token
        if token_id is None:
            return ConditionResult(
                "approval_binding", False,
                f"impact {impact:.3f} > threshold {self._approval_threshold}, no approval token",
            )

        token = self._approval_store.get(token_id)
        if token is None:
            return ConditionResult(
                "approval_binding", False, "approval token not found",
            )

        # Rule 5: Action-hash integrity
        expected_hash = compute_action_hash(
            action.action_type, action.target_resource, action.parameters,
        )
        validation = token.validate_for_action(expected_hash, action.task_session_id)
        if not validation.valid:
            return ConditionResult(
                "approval_binding", False,
                f"approval token invalid: {validation.errors}",
            )

        return ConditionResult("approval_binding", True, "approved")

    def _check_intent(
        self,
        action: ProposedAction,
        intent_checker: IntentChecker | None,
    ) -> ConditionResult:
        if intent_checker is None or not intent_checker.has_intent:
            return ConditionResult("intent_binding", True, "no intent spec (trivially satisfied)")

        result = intent_checker.check(action.action_type, action.target_resource)
        if result.admitted:
            detail = "conforms" if result.conforms else f"deviation (mode={result.enforcement_mode.value}): {result.deviations}"
            return ConditionResult("intent_binding", True, detail)

        return ConditionResult(
            "intent_binding", False,
            f"intent violation: {result.deviations}",
        )

    def _check_parameters(self, action: ProposedAction) -> ConditionResult | None:
        """Validate tool parameters against the parameter policy.

        Returns None if no parameter validator is configured (condition
        is not applicable). Returns a ConditionResult otherwise.
        """
        if self._parameter_validator is None:
            return None

        result = self._parameter_validator.validate(
            action.action_type, action.parameters,
        )
        if result.valid:
            return ConditionResult("parameter_validation", True)

        apc_logger.parameter_violation(
            action.action_type, action.target_resource,
            action.actor_principal_id, action.task_session_id,
            violations=list(result.violations),
        )
        return ConditionResult(
            "parameter_validation", False,
            f"parameter violations: {result.violations}",
        )

    def _commit_evidence(
        self,
        action: ProposedAction,
        envelope: AuthorizationEnvelope,
        budget: BudgetState,
        admitted: bool = True,
        denial_reasons: list[str] | None = None,
    ) -> bool:
        """Commit evidence package. Returns True on success, False on failure."""
        package: dict[str, Any] = {
            "action_type": action.action_type,
            "target_resource": action.target_resource,
            "parameters": action.parameters,
            "actor": action.actor_principal_id,
            "envelope_id": envelope.envelope_id,
            "task_session_id": envelope.task_session_id,
            "chain": [p.principal_id for p in envelope.chain],
            "scope_resources": sorted(envelope.effective_scope.resources),
            "budget_remaining_blast": budget.remaining_blast_radius,
            "budget_remaining_cost": budget.remaining_cost,
            "admitted": admitted,
        }
        if denial_reasons:
            package["denial_reasons"] = denial_reasons
        return self._evidence_sink.commit(package)
