"""
apc_core — Authorization Envelope lifecycle, scope algebra, principal chain.

Implements Definition 4.1 (Authorization Scope), Definition 4.2 (Principal Chain),
Definition 4.3 (Delegation Budget), Definition 4.4 (Scoped Principal),
Definition 4.5 (Blast Radius), and Theorem 4.1 (Blast Radius Monotonicity).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
from dataclasses import dataclass, field
from enum import Enum


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class EnvelopeSealedError(Exception):
    """Raised when attempting to modify a signed (sealed) envelope."""


# ---------------------------------------------------------------------------
# Resource Hierarchy — hierarchical resource matching for scope checks
# ---------------------------------------------------------------------------

def resource_matches(pattern: str, resource: str) -> bool:
    """Hierarchical resource matching for scope checks.

    Supports colon-separated namespaces with wildcard suffixes:
        "docs:*"                matches "docs:contracts/2025-Q4"
        "docs:contracts/*"      matches "docs:contracts/acme"
        "docs:contracts/acme"   matches "docs:contracts/acme" (exact)
        "email:internal"        matches "email:internal" (exact)
        "*"                     matches everything

    This is used by Scope.contains_resource() to allow hierarchical
    resource definitions without requiring explicit enumeration of
    every concrete resource identifier.

    NOT the same as glob_match() which is used only for intent binding.
    """
    if pattern == resource:
        return True
    if pattern == "*":
        return True
    if pattern.endswith(":*"):
        prefix = pattern[:-1]  # "docs:" from "docs:*"
        return resource.startswith(prefix)
    if pattern.endswith("/*"):
        prefix = pattern[:-1]  # "docs:contracts/" from "docs:contracts/*"
        return resource.startswith(prefix)
    return False


# ---------------------------------------------------------------------------
# Definition 4.1 — Authorization Scope
# ---------------------------------------------------------------------------

CompositionPair = tuple[str, str]
CompositionSequence = tuple[str, ...]  # k-tuple: ordered sequence of k action classes


@dataclass(frozen=True)
class Scope:
    """Authorization scope S = (R, A, D, X).

    Components are finite sets of concrete identifiers (not glob patterns).
    Glob expansion, if needed, happens at session initialization before the
    scope is sealed into the Authorization Envelope.

    Forms a bounded meet-semilattice under component-wise ordering.
    """

    resources: frozenset[str]
    actions: frozenset[str]
    data_classifications: frozenset[str]
    composition_restrictions: frozenset[CompositionPair] = field(default_factory=frozenset)

    def meet(self, other: Scope) -> Scope:
        """Narrowing operation S₁ ⊓ S₂.

        Resources, actions, data_classifications: intersection.
        Composition restrictions: union (asymmetric — restrictions only grow).
        """
        return Scope(
            resources=self.resources & other.resources,
            actions=self.actions & other.actions,
            data_classifications=self.data_classifications & other.data_classifications,
            composition_restrictions=self.composition_restrictions | other.composition_restrictions,
        )

    def contains_resource(self, resource: str) -> bool:
        """Check if a resource is covered by this scope's resource set.

        Supports hierarchical matching: "docs:*" covers "docs:contracts/acme".
        Falls back to exact membership for non-wildcard entries.
        """
        return any(resource_matches(pattern, resource) for pattern in self.resources)

    def contains_action(self, action: str) -> bool:
        """Check if an action is in this scope's action set (exact match)."""
        return action in self.actions

    def contains_data_classification(self, classification: str) -> bool:
        """Check if a data classification is in this scope (exact match)."""
        return classification in self.data_classifications

    def is_subset_of(self, other: Scope) -> bool:
        """S₁ ⊑ S₂ — lattice ordering check."""
        return (
            self.resources <= other.resources
            and self.actions <= other.actions
            and self.data_classifications <= other.data_classifications
            and self.composition_restrictions >= other.composition_restrictions
        )

    @staticmethod
    def top(resources: frozenset[str], actions: frozenset[str],
            data_classifications: frozenset[str]) -> Scope:
        """Top element of the lattice (widest scope, no restrictions)."""
        return Scope(resources, actions, data_classifications, frozenset())

    @staticmethod
    def bottom() -> Scope:
        """Bottom element — no authority.

        Note: composition_restrictions is empty because with no actions
        and no resources, restrictions are vacuously satisfied.
        For the lattice ordering check (is_subset_of), bottom ⊑ S holds
        for any S that also has empty composition_restrictions.
        """
        return Scope(frozenset(), frozenset(), frozenset(), frozenset())


# ---------------------------------------------------------------------------
# Definition 4.2 — Principal Chain (entity; chain structure in Envelope below)
# ---------------------------------------------------------------------------

class ExecutionRole(Enum):
    AS_USER = "as_user"
    ON_BEHALF_OF = "on_behalf_of"
    AS_AGENT = "as_agent"
    AS_SYSTEM = "as_system"


@dataclass(frozen=True)
class Principal:
    """An entity that can hold scope and be held accountable."""

    principal_id: str
    role: ExecutionRole
    role_scope: Scope

    @property
    def is_human(self) -> bool:
        return self.role == ExecutionRole.AS_USER


# ---------------------------------------------------------------------------
# Definition 4.3 — Delegation Budget (structure only; tracking in apc_budget)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DelegationBudgetSpec:
    """Immutable budget specification attached at session init."""

    max_delegation_depth: int
    max_blast_radius: float          # normalized 0..1
    max_irreversible_effects: int
    max_sensitivity_class: str       # e.g. "confidential"
    cross_domain_composition: bool
    max_cost: float


# Sensitivity ordering for budget checks
SENSITIVITY_ORDER = {
    "public": 0,
    "internal": 1,
    "confidential": 2,
    "regulated": 3,
}


# ---------------------------------------------------------------------------
# Definitions 4.2 + 4.4 — Principal Chain + Scoped Principal (Authorization Envelope)
# ---------------------------------------------------------------------------

@dataclass
class AuthorizationEnvelope:
    """Cryptographically-bound session artifact carrying scope + budget.

    Enforces immutability after signing: once sign() is called, any attempt
    to modify fields raises EnvelopeSealedError. This prevents accidental or
    malicious tampering with security-critical fields after the envelope is
    sealed into the principal chain.

    The signing workflow is: create → configure → sign() → use (read-only).
    """

    envelope_id: str
    task_session_id: str
    originating_principal: Principal
    effective_scope: Scope
    budget_spec: DelegationBudgetSpec
    chain: list[Principal] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    expires_at: float = 0.0
    policy_version: str = "1.0"
    _signature: str = ""
    _sealed: bool = field(default=False, repr=False)

    def __post_init__(self) -> None:
        if not self.chain:
            self.chain = [self.originating_principal]
        if self.expires_at == 0.0:
            self.expires_at = self.created_at + 3600  # 1h default

    def __setattr__(self, name: str, value: object) -> None:
        """Enforce immutability after signing.

        Fields prefixed with '_' (internal state) are always writable to
        support the signing workflow itself. All other fields are locked
        once _sealed is True.
        """
        # Allow setting during __init__ (before _sealed exists) and internal fields
        if name.startswith("_") or not getattr(self, "_sealed", False):
            object.__setattr__(self, name, value)
        else:
            raise EnvelopeSealedError(
                f"cannot modify '{name}' after signing — "
                f"envelope is sealed. Create a new envelope instead."
            )

    @property
    def is_sealed(self) -> bool:
        """True if the envelope has been signed and is now immutable."""
        return self._sealed

    # --- Signing (HMAC-SHA256 for reference; production uses asymmetric) ---
    # NOTE: Production implementations should replace this with an abstract
    # signing interface (e.g. a SigningBackend protocol) to support asymmetric
    # keys, HSMs, or cloud KMS services.

    def sign(self, key: bytes) -> None:
        payload = self._signable_payload()
        self._signature = hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()
        self._sealed = True

    def verify(self, key: bytes) -> bool:
        payload = self._signable_payload()
        expected = hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(self._signature, expected)

    def _signable_payload(self) -> str:
        """Canonical JSON payload covering all security-critical fields.

        Includes scope, budget, chain, expiration, and policy version so that
        any tampering with these fields invalidates the signature.
        """
        return json.dumps({
            "envelope_id": self.envelope_id,
            "task_session_id": self.task_session_id,
            "originating_principal": self.originating_principal.principal_id,
            "chain": [p.principal_id for p in self.chain],
            "scope_resources": sorted(self.effective_scope.resources),
            "scope_actions": sorted(self.effective_scope.actions),
            "scope_data": sorted(self.effective_scope.data_classifications),
            "scope_restrictions": sorted(
                (a, b) for a, b in self.effective_scope.composition_restrictions
            ),
            "budget_max_delegation_depth": self.budget_spec.max_delegation_depth,
            "budget_max_blast_radius": self.budget_spec.max_blast_radius,
            "budget_max_irreversible_effects": self.budget_spec.max_irreversible_effects,
            "budget_max_sensitivity_class": self.budget_spec.max_sensitivity_class,
            "budget_cross_domain_composition": self.budget_spec.cross_domain_composition,
            "budget_max_cost": self.budget_spec.max_cost,
            "expires_at": self.expires_at,
            "policy_version": self.policy_version,
        }, sort_keys=True)

    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    # --- Narrowing (Definition 4.4) ---

    def narrow(self, delegate: Principal, key: bytes) -> AuthorizationEnvelope:
        """Create a narrowed envelope for a downstream principal.

        S(pᵢ) = S(pᵢ₋₁) ⊓ S_role(pᵢ)
        """
        narrowed_scope = self.effective_scope.meet(delegate.role_scope)
        new_chain = list(self.chain) + [delegate]

        child = AuthorizationEnvelope(
            envelope_id=f"{self.envelope_id}:{len(new_chain) - 1}",
            task_session_id=self.task_session_id,
            originating_principal=self.originating_principal,
            effective_scope=narrowed_scope,
            budget_spec=self.budget_spec,
            chain=new_chain,
            created_at=time.time(),
            expires_at=self.expires_at,  # inherit parent expiry
            policy_version=self.policy_version,
        )
        child.sign(key)
        return child

    @property
    def delegation_depth(self) -> int:
        return len(self.chain) - 1


# ---------------------------------------------------------------------------
# Definition 4.5 — Blast Radius + Theorem 4.1
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ResourceBlastProfile:
    """Maps resources to their blast-radius contribution blast(r) ∈ [0,1].

    Paper Definition 4.5: blast(r) is the normalized blast-radius contribution
    of resource r. Used to compute BR_max — the set of resources reachable
    given the remaining blast-radius budget.
    """

    _weights: tuple[tuple[str, float], ...] = ()

    def blast(self, resource: str) -> float:
        """Return blast(r) for a resource. Defaults to 0.0 if not profiled."""
        weights = dict(self._weights)
        return weights.get(resource, 0.0)

    @staticmethod
    def from_dict(weights: dict[str, float]) -> ResourceBlastProfile:
        return ResourceBlastProfile(_weights=tuple(weights.items()))


def blast_radius_max(
    envelope: AuthorizationEnvelope,
    resource_profile: ResourceBlastProfile | None = None,
    budget_remaining: float | None = None,
) -> frozenset[str]:
    """Upper bound on reachable resources for the current chain tip.

    Paper Definition 4.5:
        BR_max(p_i) = R(S(p_i)) ∩ {r : blast(r) ≤ β_max − β_consumed}

    When resource_profile and budget_remaining are provided, computes the
    full intersection. Otherwise returns R(S(p_i)) as a conservative upper
    bound (every scope resource is considered reachable).
    """
    scope_resources = envelope.effective_scope.resources
    if resource_profile is None or budget_remaining is None:
        return scope_resources
    return frozenset(
        r for r in scope_resources
        if resource_profile.blast(r) <= budget_remaining + 1e-9
    )


def verify_blast_radius_monotonicity(
    parent: AuthorizationEnvelope,
    child: AuthorizationEnvelope,
    resource_profile: ResourceBlastProfile | None = None,
    parent_budget_remaining: float | None = None,
    child_budget_remaining: float | None = None,
) -> bool:
    """Theorem 4.1: BR_max(pᵢ) ⊆ BR_max(pᵢ₋₁)."""
    br_parent = blast_radius_max(parent, resource_profile, parent_budget_remaining)
    br_child = blast_radius_max(child, resource_profile, child_budget_remaining)
    return br_child <= br_parent


# ---------------------------------------------------------------------------
# Glob matching — infrastructure utility for intent binding (Condition 6)
# ---------------------------------------------------------------------------

def glob_match(pattern: str, value: str) -> bool:
    """Simple glob matching: * matches any sequence of characters.

    Used by intent binding (Condition 6) for pattern-based resource and
    action matching. NOT used by scope algebra (Definition 4.1), which
    operates on finite sets of concrete identifiers.

    Examples:
        docs:contracts/* matches docs:contracts/2025-Q4
        docs:* matches docs:anything
        * matches everything
    """
    regex = re.escape(pattern).replace(r"\*", ".*")
    return re.fullmatch(regex, value) is not None
