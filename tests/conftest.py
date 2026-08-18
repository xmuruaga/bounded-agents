"""Shared fixtures for APC test suite."""

from __future__ import annotations

import time

import pytest

from apc.approval import ApprovalStore
from apc.budget import BudgetState
from apc.calibrate import ImpactWeights
from apc.compose import ActionClassMapping, CompositionChecker, RestrictionTemplate, compile_templates
from apc.core import (
    AuthorizationEnvelope,
    DelegationBudgetSpec,
    ExecutionRole,
    Principal,
    Scope,
)
from apc.pdp import EvidenceSink, PolicyDecisionPoint

SIGNING_KEY = b"test-signing-key-for-reference-impl"


@pytest.fixture
def signing_key() -> bytes:
    return SIGNING_KEY


@pytest.fixture
def human_principal() -> Principal:
    return Principal(
        principal_id="user:alice",
        role=ExecutionRole.AS_USER,
        role_scope=Scope(
            resources=frozenset({"docs:*", "email:internal", "email:external", "db:read"}),
            actions=frozenset({"read", "write", "send", "delete"}),
            data_classifications=frozenset({"public", "internal", "confidential"}),
            composition_restrictions=frozenset({("read_confidential", "external_send")}),
        ),
    )


@pytest.fixture
def agent_principal() -> Principal:
    return Principal(
        principal_id="agent:doc-processor",
        role=ExecutionRole.ON_BEHALF_OF,
        role_scope=Scope(
            resources=frozenset({"docs:*", "db:read"}),
            actions=frozenset({"read"}),
            data_classifications=frozenset({"public", "internal", "confidential"}),
            composition_restrictions=frozenset(),
        ),
    )


@pytest.fixture
def budget_spec() -> DelegationBudgetSpec:
    return DelegationBudgetSpec(
        max_delegation_depth=3,
        max_blast_radius=0.5,
        max_irreversible_effects=2,
        max_sensitivity_class="confidential",
        cross_domain_composition=False,
        max_cost=100.0,
    )


@pytest.fixture
def envelope(human_principal: Principal, budget_spec: DelegationBudgetSpec, signing_key: bytes) -> AuthorizationEnvelope:
    env = AuthorizationEnvelope(
        envelope_id="env-001",
        task_session_id="session-001",
        originating_principal=human_principal,
        effective_scope=human_principal.role_scope,
        budget_spec=budget_spec,
        expires_at=time.time() + 3600,
    )
    env.sign(signing_key)
    return env


@pytest.fixture
def narrowed_envelope(
    envelope: AuthorizationEnvelope,
    agent_principal: Principal,
    signing_key: bytes,
) -> AuthorizationEnvelope:
    return envelope.narrow(agent_principal, signing_key)


@pytest.fixture
def budget_state(budget_spec: DelegationBudgetSpec) -> BudgetState:
    return BudgetState(spec=budget_spec)


@pytest.fixture
def approval_store() -> ApprovalStore:
    return ApprovalStore()


@pytest.fixture
def evidence_sink() -> EvidenceSink:
    return EvidenceSink()


@pytest.fixture
def impact_weights() -> ImpactWeights:
    return ImpactWeights(alpha=0.4, beta=0.3, gamma=0.3)


@pytest.fixture
def class_mapping() -> ActionClassMapping:
    return ActionClassMapping.from_dict({
        "read": "data_read",
        "read_confidential": "read_confidential",
        "write": "data_write",
        "send": "external_send",
        "send_internal": "internal_send",
        "delete": "state_mutate",
    })


@pytest.fixture
def composition_checker(narrowed_envelope: AuthorizationEnvelope, class_mapping: ActionClassMapping) -> CompositionChecker:
    return CompositionChecker(
        restrictions=narrowed_envelope.effective_scope.composition_restrictions,
        class_mapping=class_mapping,
    )


@pytest.fixture
def pdp(
    signing_key: bytes,
    impact_weights: ImpactWeights,
    approval_store: ApprovalStore,
    evidence_sink: EvidenceSink,
) -> PolicyDecisionPoint:
    return PolicyDecisionPoint(
        signing_key=signing_key,
        impact_weights=impact_weights,
        approval_threshold=0.5,
        approval_store=approval_store,
        evidence_sink=evidence_sink,
    )
