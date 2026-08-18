"""Verify the exfiltration example from the README actually runs."""

import time

from apc.core import Scope, Principal, ExecutionRole, AuthorizationEnvelope, DelegationBudgetSpec
from apc.budget import BudgetState
from apc.compose import CompositionChecker
from apc.approval import ApprovalStore
from apc.calibrate import ImpactWeights
from apc.pdp import PolicyDecisionPoint, ProposedAction, EvidenceSink


def test_readme_exfiltration_example():
    user = Principal("user:alice", ExecutionRole.AS_USER, Scope(
        resources=frozenset({"docs:confidential", "email:external"}),
        actions=frozenset({"read", "send"}),
        data_classifications=frozenset({"confidential"}),
        composition_restrictions=frozenset({("read", "send")}),
    ))

    key = b"infrastructure-key"
    budget_spec = DelegationBudgetSpec(3, 1.0, 5, "confidential", True, 100.0)
    envelope = AuthorizationEnvelope(
        "env-1", "session-1", user, user.role_scope, budget_spec,
        expires_at=time.time() + 3600,
    )
    envelope.sign(key)

    pdp = PolicyDecisionPoint(
        signing_key=key,
        impact_weights=ImpactWeights(0.4, 0.3, 0.3),
        approval_threshold=0.5,
        approval_store=ApprovalStore(),
        evidence_sink=EvidenceSink(),
    )
    budget = BudgetState(spec=budget_spec)
    checker = CompositionChecker(restrictions=envelope.effective_scope.composition_restrictions)

    # Step 1: Read — ADMITTED
    read_action = ProposedAction(
        action_type="read", target_resource="docs:confidential",
        parameters={"doc": "merger-plan.pdf"},
        actor_principal_id="user:alice", task_session_id="session-1",
        policy_version="1.0", sensitivity_class="confidential", blast_radius=0.05,
    )
    result = pdp.evaluate(read_action, envelope, budget, checker)
    assert result.admitted

    # Step 2: Send — DENIED (composition violation)
    send_action = ProposedAction(
        action_type="send", target_resource="email:external",
        parameters={"to": "someone@outside.com", "body": "..."},
        actor_principal_id="user:alice", task_session_id="session-1",
        policy_version="1.0", sensitivity_class="confidential", blast_radius=0.1,
    )
    result = pdp.evaluate(send_action, envelope, budget, checker)
    assert not result.admitted
    assert "composition violation" in result.summary
