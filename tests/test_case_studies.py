"""
Case Study tests from Section 7 of the paper.

Case Study I:  Delegated MCP Document Processing
Case Study II: Multi-Agent DevOps Pipeline
"""

import time

from apc.approval import ApprovalStore, compute_action_hash
from apc.budget import ActionCost, BudgetState
from apc.calibrate import ImpactWeights
from apc.compose import ActionClassMapping, CompositionChecker
from apc.core import (
    AuthorizationEnvelope,
    DelegationBudgetSpec,
    ExecutionRole,
    Principal,
    Scope,
    verify_blast_radius_monotonicity,
)
from apc.pdp import EvidenceSink, PolicyDecisionPoint, ProposedAction

KEY = b"test-signing-key-for-reference-impl"


class TestCaseStudyI:
    """Case Study I: Delegated MCP Document Processing.

    Global energy company, LLM agent processes contracts via MCP servers.
    Scope: document-read within legal/contracts classification.
    Composition restriction: (document-read, external-send) ∈ X.
    Budget: κ=false, ρ_max=0.
    """

    def setup_method(self):
        self.user = Principal(
            "user:legal-analyst",
            ExecutionRole.AS_USER,
            Scope(
                resources=frozenset({"mcp:doc-retrieval", "mcp:metadata-search",
                                     "mcp:pdf-extract", "mcp:email-external"}),
                actions=frozenset({"document_read", "metadata_search",
                                   "pdf_extract", "external_send"}),
                data_classifications=frozenset({"public", "internal", "confidential"}),
                composition_restrictions=frozenset({
                    ("document_read", "external_send"),
                    ("pdf_extract", "external_send"),
                }),
            ),
        )
        self.agent = Principal(
            "agent:doc-processor",
            ExecutionRole.ON_BEHALF_OF,
            Scope(
                resources=frozenset({"mcp:doc-retrieval", "mcp:metadata-search", "mcp:pdf-extract"}),
                actions=frozenset({"document_read", "metadata_search", "pdf_extract"}),
                data_classifications=frozenset({"public", "internal", "confidential"}),
                composition_restrictions=frozenset(),
            ),
        )
        self.budget_spec = DelegationBudgetSpec(
            max_delegation_depth=2,
            max_blast_radius=0.3,
            max_irreversible_effects=0,  # ρ_max = 0
            max_sensitivity_class="confidential",
            cross_domain_composition=False,  # κ = false
            max_cost=50.0,
        )
        self.store = ApprovalStore()
        self.sink = EvidenceSink()
        self.pdp = PolicyDecisionPoint(
            signing_key=KEY,
            impact_weights=ImpactWeights(0.4, 0.3, 0.3),
            approval_threshold=0.5,
            approval_store=self.store,
            evidence_sink=self.sink,
        )

        env = AuthorizationEnvelope(
            envelope_id="cs1-env",
            task_session_id="cs1-session",
            originating_principal=self.user,
            effective_scope=self.user.role_scope,
            budget_spec=self.budget_spec,
            expires_at=time.time() + 3600,
        )
        env.sign(KEY)
        self.user_env = env
        self.agent_env = env.narrow(self.agent, KEY)

    def test_agent_scope_narrowed(self):
        """Agent cannot access email MCP server."""
        assert "mcp:email-external" not in self.agent_env.effective_scope.resources
        assert "external_send" not in self.agent_env.effective_scope.actions

    def test_blast_radius_monotonicity(self):
        assert verify_blast_radius_monotonicity(self.user_env, self.agent_env)

    def test_document_read_admitted(self):
        budget = BudgetState(spec=self.budget_spec)
        checker = CompositionChecker(
            restrictions=self.agent_env.effective_scope.composition_restrictions,
        )
        action = ProposedAction(
            action_type="document_read",
            target_resource="mcp:doc-retrieval",
            parameters={"doc_id": "contract-2024-001"},
            actor_principal_id="agent:doc-processor",
            task_session_id="cs1-session",
            policy_version="1.0",
            sensitivity_class="confidential",
            blast_radius=0.05,
        )
        decision = self.pdp.evaluate(action, self.agent_env, budget, checker)
        assert decision.admitted

    def test_external_send_denied_by_scope(self):
        """Even if agent tries to send externally, scope blocks it."""
        budget = BudgetState(spec=self.budget_spec)
        checker = CompositionChecker(
            restrictions=self.agent_env.effective_scope.composition_restrictions,
        )
        action = ProposedAction(
            action_type="external_send",
            target_resource="mcp:email-external",
            parameters={"to": "attacker@evil.com"},
            actor_principal_id="agent:doc-processor",
            task_session_id="cs1-session",
            policy_version="1.0",
            sensitivity_class="confidential",
        )
        decision = self.pdp.evaluate(action, self.agent_env, budget, checker)
        assert not decision.admitted

    def test_composition_blocks_exfiltration_at_user_level(self):
        """Even at user level, read + send is blocked by composition closure."""
        budget = BudgetState(spec=self.budget_spec)
        checker = CompositionChecker(
            restrictions=self.user_env.effective_scope.composition_restrictions,
        )

        # Read document
        a1 = ProposedAction(
            action_type="document_read",
            target_resource="mcp:doc-retrieval",
            parameters={"doc_id": "secret"},
            actor_principal_id="user:legal-analyst",
            task_session_id="cs1-session",
            policy_version="1.0",
            sensitivity_class="confidential",
            blast_radius=0.05,
        )
        d1 = self.pdp.evaluate(a1, self.user_env, budget, checker)
        assert d1.admitted

        # Try to send externally — composition violation
        a2 = ProposedAction(
            action_type="external_send",
            target_resource="mcp:email-external",
            parameters={"to": "leak@evil.com", "body": "secret data"},
            actor_principal_id="user:legal-analyst",
            task_session_id="cs1-session",
            policy_version="1.0",
            sensitivity_class="confidential",
            blast_radius=0.1,
        )
        d2 = self.pdp.evaluate(a2, self.user_env, budget, checker)
        assert not d2.admitted

    def test_irreversible_effects_blocked(self):
        """ρ_max = 0 means no irreversible actions allowed."""
        budget = BudgetState(spec=self.budget_spec)
        checker = CompositionChecker(
            restrictions=self.agent_env.effective_scope.composition_restrictions,
        )
        action = ProposedAction(
            action_type="document_read",
            target_resource="mcp:doc-retrieval",
            parameters={"doc_id": "x"},
            actor_principal_id="agent:doc-processor",
            task_session_id="cs1-session",
            policy_version="1.0",
            sensitivity_class="public",
            irreversible_effects=1,  # ρ_max = 0, this should fail
        )
        decision = self.pdp.evaluate(action, self.agent_env, budget, checker)
        assert not decision.admitted

    def test_evidence_trail(self):
        """Every admitted action produces an evidence package."""
        budget = BudgetState(spec=self.budget_spec)
        checker = CompositionChecker(
            restrictions=self.agent_env.effective_scope.composition_restrictions,
        )
        for i in range(3):
            action = ProposedAction(
                action_type="document_read",
                target_resource="mcp:doc-retrieval",
                parameters={"doc_id": f"contract-{i}"},
                actor_principal_id="agent:doc-processor",
                task_session_id="cs1-session",
                policy_version="1.0",
                sensitivity_class="internal",
                blast_radius=0.05,
            )
            self.pdp.evaluate(action, self.agent_env, budget, checker)

        assert len(self.sink.packages) == 3


class TestCaseStudyII:
    """Case Study II: Multi-Agent DevOps Pipeline.

    Orchestrator → Planning Agent → Security Review Agent → Deployment Agent.
    Each hop narrows scope. Deployment requires approval token.
    """

    def setup_method(self):
        self.user = Principal(
            "user:devops-lead",
            ExecutionRole.AS_USER,
            Scope(
                resources=frozenset({"infra:terraform", "infra:cloud-api",
                                     "infra:security-scan", "infra:deploy"}),
                actions=frozenset({"plan", "review", "deploy", "scan"}),
                data_classifications=frozenset({"internal", "confidential"}),
                composition_restrictions=frozenset(),
            ),
        )
        self.orchestrator = Principal(
            "agent:orchestrator",
            ExecutionRole.ON_BEHALF_OF,
            Scope(
                resources=frozenset({"infra:terraform", "infra:cloud-api",
                                     "infra:security-scan", "infra:deploy"}),
                actions=frozenset({"plan", "review", "deploy", "scan"}),
                data_classifications=frozenset({"internal", "confidential"}),
            ),
        )
        self.planner = Principal(
            "agent:planner",
            ExecutionRole.AS_AGENT,
            Scope(
                resources=frozenset({"infra:terraform"}),
                actions=frozenset({"plan"}),
                data_classifications=frozenset({"internal"}),
            ),
        )
        self.reviewer = Principal(
            "agent:security-reviewer",
            ExecutionRole.AS_AGENT,
            Scope(
                resources=frozenset({"infra:security-scan", "infra:terraform"}),
                actions=frozenset({"scan", "review"}),
                data_classifications=frozenset({"internal", "confidential"}),
            ),
        )
        self.deployer = Principal(
            "agent:deployer",
            ExecutionRole.AS_AGENT,
            Scope(
                resources=frozenset({"infra:deploy", "infra:cloud-api"}),
                actions=frozenset({"deploy"}),
                data_classifications=frozenset({"internal"}),
            ),
        )
        self.budget_spec = DelegationBudgetSpec(
            max_delegation_depth=4,
            max_blast_radius=0.8,
            max_irreversible_effects=1,
            max_sensitivity_class="confidential",
            cross_domain_composition=False,
            max_cost=200.0,
        )
        self.store = ApprovalStore()
        self.sink = EvidenceSink()
        self.pdp = PolicyDecisionPoint(
            signing_key=KEY,
            impact_weights=ImpactWeights(0.5, 0.3, 0.2),
            approval_threshold=0.4,
            approval_store=self.store,
            evidence_sink=self.sink,
        )

        # Build the chain
        root_env = AuthorizationEnvelope(
            envelope_id="cs2-env",
            task_session_id="cs2-session",
            originating_principal=self.user,
            effective_scope=self.user.role_scope,
            budget_spec=self.budget_spec,
            expires_at=time.time() + 3600,
        )
        root_env.sign(KEY)
        self.root_env = root_env
        self.orch_env = root_env.narrow(self.orchestrator, KEY)
        self.plan_env = self.orch_env.narrow(self.planner, KEY)
        self.review_env = self.orch_env.narrow(self.reviewer, KEY)
        self.deploy_env = self.orch_env.narrow(self.deployer, KEY)

    def test_chain_depth(self):
        assert self.root_env.delegation_depth == 0
        assert self.orch_env.delegation_depth == 1
        assert self.plan_env.delegation_depth == 2
        assert self.deploy_env.delegation_depth == 2

    def test_blast_radius_monotonicity_full_chain(self):
        assert verify_blast_radius_monotonicity(self.root_env, self.orch_env)
        assert verify_blast_radius_monotonicity(self.orch_env, self.plan_env)
        assert verify_blast_radius_monotonicity(self.orch_env, self.deploy_env)

    def test_planner_cannot_deploy(self):
        budget = BudgetState(spec=self.budget_spec)
        checker = CompositionChecker(restrictions=frozenset())

        action = ProposedAction(
            action_type="deploy",
            target_resource="infra:deploy",
            parameters={"plan_id": "tf-plan-001"},
            actor_principal_id="agent:planner",
            task_session_id="cs2-session",
            policy_version="1.0",
            sensitivity_class="internal",
        )
        decision = self.pdp.evaluate(action, self.plan_env, budget, checker)
        assert not decision.admitted  # deploy not in planner's scope

    def test_deploy_requires_approval(self):
        budget = BudgetState(spec=self.budget_spec)
        checker = CompositionChecker(restrictions=frozenset())

        action = ProposedAction(
            action_type="deploy",
            target_resource="infra:deploy",
            parameters={"plan_id": "tf-plan-001"},
            actor_principal_id="agent:deployer",
            task_session_id="cs2-session",
            policy_version="1.0",
            sensitivity_class="internal",
            irreversibility_score=0.9,
            blast_radius_score=0.7,
            sensitivity_score=0.5,
            irreversible_effects=1,
            blast_radius=0.3,
        )
        # Without approval token
        d1 = self.pdp.evaluate(action, self.deploy_env, budget, checker)
        assert not d1.admitted

        # With approval token
        params = {"plan_id": "tf-plan-001"}
        self.store.issue(
            token_id="deploy-tok-1",
            action_type="deploy",
            target_resource="infra:deploy",
            parameters=params,
            scope_snapshot={},
            approver_id="user:devops-lead",
            policy_version="1.0",
            task_session_id="cs2-session",
        )
        d2 = self.pdp.evaluate(
            action, self.deploy_env, budget, checker,
            approval_token_id="deploy-tok-1",
        )
        assert d2.admitted

    def test_full_pipeline_evidence_trail(self):
        """Plan → Review → Deploy produces 3 evidence packages."""
        budget = BudgetState(spec=self.budget_spec)
        checker = CompositionChecker(restrictions=frozenset())

        # Plan
        plan_action = ProposedAction(
            action_type="plan", target_resource="infra:terraform",
            parameters={"config": "main.tf"},
            actor_principal_id="agent:planner",
            task_session_id="cs2-session", policy_version="1.0",
            sensitivity_class="internal", blast_radius=0.1,
        )
        self.pdp.evaluate(plan_action, self.plan_env, budget, checker)

        # Review
        review_checker = CompositionChecker(restrictions=frozenset())
        review_budget = BudgetState(spec=self.budget_spec)
        review_action = ProposedAction(
            action_type="scan", target_resource="infra:security-scan",
            parameters={"plan_id": "tf-plan-001"},
            actor_principal_id="agent:security-reviewer",
            task_session_id="cs2-session", policy_version="1.0",
            sensitivity_class="internal", blast_radius=0.05,
        )
        self.pdp.evaluate(review_action, self.review_env, review_budget, review_checker)

        # Deploy (with approval)
        deploy_checker = CompositionChecker(restrictions=frozenset())
        deploy_budget = BudgetState(spec=self.budget_spec)
        deploy_params = {"plan_id": "tf-plan-001"}
        self.store.issue(
            token_id="deploy-tok-2",
            action_type="deploy", target_resource="infra:deploy",
            parameters=deploy_params, scope_snapshot={},
            approver_id="user:devops-lead", policy_version="1.0",
            task_session_id="cs2-session",
        )
        deploy_action = ProposedAction(
            action_type="deploy", target_resource="infra:deploy",
            parameters=deploy_params,
            actor_principal_id="agent:deployer",
            task_session_id="cs2-session", policy_version="1.0",
            sensitivity_class="internal",
            irreversibility_score=0.9, blast_radius_score=0.7, sensitivity_score=0.5,
            irreversible_effects=1, blast_radius=0.3,
        )
        self.pdp.evaluate(
            deploy_action, self.deploy_env, deploy_budget, deploy_checker,
            approval_token_id="deploy-tok-2",
        )

        assert len(self.sink.packages) == 3
