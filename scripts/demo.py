"""
Bounded Agents -- APC Reference Implementation Demo
====================================================
Demonstrates every formal claim from the paper as executable code.

  python scripts/demo.py

No dependencies beyond Python 3.11+.

Paper: "Bounded Agents: Delegation Security for Multi-Agent AI Systems"
       Xabier Muruaga, 2026. arXiv:2608.15888
       https://arxiv.org/abs/2608.15888

Paper-to-demo mapping:
  S4 Definition 4.1 (Scope)           -> Section 1 (Scope Algebra)
  S4 Definition 4.2 (Principal Chain)  -> Section 2 (Delegation Chain)
  S4 Theorem 4.1 (BR Monotonicity)    -> Section 2 (Blast Radius)
  S5 Condition 1 (Identity)           -> Section 3 (Identity Binding)
  S5 Condition 2 (Scope+Comp)         -> Section 4 (Composition Closure / Theorem 5.1)
  S5 Condition 3 (Context)            -> Section 5 (Context Binding)
  S5 Condition 4 (Approval)           -> Section 6 (Approval Binding)
  S5 Condition 5 (Evidence)           -> Section 7 (Evidence Commitment / Rule 7)
  S5 Condition 6 (Intent)             -> Section 8 (Intent Binding / Proposition 5.1)
  S4 Definition 4.3 (Budget)          -> Section 9 (Delegation Budget)
  S7 Case Study I                     -> Section 10 (MCP Document Processing)
  S7 Case Study II                    -> Section 11 (Multi-Agent DevOps Pipeline)
  Appendix A.6 Worked Example         -> Section 12 (Worked Example)
"""
import sys
import time
from pathlib import Path

# Run from a fresh clone without installing the package first.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from apc.core import (
    Scope, Principal, ExecutionRole,
    AuthorizationEnvelope, DelegationBudgetSpec,
    ResourceBlastProfile,
    blast_radius_max, verify_blast_radius_monotonicity,
)
from apc.budget import BudgetState, ActionCost
from apc.compose import CompositionChecker, ActionClassMapping
from apc.approval import ApprovalStore, compute_action_hash
from apc.calibrate import ImpactWeights
from apc.intent import IntentSpec, IntentChecker, IntentEnforcementMode
from apc.pdp import PolicyDecisionPoint, ProposedAction, EvidenceSink

KEY = b"infrastructure-signing-key"
SEP = "=" * 72


def section(title: str) -> None:
    print(f"\n{SEP}")
    print(f"  {title}")
    print(SEP)


def result_line(label: str, decision) -> None:
    tag = "ADMITTED" if decision.admitted else f"DENIED ({', '.join(decision.denial_reasons)})"
    print(f"  {label:.<56s} {tag}")


# =========================================================================
# 1. SCOPE ALGEBRA -- S4, Definition 4.1
# =========================================================================
section("1. Scope Algebra -- Definition 4.1 (S4)")

s_user = Scope(
    resources=frozenset({"docs:*", "email:internal", "email:external"}),
    actions=frozenset({"read", "write", "send"}),
    data_classifications=frozenset({"public", "confidential"}),
    composition_restrictions=frozenset({("read", "send")}),
)
s_agent = Scope(
    resources=frozenset({"docs:*", "email:internal"}),
    actions=frozenset({"read", "summarize"}),
    data_classifications=frozenset({"public", "confidential"}),
    composition_restrictions=frozenset({("write", "send")}),
)
s_effective = s_user.meet(s_agent)

print(f"  User scope S_1:")
print(f"    R = {sorted(s_user.resources)}")
print(f"    A = {sorted(s_user.actions)}")
print(f"    X = {s_user.composition_restrictions}")
print(f"  Agent role scope S_2:")
print(f"    R = {sorted(s_agent.resources)}")
print(f"    A = {sorted(s_agent.actions)}")
print(f"    X = {s_agent.composition_restrictions}")
print(f"  Effective scope S_1 meet S_2:")
print(f"    R = {sorted(s_effective.resources)}  (intersection)")
print(f"    A = {sorted(s_effective.actions)}  (intersection)")
print(f"    X = {s_effective.composition_restrictions}  (union -- only grows)")
print()
print(f"  S_1 meet S_2 <= S_1? {s_effective.is_subset_of(s_user)}")
print(f"  S_1 meet S_2 <= S_2? {s_effective.is_subset_of(s_agent)}")

assert s_user.meet(s_agent) == s_agent.meet(s_user), "commutativity"
assert s_effective.meet(s_effective) == s_effective, "idempotency"
print("  Commutativity: OK   Idempotency: OK")


# =========================================================================
# 2. DELEGATION CHAIN + BLAST RADIUS -- S4, Definition 4.2, Theorem 4.1
# =========================================================================
section("2. Delegation Chain + Blast Radius -- Definition 4.2, Theorem 4.1")

user = Principal("user:alice", ExecutionRole.AS_USER, s_user)
agent = Principal("agent:doc-processor", ExecutionRole.ON_BEHALF_OF, s_agent)
sub_agent = Principal("agent:summarizer", ExecutionRole.AS_AGENT, Scope(
    resources=frozenset({"docs:*"}),
    actions=frozenset({"read"}),
    data_classifications=frozenset({"public"}),
))

budget_spec = DelegationBudgetSpec(
    max_delegation_depth=3, max_blast_radius=0.5,
    max_irreversible_effects=2, max_sensitivity_class="confidential",
    cross_domain_composition=False, max_cost=100.0,
)

env_root = AuthorizationEnvelope(
    "env-demo", "session-demo", user, user.role_scope, budget_spec,
    expires_at=time.time() + 3600,
)
env_root.sign(KEY)
env_agent = env_root.narrow(agent, KEY)
env_sub = env_agent.narrow(sub_agent, KEY)

print(f"  Chain: {' -> '.join(p.principal_id for p in env_sub.chain)}")
print(f"  Depth: {env_sub.delegation_depth}")
print(f"  BR(root)  = {sorted(blast_radius_max(env_root))}")
print(f"  BR(agent) = {sorted(blast_radius_max(env_agent))}")
print(f"  BR(sub)   = {sorted(blast_radius_max(env_sub))}")
print(f"  BR monotonicity root->agent: {verify_blast_radius_monotonicity(env_root, env_agent)}")
print(f"  BR monotonicity agent->sub:  {verify_blast_radius_monotonicity(env_agent, env_sub)}")
print(f"  BR monotonicity root->sub:   {verify_blast_radius_monotonicity(env_root, env_sub)}")

assert verify_blast_radius_monotonicity(env_root, env_agent)
assert verify_blast_radius_monotonicity(env_agent, env_sub)
assert verify_blast_radius_monotonicity(env_root, env_sub)
assert blast_radius_max(env_sub) <= blast_radius_max(env_agent) <= blast_radius_max(env_root)

# Definition 4.5: BR_max with per-resource blast weights
res_profile = ResourceBlastProfile.from_dict({
    "docs:*": 0.05,
    "email:internal": 0.15,
    "email:external": 0.80,
})
print()
print(f"  Per-resource blast weights (Definition 4.5):")
print(f"    blast(docs:*)          = {res_profile.blast('docs:*')}")
print(f"    blast(email:internal)  = {res_profile.blast('email:internal')}")
print(f"    blast(email:external)  = {res_profile.blast('email:external')}")
print(f"  With beta_remaining = 0.20:")
br_budget = blast_radius_max(env_root, res_profile, budget_remaining=0.20)
print(f"    BR_max(root, beta=0.20) = {sorted(br_budget)}")
print(f"    email:external (0.80) excluded -- exceeds remaining budget")
assert "email:external" not in br_budget
assert "docs:*" in br_budget


# =========================================================================
# 3. IDENTITY BINDING -- S5, Condition 1
# =========================================================================
section("3. Identity Binding -- Condition 1 (S5)")

store = ApprovalStore()
sink = EvidenceSink()
pdp = PolicyDecisionPoint(
    signing_key=KEY, impact_weights=ImpactWeights(0.4, 0.3, 0.3),
    approval_threshold=0.5, approval_store=store, evidence_sink=sink,
)
budget = BudgetState(spec=budget_spec)
checker = CompositionChecker(restrictions=frozenset())

# Actor in chain — admitted
a_ok = ProposedAction(
    action_type="read", target_resource="docs:*",
    parameters={"doc": "contract.pdf"}, actor_principal_id="agent:doc-processor",
    task_session_id="session-demo", policy_version="1.0",
    sensitivity_class="public", blast_radius=0.05,
)
d_ok = pdp.evaluate(a_ok, env_agent, budget, checker)
result_line("Actor in chain (agent:doc-processor)", d_ok)
assert d_ok.admitted

# Actor NOT in chain — denied
budget2 = BudgetState(spec=budget_spec)
checker2 = CompositionChecker(restrictions=frozenset())
a_bad = ProposedAction(
    action_type="read", target_resource="docs:*",
    parameters={}, actor_principal_id="agent:evil",
    task_session_id="session-demo", policy_version="1.0",
    sensitivity_class="public",
)
d_bad = pdp.evaluate(a_bad, env_agent, budget2, checker2)
result_line("Actor NOT in chain (agent:evil)", d_bad)
assert not d_bad.admitted

# Tampered envelope — denied
env_tampered = AuthorizationEnvelope(
    "env-tampered", "session-demo", user, user.role_scope, budget_spec,
    expires_at=time.time() + 3600,
)
env_tampered.sign(KEY)
# Bypass seal to simulate attacker tampering with memory
object.__setattr__(env_tampered, 'effective_scope', Scope(
    frozenset({"docs:*", "db:production"}), frozenset({"read", "delete"}),
    frozenset({"public", "regulated"}),
))
budget3 = BudgetState(spec=budget_spec)
checker3 = CompositionChecker(restrictions=frozenset())
a_tamper = ProposedAction(
    action_type="read", target_resource="docs:*",
    parameters={}, actor_principal_id="user:alice",
    task_session_id="session-demo", policy_version="1.0",
    sensitivity_class="public",
)
d_tamper = pdp.evaluate(a_tamper, env_tampered, budget3, checker3)
result_line("Tampered envelope (signature invalid)", d_tamper)
assert not d_tamper.admitted


# =========================================================================
# 4. COMPOSITION CLOSURE -- S5, Condition 2b / Theorem 5.1
# =========================================================================
section("4. Composition Closure -- Condition 2b, Theorem 5.1")

comp_scope = Scope(
    resources=frozenset({"docs:confidential", "email:external"}),
    actions=frozenset({"read", "send"}),
    data_classifications=frozenset({"confidential"}),
    composition_restrictions=frozenset({("read", "send")}),
)
comp_user = Principal("user:analyst", ExecutionRole.AS_USER, comp_scope)
comp_env = AuthorizationEnvelope(
    "env-comp", "session-comp", comp_user, comp_scope, budget_spec,
    expires_at=time.time() + 3600,
)
comp_env.sign(KEY)

store4 = ApprovalStore()
sink4 = EvidenceSink()
pdp4 = PolicyDecisionPoint(
    signing_key=KEY, impact_weights=ImpactWeights(0.4, 0.3, 0.3),
    approval_threshold=0.5, approval_store=store4, evidence_sink=sink4,
)
budget4 = BudgetState(spec=budget_spec)
checker4 = CompositionChecker(restrictions=comp_scope.composition_restrictions)

read_action = ProposedAction(
    action_type="read", target_resource="docs:confidential",
    parameters={"doc": "merger-plan.pdf"}, actor_principal_id="user:analyst",
    task_session_id="session-comp", policy_version="1.0",
    sensitivity_class="confidential", blast_radius=0.05,
)
d_read = pdp4.evaluate(read_action, comp_env, budget4, checker4)
result_line("Step 1: read confidential doc", d_read)
assert d_read.admitted

send_action = ProposedAction(
    action_type="send", target_resource="email:external",
    parameters={"to": "external@example.com"}, actor_principal_id="user:analyst",
    task_session_id="session-comp", policy_version="1.0",
    sensitivity_class="confidential", blast_radius=0.1,
)
d_send = pdp4.evaluate(send_action, comp_env, budget4, checker4)
result_line("Step 2: send externally (composition violation)", d_send)
assert not d_send.admitted
print(f"  Violation: (read, send) in X -- exfiltration blocked")


# =========================================================================
# 5. CONTEXT BINDING -- S5, Condition 3
# =========================================================================
section("5. Context Binding -- Condition 3 (S5)")

ctx_user = Principal("user:bob", ExecutionRole.AS_USER, Scope(
    frozenset({"docs:x"}), frozenset({"read"}), frozenset({"public"}),
))
ctx_spec = DelegationBudgetSpec(3, 1.0, 5, "confidential", True, 100.0)
ctx_env = AuthorizationEnvelope(
    "env-ctx", "session-ctx", ctx_user, ctx_user.role_scope, ctx_spec,
    expires_at=time.time() + 3600,
)
ctx_env.sign(KEY)

store5 = ApprovalStore()
sink5 = EvidenceSink()
pdp5 = PolicyDecisionPoint(
    signing_key=KEY, impact_weights=ImpactWeights(0.4, 0.3, 0.3),
    approval_threshold=0.5, approval_store=store5, evidence_sink=sink5,
)

# Correct session — admitted
budget5a = BudgetState(spec=ctx_spec)
checker5a = CompositionChecker(restrictions=frozenset())
a_ctx_ok = ProposedAction(
    action_type="read", target_resource="docs:x", parameters={},
    actor_principal_id="user:bob", task_session_id="session-ctx",
    policy_version="1.0", sensitivity_class="public",
)
d_ctx_ok = pdp5.evaluate(a_ctx_ok, ctx_env, budget5a, checker5a)
result_line("Correct session + policy version", d_ctx_ok)
assert d_ctx_ok.admitted

# Wrong session — denied (anti-replay)
budget5b = BudgetState(spec=ctx_spec)
checker5b = CompositionChecker(restrictions=frozenset())
a_ctx_bad = ProposedAction(
    action_type="read", target_resource="docs:x", parameters={},
    actor_principal_id="user:bob", task_session_id="different-session",
    policy_version="1.0", sensitivity_class="public",
)
d_ctx_bad = pdp5.evaluate(a_ctx_bad, ctx_env, budget5b, checker5b)
result_line("Wrong session_id (anti-replay)", d_ctx_bad)
assert not d_ctx_bad.admitted

# Wrong policy version — denied
budget5c = BudgetState(spec=ctx_spec)
checker5c = CompositionChecker(restrictions=frozenset())
a_ctx_ver = ProposedAction(
    action_type="read", target_resource="docs:x", parameters={},
    actor_principal_id="user:bob", task_session_id="session-ctx",
    policy_version="2.0", sensitivity_class="public",
)
d_ctx_ver = pdp5.evaluate(a_ctx_ver, ctx_env, budget5c, checker5c)
result_line("Wrong policy_version", d_ctx_ver)
assert not d_ctx_ver.admitted


# =========================================================================
# 6. APPROVAL BINDING -- S5, Condition 4
# =========================================================================
section("6. Approval Binding -- Condition 4 (S5)")

appr_user = Principal("user:admin", ExecutionRole.AS_USER, Scope(
    frozenset({"db:prod"}), frozenset({"delete"}), frozenset({"confidential"}),
))
appr_spec = DelegationBudgetSpec(3, 1.0, 5, "confidential", True, 100.0)
appr_env = AuthorizationEnvelope(
    "env-appr", "session-appr", appr_user, appr_user.role_scope, appr_spec,
    expires_at=time.time() + 3600,
)
appr_env.sign(KEY)

store6 = ApprovalStore()
sink6 = EvidenceSink()
pdp6 = PolicyDecisionPoint(
    signing_key=KEY, impact_weights=ImpactWeights(0.4, 0.3, 0.3),
    approval_threshold=0.3, approval_store=store6, evidence_sink=sink6,
)

params_del = {"table": "users"}
high_impact = ProposedAction(
    action_type="delete", target_resource="db:prod", parameters=params_del,
    actor_principal_id="user:admin", task_session_id="session-appr",
    policy_version="1.0", sensitivity_class="confidential",
    irreversibility_score=1.0, blast_radius_score=0.8, sensitivity_score=0.9,
)

# Without approval — denied
budget6a = BudgetState(spec=appr_spec)
checker6a = CompositionChecker(restrictions=frozenset())
d_no_tok = pdp6.evaluate(high_impact, appr_env, budget6a, checker6a)
result_line("High-impact delete WITHOUT approval token", d_no_tok)
assert not d_no_tok.admitted

# With valid approval — admitted
token = store6.issue(
    token_id="tok-demo-1", action_type="delete", target_resource="db:prod",
    parameters=params_del, scope_snapshot={}, approver_id="user:ciso",
    policy_version="1.0", task_session_id="session-appr",
)
budget6b = BudgetState(spec=appr_spec)
checker6b = CompositionChecker(restrictions=frozenset())
d_with_tok = pdp6.evaluate(
    high_impact, appr_env, budget6b, checker6b, approval_token_id="tok-demo-1",
)
result_line("High-impact delete WITH approval token", d_with_tok)
assert d_with_tok.admitted
print(f"  Token consumed: {not store6.get('tok-demo-1').is_valid}")


# =========================================================================
# 7. EVIDENCE COMMITMENT -- S5, Condition 5 / Rule 7
# =========================================================================
section("7. Evidence Commitment -- Condition 5, Rule 7")

ev_user = Principal("user:bob", ExecutionRole.AS_USER, Scope(
    frozenset({"docs:x"}), frozenset({"read"}), frozenset({"public"}),
))
ev_spec = DelegationBudgetSpec(3, 1.0, 5, "confidential", True, 100.0)
ev_env = AuthorizationEnvelope(
    "env-ev", "session-ev", ev_user, ev_user.role_scope, ev_spec,
    expires_at=time.time() + 3600,
)
ev_env.sign(KEY)

# Evidence sink available — action admitted, evidence committed
sink7a = EvidenceSink()
store7a = ApprovalStore()
pdp7a = PolicyDecisionPoint(
    signing_key=KEY, impact_weights=ImpactWeights(0.4, 0.3, 0.3),
    approval_threshold=0.5, approval_store=store7a, evidence_sink=sink7a,
)
budget7a = BudgetState(spec=ev_spec)
checker7a = CompositionChecker(restrictions=frozenset())
a_ev = ProposedAction(
    action_type="read", target_resource="docs:x", parameters={},
    actor_principal_id="user:bob", task_session_id="session-ev",
    policy_version="1.0", sensitivity_class="public",
)
d_ev = pdp7a.evaluate(a_ev, ev_env, budget7a, checker7a)
result_line("Evidence sink available", d_ev)
assert d_ev.admitted
print(f"  Evidence packages committed: {len(sink7a.packages)}")
assert len(sink7a.packages) == 1

# Evidence sink unavailable — action denied (Rule 7)
sink7b = EvidenceSink()
sink7b.set_available(False)
store7b = ApprovalStore()
pdp7b = PolicyDecisionPoint(
    signing_key=KEY, impact_weights=ImpactWeights(0.4, 0.3, 0.3),
    approval_threshold=0.5, approval_store=store7b, evidence_sink=sink7b,
)
budget7b = BudgetState(spec=ev_spec)
checker7b = CompositionChecker(restrictions=frozenset())
d_ev_down = pdp7b.evaluate(a_ev, ev_env, budget7b, checker7b)
result_line("Evidence sink UNAVAILABLE (Rule 7)", d_ev_down)
assert not d_ev_down.admitted


# =========================================================================
# 8. INTENT BINDING -- S5, Condition 6 / Proposition 5.1
# =========================================================================
section("8. Intent Binding -- Condition 6, Proposition 5.1")

intent_user = Principal("user:analyst", ExecutionRole.AS_USER, Scope(
    frozenset({"docs:contracts/acme", "docs:personnel/ceo"}),
    frozenset({"read", "summarize"}),
    frozenset({"confidential"}),
))
intent_spec_budget = DelegationBudgetSpec(3, 1.0, 5, "confidential", True, 100.0)
intent_env = AuthorizationEnvelope(
    "env-intent", "session-intent", intent_user, intent_user.role_scope,
    intent_spec_budget, expires_at=time.time() + 3600,
)
intent_env.sign(KEY)

intent = IntentSpec(
    task_objective="Summarize the Acme contract",
    permitted_resource_patterns=("docs:contracts/*",),
    permitted_action_sequences=("read", "summarize"),
    enforcement_mode=IntentEnforcementMode.STRICT,
)
intent_checker = IntentChecker(intent_spec=intent)

store8 = ApprovalStore()
sink8 = EvidenceSink()
pdp8 = PolicyDecisionPoint(
    signing_key=KEY, impact_weights=ImpactWeights(0.4, 0.3, 0.3),
    approval_threshold=0.5, approval_store=store8, evidence_sink=sink8,
)

# Within scope AND intent — admitted
budget8a = BudgetState(spec=intent_spec_budget)
checker8a = CompositionChecker(restrictions=frozenset())
a_intent_ok = ProposedAction(
    action_type="read", target_resource="docs:contracts/acme",
    parameters={}, actor_principal_id="user:analyst",
    task_session_id="session-intent", policy_version="1.0",
    sensitivity_class="confidential", blast_radius=0.05,
)
d_intent_ok = pdp8.evaluate(
    a_intent_ok, intent_env, budget8a, checker8a, intent_checker=intent_checker,
)
result_line("Within scope AND intent (contracts)", d_intent_ok)
assert d_intent_ok.admitted

# Within scope but OUTSIDE intent — denied
budget8b = BudgetState(spec=intent_spec_budget)
checker8b = CompositionChecker(restrictions=frozenset())
a_intent_bad = ProposedAction(
    action_type="read", target_resource="docs:personnel/ceo",
    parameters={}, actor_principal_id="user:analyst",
    task_session_id="session-intent", policy_version="1.0",
    sensitivity_class="confidential", blast_radius=0.05,
)
d_intent_bad = pdp8.evaluate(
    a_intent_bad, intent_env, budget8b, checker8b, intent_checker=intent_checker,
)
result_line("Within scope but OUTSIDE intent (personnel)", d_intent_bad)
assert not d_intent_bad.admitted
print(f"  Intent defines inner boundary; scope defines outer boundary")


# =========================================================================
# 9. DELEGATION BUDGET -- S4, Definition 4.3
# =========================================================================
section("9. Delegation Budget -- Definition 4.3 (S4)")

budget9_spec = DelegationBudgetSpec(
    max_delegation_depth=3, max_blast_radius=0.3,
    max_irreversible_effects=2, max_sensitivity_class="confidential",
    cross_domain_composition=False, max_cost=100.0,
)
budget9 = BudgetState(spec=budget9_spec)

print(f"  Budget spec: BR_max={budget9_spec.max_blast_radius}, "
      f"rho_max={budget9_spec.max_irreversible_effects}, "
      f"cost_max={budget9_spec.max_cost}")

# Consume incrementally
for i in range(6):
    cost = ActionCost(blast_radius=0.05, compute_cost=10.0)
    result = budget9.consume(cost)
    status = "OK" if result.allowed else "OVER BUDGET"
    print(f"  Action {i+1}: BR+=0.05, cost+=10.0 -> "
          f"cumBR={budget9.cumulative_blast_radius:.2f}, "
          f"cumCost={budget9.cumulative_cost:.1f} [{status}]")

print(f"  Budget exhausted: {budget9.is_exhausted}")
print(f"  Remaining BR: {budget9.remaining_blast_radius:.2f}")
print(f"  Remaining cost: {budget9.remaining_cost:.1f}")

# 7th action should fail
cost_over = ActionCost(blast_radius=0.05)
result_over = budget9.check(cost_over)
print(f"  7th action (BR=0.05): {'ALLOWED' if result_over.allowed else 'DENIED'}")
assert not result_over.allowed


# =========================================================================
# 10. CASE STUDY I -- MCP Document Processing (S7)
# =========================================================================
section("10. Case Study I -- MCP Document Processing (S7)")

cs1_user = Principal("user:legal-analyst", ExecutionRole.AS_USER, Scope(
    resources=frozenset({"mcp:doc-retrieval", "mcp:metadata-search",
                         "mcp:pdf-extract", "mcp:email-external"}),
    actions=frozenset({"document_read", "metadata_search",
                       "pdf_extract", "external_send"}),
    data_classifications=frozenset({"public", "internal", "confidential"}),
    composition_restrictions=frozenset({
        ("document_read", "external_send"),
        ("pdf_extract", "external_send"),
    }),
))
cs1_agent = Principal("agent:doc-processor", ExecutionRole.ON_BEHALF_OF, Scope(
    resources=frozenset({"mcp:doc-retrieval", "mcp:metadata-search", "mcp:pdf-extract"}),
    actions=frozenset({"document_read", "metadata_search", "pdf_extract"}),
    data_classifications=frozenset({"public", "internal", "confidential"}),
))
cs1_spec = DelegationBudgetSpec(
    max_delegation_depth=2, max_blast_radius=0.3,
    max_irreversible_effects=0, cross_domain_composition=False,
    max_sensitivity_class="confidential", max_cost=50.0,
)

cs1_env = AuthorizationEnvelope(
    "cs1-env", "cs1-session", cs1_user, cs1_user.role_scope, cs1_spec,
    expires_at=time.time() + 3600,
)
cs1_env.sign(KEY)
cs1_agent_env = cs1_env.narrow(cs1_agent, KEY)

print(f"  Agent scope narrowed:")
print(f"    Resources: {sorted(cs1_agent_env.effective_scope.resources)}")
print(f"    Actions:   {sorted(cs1_agent_env.effective_scope.actions)}")
print(f"    email-external in scope? {'mcp:email-external' in cs1_agent_env.effective_scope.resources}")

store10 = ApprovalStore()
sink10 = EvidenceSink()
pdp10 = PolicyDecisionPoint(
    signing_key=KEY, impact_weights=ImpactWeights(0.4, 0.3, 0.3),
    approval_threshold=0.5, approval_store=store10, evidence_sink=sink10,
)
budget10 = BudgetState(spec=cs1_spec)
checker10 = CompositionChecker(restrictions=cs1_agent_env.effective_scope.composition_restrictions)

a_doc = ProposedAction(
    action_type="document_read", target_resource="mcp:doc-retrieval",
    parameters={"doc_id": "contract-2024-001"},
    actor_principal_id="agent:doc-processor",
    task_session_id="cs1-session", policy_version="1.0",
    sensitivity_class="confidential", blast_radius=0.05,
)
d_doc = pdp10.evaluate(a_doc, cs1_agent_env, budget10, checker10)
result_line("Document read (within scope)", d_doc)
assert d_doc.admitted

a_send = ProposedAction(
    action_type="external_send", target_resource="mcp:email-external",
    parameters={"to": "attacker@evil.com"},
    actor_principal_id="agent:doc-processor",
    task_session_id="cs1-session", policy_version="1.0",
    sensitivity_class="confidential",
)
d_send = pdp10.evaluate(a_send, cs1_agent_env, budget10, checker10)
result_line("External send (scope blocks)", d_send)
assert not d_send.admitted
print(f"  Exfiltration blocked by scope narrowing + composition closure")


# =========================================================================
# 11. CASE STUDY II -- Multi-Agent DevOps Pipeline (S7)
# =========================================================================
section("11. Case Study II -- Multi-Agent DevOps Pipeline (S7)")

cs2_user = Principal("user:devops-lead", ExecutionRole.AS_USER, Scope(
    resources=frozenset({"infra:terraform", "infra:cloud-api",
                         "infra:security-scan", "infra:deploy"}),
    actions=frozenset({"plan", "review", "deploy", "scan"}),
    data_classifications=frozenset({"internal", "confidential"}),
))
cs2_orch = Principal("agent:orchestrator", ExecutionRole.ON_BEHALF_OF, Scope(
    resources=frozenset({"infra:terraform", "infra:cloud-api",
                         "infra:security-scan", "infra:deploy"}),
    actions=frozenset({"plan", "review", "deploy", "scan"}),
    data_classifications=frozenset({"internal", "confidential"}),
))
cs2_planner = Principal("agent:planner", ExecutionRole.AS_AGENT, Scope(
    resources=frozenset({"infra:terraform"}),
    actions=frozenset({"plan"}),
    data_classifications=frozenset({"internal"}),
))
cs2_deployer = Principal("agent:deployer", ExecutionRole.AS_AGENT, Scope(
    resources=frozenset({"infra:deploy", "infra:cloud-api"}),
    actions=frozenset({"deploy"}),
    data_classifications=frozenset({"internal"}),
))

cs2_spec = DelegationBudgetSpec(
    max_delegation_depth=4, max_blast_radius=0.8,
    max_irreversible_effects=1, max_sensitivity_class="confidential",
    cross_domain_composition=False, max_cost=200.0,
)

cs2_root = AuthorizationEnvelope(
    "cs2-env", "cs2-session", cs2_user, cs2_user.role_scope, cs2_spec,
    expires_at=time.time() + 3600,
)
cs2_root.sign(KEY)
cs2_orch_env = cs2_root.narrow(cs2_orch, KEY)
cs2_plan_env = cs2_orch_env.narrow(cs2_planner, KEY)
cs2_deploy_env = cs2_orch_env.narrow(cs2_deployer, KEY)

print(f"  Chain depths: root={cs2_root.delegation_depth}, "
      f"orch={cs2_orch_env.delegation_depth}, "
      f"planner={cs2_plan_env.delegation_depth}, "
      f"deployer={cs2_deploy_env.delegation_depth}")

store11 = ApprovalStore()
sink11 = EvidenceSink()
pdp11 = PolicyDecisionPoint(
    signing_key=KEY, impact_weights=ImpactWeights(0.5, 0.3, 0.2),
    approval_threshold=0.4, approval_store=store11, evidence_sink=sink11,
)

# Planner plans — admitted
budget11a = BudgetState(spec=cs2_spec)
checker11a = CompositionChecker(restrictions=frozenset())
a_plan = ProposedAction(
    action_type="plan", target_resource="infra:terraform",
    parameters={"config": "main.tf"}, actor_principal_id="agent:planner",
    task_session_id="cs2-session", policy_version="1.0",
    sensitivity_class="internal", blast_radius=0.1,
)
d_plan = pdp11.evaluate(a_plan, cs2_plan_env, budget11a, checker11a)
result_line("Planner: plan terraform", d_plan)
assert d_plan.admitted

# Planner tries to deploy — denied (not in scope)
a_plan_deploy = ProposedAction(
    action_type="deploy", target_resource="infra:deploy",
    parameters={}, actor_principal_id="agent:planner",
    task_session_id="cs2-session", policy_version="1.0",
    sensitivity_class="internal",
)
d_plan_deploy = pdp11.evaluate(a_plan_deploy, cs2_plan_env, budget11a, checker11a)
result_line("Planner: deploy (out of scope)", d_plan_deploy)
assert not d_plan_deploy.admitted

# Deployer deploys with approval — admitted
deploy_params = {"plan_id": "tf-plan-001"}
store11.issue(
    token_id="deploy-tok", action_type="deploy", target_resource="infra:deploy",
    parameters=deploy_params, scope_snapshot={}, approver_id="user:devops-lead",
    policy_version="1.0", task_session_id="cs2-session",
)
budget11b = BudgetState(spec=cs2_spec)
checker11b = CompositionChecker(restrictions=frozenset())
a_deploy = ProposedAction(
    action_type="deploy", target_resource="infra:deploy",
    parameters=deploy_params, actor_principal_id="agent:deployer",
    task_session_id="cs2-session", policy_version="1.0",
    sensitivity_class="internal",
    irreversibility_score=0.9, blast_radius_score=0.7, sensitivity_score=0.5,
    irreversible_effects=1, blast_radius=0.3,
)
d_deploy = pdp11.evaluate(
    a_deploy, cs2_deploy_env, budget11b, checker11b,
    approval_token_id="deploy-tok",
)
result_line("Deployer: deploy with approval", d_deploy)
assert d_deploy.admitted
print(f"  Evidence trail: {len(sink11.packages)} packages committed")


# =========================================================================
# 12. WORKED EXAMPLE -- Appendix A.6
# =========================================================================
section("12. Worked Example -- Appendix A.6")

print("  Scenario: HR agent reads compensation data and sends summary to HR team.")
print("  Composition restriction: (read_confidential, external_send) in X")
print("  Intent: read compensation/*, send to team-hr@company.com only")
print()

we_scope = Scope(
    resources=frozenset({"docs:compensation/bands.xlsx", "email:team-hr@company.com"}),
    actions=frozenset({"read", "send_internal"}),
    data_classifications=frozenset({"confidential"}),
    composition_restrictions=frozenset({("read_confidential", "external_send")}),
)
we_user = Principal("user:hr-manager", ExecutionRole.AS_USER, we_scope)
we_spec = DelegationBudgetSpec(2, 0.5, 1, "confidential", False, 50.0)
we_env = AuthorizationEnvelope(
    "env-we", "session-we", we_user, we_scope, we_spec,
    expires_at=time.time() + 3600,
)
we_env.sign(KEY)

we_intent = IntentSpec(
    task_objective="Summarize compensation bands and send to HR team",
    permitted_resource_patterns=("docs:compensation/*", "email:team-hr@*"),
    permitted_action_sequences=("read", "send_internal"),
    negative_constraints=("docs:personnel/*",),
    enforcement_mode=IntentEnforcementMode.STRICT,
    action_resource_map=(
        ("read", ("docs:compensation/*",)),
        ("send_internal", ("email:team-hr@company.com",)),
    ),
)
we_intent_checker = IntentChecker(intent_spec=we_intent)

store12 = ApprovalStore()
sink12 = EvidenceSink()
pdp12 = PolicyDecisionPoint(
    signing_key=KEY, impact_weights=ImpactWeights(0.4, 0.3, 0.3),
    approval_threshold=0.5, approval_store=store12, evidence_sink=sink12,
)
budget12 = BudgetState(spec=we_spec)
checker12 = CompositionChecker(restrictions=we_scope.composition_restrictions)

# Step 1: Read compensation data — admitted
a_we_read = ProposedAction(
    action_type="read", target_resource="docs:compensation/bands.xlsx",
    parameters={"format": "xlsx"}, actor_principal_id="user:hr-manager",
    task_session_id="session-we", policy_version="1.0",
    sensitivity_class="confidential", blast_radius=0.05,
)
d_we_read = pdp12.evaluate(
    a_we_read, we_env, budget12, checker12, intent_checker=we_intent_checker,
)
result_line("Step 1: read compensation data", d_we_read)
assert d_we_read.admitted

# Step 2: Send to HR team — admitted (internal, not external)
a_we_send = ProposedAction(
    action_type="send_internal", target_resource="email:team-hr@company.com",
    parameters={"body": "Q4 compensation summary"},
    actor_principal_id="user:hr-manager",
    task_session_id="session-we", policy_version="1.0",
    sensitivity_class="confidential", blast_radius=0.1,
)
d_we_send = pdp12.evaluate(
    a_we_send, we_env, budget12, checker12, intent_checker=we_intent_checker,
)
result_line("Step 2: send to HR team (internal)", d_we_send)
assert d_we_send.admitted

print(f"\n  Evidence packages: {len(sink12.packages)}")
print(f"  Budget remaining: BR={budget12.remaining_blast_radius:.2f}, "
      f"cost={budget12.remaining_cost:.1f}")

print(f"\n{SEP}")
print(f"  ALL SECTIONS PASSED")
print(SEP)

