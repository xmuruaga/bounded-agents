"""Tests for apc_core — scope algebra, envelope, blast radius."""

from apc.core import (
    AuthorizationEnvelope,
    DelegationBudgetSpec,
    ExecutionRole,
    Principal,
    ResourceBlastProfile,
    Scope,
    blast_radius_max,
    verify_blast_radius_monotonicity,
)

SIGNING_KEY = b"test-signing-key-for-reference-impl"


class TestScopeAlgebra:
    """Definition 4.1: Authorization Scope meet-semilattice."""

    def test_meet_narrows_resources(self):
        s1 = Scope(frozenset({"a", "b", "c"}), frozenset({"read"}), frozenset({"public"}))
        s2 = Scope(frozenset({"b", "c", "d"}), frozenset({"read"}), frozenset({"public"}))
        m = s1.meet(s2)
        assert m.resources == frozenset({"b", "c"})

    def test_meet_narrows_actions(self):
        s1 = Scope(frozenset({"a"}), frozenset({"read", "write"}), frozenset({"public"}))
        s2 = Scope(frozenset({"a"}), frozenset({"read"}), frozenset({"public"}))
        m = s1.meet(s2)
        assert m.actions == frozenset({"read"})

    def test_meet_unions_restrictions(self):
        s1 = Scope(frozenset(), frozenset(), frozenset(), frozenset({("read", "send")}))
        s2 = Scope(frozenset(), frozenset(), frozenset(), frozenset({("write", "delete")}))
        m = s1.meet(s2)
        assert m.composition_restrictions == frozenset({("read", "send"), ("write", "delete")})

    def test_restrictions_never_shrink_on_narrowing(self):
        """Asymmetry: restrictions only grow."""
        parent = Scope(
            frozenset({"a"}), frozenset({"read"}), frozenset({"public"}),
            frozenset({("read", "send")}),
        )
        child_role = Scope(
            frozenset({"a"}), frozenset({"read"}), frozenset({"public"}),
            frozenset(),  # child has no restrictions of its own
        )
        narrowed = parent.meet(child_role)
        assert ("read", "send") in narrowed.composition_restrictions

    def test_is_subset_of(self):
        parent = Scope(frozenset({"a", "b"}), frozenset({"read", "write"}), frozenset({"public", "internal"}))
        child = Scope(frozenset({"a"}), frozenset({"read"}), frozenset({"public"}))
        assert child.is_subset_of(parent)
        assert not parent.is_subset_of(child)

    def test_bottom_is_subset_of_everything(self):
        s = Scope(frozenset({"a"}), frozenset({"read"}), frozenset({"public"}))
        assert Scope.bottom().is_subset_of(s)

    def test_meet_is_commutative(self):
        s1 = Scope(frozenset({"a", "b"}), frozenset({"read"}), frozenset({"public"}))
        s2 = Scope(frozenset({"b", "c"}), frozenset({"read", "write"}), frozenset({"public"}))
        assert s1.meet(s2) == s2.meet(s1)

    def test_meet_is_associative(self):
        s1 = Scope(frozenset({"a", "b", "c"}), frozenset({"read", "write"}), frozenset({"public"}))
        s2 = Scope(frozenset({"b", "c", "d"}), frozenset({"read"}), frozenset({"public", "internal"}))
        s3 = Scope(frozenset({"c", "d", "e"}), frozenset({"read", "delete"}), frozenset({"public"}))
        assert s1.meet(s2).meet(s3) == s1.meet(s2.meet(s3))

    def test_meet_is_idempotent(self):
        s = Scope(frozenset({"a"}), frozenset({"read"}), frozenset({"public"}))
        assert s.meet(s) == s


class TestEnvelope:
    """Authorization Envelope lifecycle."""

    def test_sign_and_verify(self, envelope):
        assert envelope.verify(SIGNING_KEY)

    def test_verify_fails_with_wrong_key(self, envelope):
        assert not envelope.verify(b"wrong-key")

    def test_narrow_produces_subset_scope(self, envelope, agent_principal):
        child = envelope.narrow(agent_principal, SIGNING_KEY)
        assert child.effective_scope.is_subset_of(envelope.effective_scope)

    def test_narrow_extends_chain(self, envelope, agent_principal):
        child = envelope.narrow(agent_principal, SIGNING_KEY)
        assert len(child.chain) == len(envelope.chain) + 1
        assert child.chain[-1] == agent_principal

    def test_narrow_inherits_restrictions(self, envelope, agent_principal):
        child = envelope.narrow(agent_principal, SIGNING_KEY)
        assert envelope.effective_scope.composition_restrictions <= child.effective_scope.composition_restrictions

    def test_delegation_depth(self, envelope, agent_principal):
        assert envelope.delegation_depth == 0
        child = envelope.narrow(agent_principal, SIGNING_KEY)
        assert child.delegation_depth == 1

    def test_child_envelope_is_signed(self, envelope, agent_principal):
        child = envelope.narrow(agent_principal, SIGNING_KEY)
        assert child.verify(SIGNING_KEY)

    def test_multi_hop_narrowing(self, envelope, agent_principal):
        sub_agent = Principal(
            principal_id="agent:sub-processor",
            role=ExecutionRole.AS_AGENT,
            role_scope=Scope(
                resources=frozenset({"docs:*"}),
                actions=frozenset({"read"}),
                data_classifications=frozenset({"public"}),
            ),
        )
        child = envelope.narrow(agent_principal, SIGNING_KEY)
        grandchild = child.narrow(sub_agent, SIGNING_KEY)
        assert grandchild.delegation_depth == 2
        assert grandchild.effective_scope.is_subset_of(child.effective_scope)
        assert grandchild.effective_scope.is_subset_of(envelope.effective_scope)


class TestBlastRadius:
    """Definition 4.5 and Theorem 4.1."""

    def test_blast_radius_bounded_by_scope(self, envelope):
        br = blast_radius_max(envelope)
        assert br == envelope.effective_scope.resources

    def test_blast_radius_monotonicity(self, envelope, agent_principal):
        child = envelope.narrow(agent_principal, SIGNING_KEY)
        assert verify_blast_radius_monotonicity(envelope, child)

    def test_blast_radius_monotonicity_multi_hop(self, envelope, agent_principal):
        sub_agent = Principal(
            principal_id="agent:sub",
            role=ExecutionRole.AS_AGENT,
            role_scope=Scope(
                resources=frozenset({"docs:*"}),
                actions=frozenset({"read"}),
                data_classifications=frozenset({"public"}),
            ),
        )
        child = envelope.narrow(agent_principal, SIGNING_KEY)
        grandchild = child.narrow(sub_agent, SIGNING_KEY)

        assert verify_blast_radius_monotonicity(envelope, child)
        assert verify_blast_radius_monotonicity(child, grandchild)
        assert verify_blast_radius_monotonicity(envelope, grandchild)

    def test_blast_radius_strictly_narrows(self, envelope, agent_principal):
        child = envelope.narrow(agent_principal, SIGNING_KEY)
        assert blast_radius_max(child) < blast_radius_max(envelope)

    def test_blast_radius_with_resource_profile(self):
        """Definition 4.5: BR_max = R(S) ∩ {r : blast(r) ≤ β_remaining}."""
        scope = Scope(
            frozenset({"db:production", "db:staging", "docs:public"}),
            frozenset({"read"}),
            frozenset({"public"}),
        )
        principal = Principal("user:x", ExecutionRole.AS_USER, scope)
        spec = DelegationBudgetSpec(3, 0.5, 5, "confidential", True, 100.0)
        env = AuthorizationEnvelope(
            "e1", "s1", principal, scope, spec,
            expires_at=1e12,
        )
        env.sign(SIGNING_KEY)

        profile = ResourceBlastProfile.from_dict({
            "db:production": 0.9,
            "db:staging": 0.3,
            "docs:public": 0.05,
        })

        # With full budget (0.5 remaining), db:production (0.9) is unreachable
        br = blast_radius_max(env, profile, budget_remaining=0.5)
        assert "db:production" not in br  # 0.9 > 0.5
        assert "db:staging" in br         # 0.3 ≤ 0.5
        assert "docs:public" in br        # 0.05 ≤ 0.5

        # With tight budget (0.1 remaining), only docs:public is reachable
        br_tight = blast_radius_max(env, profile, budget_remaining=0.1)
        assert br_tight == frozenset({"docs:public"})

        # With zero budget, nothing with blast > 0 is reachable
        br_zero = blast_radius_max(env, profile, budget_remaining=0.0)
        assert br_zero == frozenset()  # 0.05 > 0.0

    def test_blast_radius_monotonicity_with_profile(self):
        """Theorem 4.1 with real per-resource blast weights."""
        parent_scope = Scope(
            frozenset({"db:prod", "db:staging", "docs:x"}),
            frozenset({"read"}),
            frozenset({"public"}),
        )
        child_role_scope = Scope(
            frozenset({"db:staging", "docs:x"}),
            frozenset({"read"}),
            frozenset({"public"}),
        )
        parent_p = Principal("user:x", ExecutionRole.AS_USER, parent_scope)
        child_p = Principal("agent:y", ExecutionRole.ON_BEHALF_OF, child_role_scope)
        spec = DelegationBudgetSpec(3, 1.0, 5, "confidential", True, 100.0)

        parent_env = AuthorizationEnvelope(
            "e1", "s1", parent_p, parent_scope, spec, expires_at=1e12,
        )
        parent_env.sign(SIGNING_KEY)
        child_env = parent_env.narrow(child_p, SIGNING_KEY)

        profile = ResourceBlastProfile.from_dict({
            "db:prod": 0.9,
            "db:staging": 0.3,
            "docs:x": 0.05,
        })

        # Parent has more budget remaining than child (child consumed some)
        assert verify_blast_radius_monotonicity(
            parent_env, child_env, profile,
            parent_budget_remaining=0.8,
            child_budget_remaining=0.5,
        )
