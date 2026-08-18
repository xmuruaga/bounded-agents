"""Maps AgentDojo suites to APC authorization scopes."""
from __future__ import annotations
from dataclasses import dataclass, field
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent))

from apc.core import CompositionPair, DelegationBudgetSpec, Scope
from apc.compose import ActionClassMapping, KTupleRestriction, RestrictionTemplate, compile_templates


@dataclass
class SuiteScope:
    scope: Scope
    budget_spec: DelegationBudgetSpec
    class_mapping: ActionClassMapping
    restriction_templates: list[RestrictionTemplate] = field(default_factory=list)
    k_tuple_restrictions: tuple[KTupleRestriction, ...] = ()

    @property
    def composition_restrictions(self) -> frozenset[CompositionPair]:
        return compile_templates(self.restriction_templates)


class ScopeRegistry:
    @staticmethod
    def workspace_complete() -> SuiteScope:
        resources = frozenset(["email:*", "calendar:*", "files:*", "contacts:*", "web:*"])
        actions = frozenset(["read", "read_sensitive", "read_external", "write", "delete",
                             "send_internal", "send_external", "transfer"])
        data_classifications = frozenset(["public", "internal", "confidential"])
        templates = [
            RestrictionTemplate.deny_compose("read", "send_external"),
            RestrictionTemplate.deny_compose("read_sensitive", "send_external"),
            RestrictionTemplate.deny_compose("read", "post_webpage"),
            RestrictionTemplate.deny_compose("read_sensitive", "post_webpage"),
            RestrictionTemplate.deny_compose("read_sensitive", "write"),
            RestrictionTemplate.deny_compose("read", "read_external"),
            RestrictionTemplate.deny_compose("read_sensitive", "read_external"),
        ]
        restrictions = compile_templates(templates)
        scope = Scope(resources=resources, actions=actions,
                      data_classifications=data_classifications,
                      composition_restrictions=restrictions)
        budget = DelegationBudgetSpec(max_delegation_depth=2, max_blast_radius=1.0,
                                     max_irreversible_effects=5, max_sensitivity_class="confidential",
                                     cross_domain_composition=True, max_cost=10.0)
        class_mapping = ActionClassMapping.from_dict({
            "read": "read", "read_sensitive": "read_sensitive", "read_external": "read_external",
            "write": "write", "delete": "delete", "send_internal": "send_internal",
            "send_external": "send_external", "transfer": "transfer",
            "post_webpage": "send_external",
        })
        k_tuples = (
            KTupleRestriction.deny_sequence("read", "write", "send_external"),
            KTupleRestriction.deny_sequence("read", "write", "send_internal"),
            KTupleRestriction.deny_sequence("read_sensitive", "write", "send_external"),
            KTupleRestriction.deny_sequence("read_sensitive", "write", "send_internal"),
            KTupleRestriction.deny_sequence("read", "write", "read_external"),
            KTupleRestriction.deny_sequence("read_sensitive", "write", "read_external"),
            KTupleRestriction.deny_sequence("read", "delete", "send_external"),
            KTupleRestriction.deny_sequence("read_sensitive", "delete", "send_external"),
        )
        return SuiteScope(scope=scope, budget_spec=budget, class_mapping=class_mapping,
                          restriction_templates=templates, k_tuple_restrictions=k_tuples)

    @staticmethod
    def workspace_incomplete() -> SuiteScope:
        complete = ScopeRegistry.workspace_complete()
        reduced_templates = [
            RestrictionTemplate.deny_compose("read", "send_external"),
            RestrictionTemplate.deny_compose("read_sensitive", "send_external"),
            RestrictionTemplate.deny_compose("read", "post_webpage"),
            RestrictionTemplate.deny_compose("read_sensitive", "post_webpage"),
        ]
        restrictions = compile_templates(reduced_templates)
        scope = Scope(resources=complete.scope.resources, actions=complete.scope.actions,
                      data_classifications=complete.scope.data_classifications,
                      composition_restrictions=restrictions)
        return SuiteScope(scope=scope, budget_spec=complete.budget_spec,
                          class_mapping=complete.class_mapping,
                          restriction_templates=reduced_templates)

    @staticmethod
    def banking_complete() -> SuiteScope:
        resources = frozenset(["account:*", "transaction:*", "user:*", "web:*", "files:*"])
        actions = frozenset(["read", "read_sensitive", "read_external", "write", "transfer", "send_external"])
        data_classifications = frozenset(["public", "internal", "confidential"])
        templates = [
            RestrictionTemplate.deny_compose("read", "send_external"),
            RestrictionTemplate.deny_compose("read_sensitive", "send_external"),
            RestrictionTemplate.deny_compose("read", "transfer"),
            RestrictionTemplate.deny_compose("read_sensitive", "transfer"),
            RestrictionTemplate.deny_compose("read_sensitive", "write"),
        ]
        restrictions = compile_templates(templates)
        scope = Scope(resources=resources, actions=actions,
                      data_classifications=data_classifications,
                      composition_restrictions=restrictions)
        budget = DelegationBudgetSpec(max_delegation_depth=1, max_blast_radius=0.7,
                                     max_irreversible_effects=2, max_sensitivity_class="confidential",
                                     cross_domain_composition=True, max_cost=5.0)
        class_mapping = ActionClassMapping.from_dict({
            "read": "read", "read_sensitive": "read_sensitive", "read_external": "read_external",
            "write": "write", "transfer": "transfer", "send_external": "send_external",
            "post_webpage": "send_external",
        })
        k_tuples = (
            KTupleRestriction.deny_sequence("read_sensitive", "write", "send_external"),
            KTupleRestriction.deny_sequence("read", "write", "send_external"),
            KTupleRestriction.deny_sequence("read_sensitive", "write", "transfer"),
        )
        return SuiteScope(scope=scope, budget_spec=budget, class_mapping=class_mapping,
                          restriction_templates=templates, k_tuple_restrictions=k_tuples)

    @staticmethod
    def travel_complete() -> SuiteScope:
        resources = frozenset([
            "hotels:*", "flights:*", "restaurants:*", "cars:*",
            "calendar:*", "email:*", "user:*",
        ])
        actions = frozenset([
            "read", "read_sensitive", "read_external", "write", "delete",
            "send_internal", "send_external",
        ])
        data_classifications = frozenset(["public", "internal", "confidential"])
        templates = [
            RestrictionTemplate.deny_compose("read", "send_external"),
            RestrictionTemplate.deny_compose("read_sensitive", "send_external"),
            RestrictionTemplate.deny_compose("read_sensitive", "write"),
        ]
        restrictions = compile_templates(templates)
        scope = Scope(resources=resources, actions=actions,
                      data_classifications=data_classifications,
                      composition_restrictions=restrictions)
        budget = DelegationBudgetSpec(max_delegation_depth=2, max_blast_radius=1.0,
                                     max_irreversible_effects=5, max_sensitivity_class="confidential",
                                     cross_domain_composition=True, max_cost=10.0)
        class_mapping = ActionClassMapping.from_dict({
            "read": "read", "read_sensitive": "read_sensitive", "read_external": "read_external",
            "write": "write", "delete": "delete", "send_internal": "send_internal",
            "send_external": "send_external",
        })
        k_tuples = (
            KTupleRestriction.deny_sequence("read", "write", "send_external"),
            KTupleRestriction.deny_sequence("read_sensitive", "write", "send_external"),
            KTupleRestriction.deny_sequence("read", "write", "send_internal"),
            KTupleRestriction.deny_sequence("read_sensitive", "write", "send_internal"),
        )
        return SuiteScope(scope=scope, budget_spec=budget, class_mapping=class_mapping,
                          restriction_templates=templates, k_tuple_restrictions=k_tuples)

    @staticmethod
    def slack_complete() -> SuiteScope:
        resources = frozenset(["channels:*", "messages:*", "users:*", "web:*"])
        actions = frozenset([
            "read", "read_external", "write", "delete",
            "send_internal", "send_external",
        ])
        data_classifications = frozenset(["public", "internal", "confidential"])
        templates = [
            RestrictionTemplate.deny_compose("read", "send_external"),
            RestrictionTemplate.deny_compose("read", "post_webpage"),
            RestrictionTemplate.deny_compose("send_internal", "send_external"),
        ]
        restrictions = compile_templates(templates)
        scope = Scope(resources=resources, actions=actions,
                      data_classifications=data_classifications,
                      composition_restrictions=restrictions)
        budget = DelegationBudgetSpec(max_delegation_depth=2, max_blast_radius=0.8,
                                     max_irreversible_effects=3, max_sensitivity_class="confidential",
                                     cross_domain_composition=True, max_cost=8.0)
        class_mapping = ActionClassMapping.from_dict({
            "read": "read", "read_external": "read_external",
            "write": "write", "delete": "delete",
            "send_internal": "send_internal", "send_external": "send_external",
            "post_webpage": "send_external",
        })
        k_tuples = (
            KTupleRestriction.deny_sequence("read", "send_internal", "send_external"),
            KTupleRestriction.deny_sequence("read", "write", "send_external"),
        )
        return SuiteScope(scope=scope, budget_spec=budget, class_mapping=class_mapping,
                          restriction_templates=templates, k_tuple_restrictions=k_tuples)
