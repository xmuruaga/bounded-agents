"""Tests for apc_compose — composition closure checker."""

from apc.compose import (
    ActionClassMapping,
    CompositionChecker,
    RestrictionTemplate,
    compile_templates,
)


class TestActionClassMapping:
    def test_exact_match(self):
        m = ActionClassMapping.from_dict({"read": "data_read"})
        assert m.classify("read") == "data_read"

    def test_prefix_match(self):
        m = ActionClassMapping.from_dict({"read": "data_read"})
        assert m.classify("read_confidential") == "data_read"

    def test_fallback_to_self(self):
        m = ActionClassMapping.from_dict({})
        assert m.classify("unknown_action") == "unknown_action"


class TestRestrictionTemplates:
    def test_compile(self):
        templates = [
            RestrictionTemplate.deny_compose("read_confidential", "external_send"),
            RestrictionTemplate.deny_compose("data_write", "external_send"),
        ]
        X = compile_templates(templates)
        assert ("read_confidential", "external_send") in X
        assert ("data_write", "external_send") in X
        assert len(X) == 2


class TestCompositionChecker:
    def test_first_action_always_allowed(self):
        checker = CompositionChecker(
            restrictions=frozenset({("read_confidential", "external_send")}),
        )
        result = checker.check("read_confidential")
        assert result.allowed

    def test_violation_detected(self):
        checker = CompositionChecker(
            restrictions=frozenset({("read_confidential", "external_send")}),
        )
        checker.record("read_confidential")
        result = checker.check("external_send")
        assert not result.allowed
        assert len(result.violations) > 0

    def test_reverse_direction_also_caught(self):
        checker = CompositionChecker(
            restrictions=frozenset({("read_confidential", "external_send")}),
        )
        checker.record("external_send")
        result = checker.check("read_confidential")
        assert not result.allowed

    def test_non_restricted_pair_allowed(self):
        checker = CompositionChecker(
            restrictions=frozenset({("read_confidential", "external_send")}),
        )
        checker.record("read_confidential")
        result = checker.check("data_write")
        assert result.allowed

    def test_check_and_record(self):
        checker = CompositionChecker(
            restrictions=frozenset({("A", "B")}),
        )
        r1 = checker.check_and_record("A")
        assert r1.allowed
        assert "A" in checker.exercised_classes

        r2 = checker.check_and_record("B")
        assert not r2.allowed
        assert "B" not in checker.exercised_classes  # not recorded on failure

    def test_with_class_mapping(self):
        mapping = ActionClassMapping.from_dict({
            "read_contract": "read_confidential",
            "send_email": "external_send",
        })
        checker = CompositionChecker(
            restrictions=frozenset({("read_confidential", "external_send")}),
            class_mapping=mapping,
        )
        checker.record("read_contract")
        result = checker.check("send_email")
        assert not result.allowed

    def test_incremental_performance(self):
        """Verify O(|exercised_classes|) behavior — many actions, few classes."""
        mapping = ActionClassMapping.from_dict({
            "read_doc_1": "data_read",
            "read_doc_2": "data_read",
            "read_doc_3": "data_read",
        })
        checker = CompositionChecker(
            restrictions=frozenset({("data_read", "external_send")}),
            class_mapping=mapping,
        )
        # Record many actions that map to same class
        for i in range(100):
            checker.record(f"read_doc_{i % 3 + 1}")

        # Only 1 exercised class despite 100 actions
        assert len(checker.exercised_classes) == 1
        result = checker.check("external_send")
        assert not result.allowed

    def test_reset(self):
        checker = CompositionChecker(
            restrictions=frozenset({("A", "B")}),
        )
        checker.record("A")
        checker.reset()
        result = checker.check("B")
        assert result.allowed
