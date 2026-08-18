"""Tests for k-tuple composition restrictions.

Validates the extension from pairwise (k=2) to arbitrary k-tuple
ordered subsequence restrictions, including resource-qualified variants.
"""

from apc.compose import (
    ActionClassMapping,
    CompositionChecker,
    KTupleRestriction,
)


class TestKTupleRestriction:
    def test_deny_sequence_creates_correct_k(self):
        r = KTupleRestriction.deny_sequence("read", "write", "send")
        assert r.k == 3
        assert r.sequence == ("read", "write", "send")
        assert r.resource_qualifiers == ()

    def test_deny_sequence_pair(self):
        r = KTupleRestriction.deny_sequence("read", "send")
        assert r.k == 2

    def test_k_less_than_2_raises(self):
        try:
            KTupleRestriction(sequence=("read",))
            assert False, "Should have raised ValueError"
        except ValueError:
            pass

    def test_mismatched_qualifiers_raises(self):
        try:
            KTupleRestriction(
                sequence=("read", "write", "send"),
                resource_qualifiers=(("email:*",), None),  # length 2 != 3
            )
            assert False, "Should have raised ValueError"
        except ValueError:
            pass

    def test_deny_qualified_sequence(self):
        r = KTupleRestriction.deny_qualified_sequence([
            ("read", ("email:*",)),
            ("write", None),
            ("send_external", ("web:*",)),
        ])
        assert r.k == 3
        assert r.sequence == ("read", "write", "send_external")
        assert r.resource_qualifiers == (("email:*",), None, ("web:*",))


class TestKTupleChecker:
    """Test k-tuple enforcement in CompositionChecker."""

    def test_3_tuple_blocked_in_order(self):
        """read → write → send in order triggers violation."""
        checker = CompositionChecker(
            k_tuple_restrictions=(
                KTupleRestriction.deny_sequence("read", "write", "send"),
            ),
        )
        checker.record("read")
        checker.record("write")
        result = checker.check("send")
        assert not result.allowed
        assert len(result.k_tuple_violations) == 1
        assert result.k_tuple_violations[0] == ("read", "write", "send")

    def test_3_tuple_allowed_wrong_order(self):
        """write → read → send does NOT match read → write → send."""
        checker = CompositionChecker(
            k_tuple_restrictions=(
                KTupleRestriction.deny_sequence("read", "write", "send"),
            ),
        )
        checker.record("write")
        checker.record("read")
        result = checker.check("send")
        assert result.allowed

    def test_3_tuple_allowed_incomplete(self):
        """read → send (missing write) does NOT match read → write → send."""
        checker = CompositionChecker(
            k_tuple_restrictions=(
                KTupleRestriction.deny_sequence("read", "write", "send"),
            ),
        )
        checker.record("read")
        result = checker.check("send")
        assert result.allowed

    def test_3_tuple_non_consecutive_match(self):
        """read → X → write → Y → send still matches (subsequence, not substring)."""
        checker = CompositionChecker(
            k_tuple_restrictions=(
                KTupleRestriction.deny_sequence("read", "write", "send"),
            ),
        )
        checker.record("read")
        checker.record("other_action")
        checker.record("write")
        checker.record("another_action")
        result = checker.check("send")
        assert not result.allowed

    def test_pairwise_and_ktuple_combined(self):
        """Both pairwise and k-tuple restrictions enforced simultaneously."""
        checker = CompositionChecker(
            restrictions=frozenset({("read", "send_external")}),
            k_tuple_restrictions=(
                KTupleRestriction.deny_sequence("read", "write", "send_internal"),
            ),
        )
        # Pairwise blocks read → send_external
        checker.record("read")
        result = checker.check("send_external")
        assert not result.allowed
        assert len(result.violations) > 0

        # k-tuple blocks read → write → send_internal
        checker.record("write")
        result = checker.check("send_internal")
        assert not result.allowed
        assert len(result.k_tuple_violations) == 1

    def test_4_tuple(self):
        """4-step restriction works."""
        checker = CompositionChecker(
            k_tuple_restrictions=(
                KTupleRestriction.deny_sequence("read", "summarize", "write", "send"),
            ),
        )
        checker.record("read")
        checker.record("summarize")
        checker.record("write")
        result = checker.check("send")
        assert not result.allowed

    def test_4_tuple_missing_step(self):
        """Missing one step in 4-tuple → allowed."""
        checker = CompositionChecker(
            k_tuple_restrictions=(
                KTupleRestriction.deny_sequence("read", "summarize", "write", "send"),
            ),
        )
        checker.record("read")
        checker.record("write")  # skipped summarize
        result = checker.check("send")
        assert result.allowed

    def test_with_class_mapping(self):
        """k-tuple works with action class mapping."""
        mapping = ActionClassMapping.from_dict({
            "get_file_by_id": "read",
            "create_file": "write",
            "send_email": "send",
        })
        checker = CompositionChecker(
            class_mapping=mapping,
            k_tuple_restrictions=(
                KTupleRestriction.deny_sequence("read", "write", "send"),
            ),
        )
        checker.record("get_file_by_id")
        checker.record("create_file")
        result = checker.check("send_email")
        assert not result.allowed

    def test_reset_clears_ktuple_history(self):
        """Reset clears the ordered history used for k-tuple checks."""
        checker = CompositionChecker(
            k_tuple_restrictions=(
                KTupleRestriction.deny_sequence("read", "write", "send"),
            ),
        )
        checker.record("read")
        checker.record("write")
        checker.reset()
        result = checker.check("send")
        assert result.allowed

    def test_check_and_record_with_ktuple(self):
        """check_and_record respects k-tuple restrictions."""
        checker = CompositionChecker(
            k_tuple_restrictions=(
                KTupleRestriction.deny_sequence("A", "B", "C"),
            ),
        )
        r1 = checker.check_and_record("A")
        assert r1.allowed
        r2 = checker.check_and_record("B")
        assert r2.allowed
        r3 = checker.check_and_record("C")
        assert not r3.allowed
        # C should NOT be recorded since it was denied
        assert len(checker.action_history) == 2


class TestResourceQualifiedKTuple:
    """Test resource-qualified k-tuple restrictions."""

    def test_qualified_match(self):
        """Restriction matches when resources match qualifiers."""
        checker = CompositionChecker(
            k_tuple_restrictions=(
                KTupleRestriction.deny_qualified_sequence([
                    ("read", ("email:*",)),
                    ("write", None),  # any resource
                    ("send_internal", None),
                ]),
            ),
        )
        checker.record("read", resource="email:msg-123")
        checker.record("write", resource="files:summary.txt")
        result = checker.check("send_internal", resource="calendar:event-1")
        assert not result.allowed

    def test_qualified_no_match_wrong_resource(self):
        """Restriction does NOT match when resource doesn't match qualifier."""
        checker = CompositionChecker(
            k_tuple_restrictions=(
                KTupleRestriction.deny_qualified_sequence([
                    ("read", ("email:*",)),
                    ("write", None),
                    ("send_internal", None),
                ]),
            ),
        )
        # read from files, not email — doesn't match the qualifier
        checker.record("read", resource="files:doc.txt")
        checker.record("write", resource="files:summary.txt")
        result = checker.check("send_internal", resource="calendar:event-1")
        assert result.allowed

    def test_qualified_multiple_patterns(self):
        """Qualifier with multiple patterns — any match suffices."""
        checker = CompositionChecker(
            k_tuple_restrictions=(
                KTupleRestriction.deny_qualified_sequence([
                    ("read", ("email:*", "files:confidential/*")),
                    ("send_external", None),
                ]),
            ),
        )
        checker.record("read", resource="files:confidential/salaries.csv")
        result = checker.check("send_external", resource="web:attacker.com")
        assert not result.allowed
