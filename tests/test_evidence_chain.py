"""
Tests for C5 Evidence Commitment — SHA-256 hash chain integrity.

Covers:
  - Chain structure: genesis anchor, previous_hash linkage, content_hash
  - verify_integrity() on intact chains of varying lengths
  - Tamper detection: field modification, package deletion, package insertion
  - Fail-closed: sink unavailable → commit returns False
  - Positive case: sink available → commit succeeds and chain grows
  - Empty chain: verify_integrity() returns valid with zero packages
"""

import copy
import hashlib
import json

import pytest

from apc.pdp import EvidenceSink, EvidenceIntegrityResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_package(action: str, resource: str, session: str = "session-test") -> dict:
    return {
        "action_type": action,
        "target_resource": resource,
        "actor": "agent:hop-1",
        "session_id": session,
    }


def _populated_sink(n: int) -> EvidenceSink:
    """Return a sink with n committed packages."""
    sink = EvidenceSink()
    for i in range(n):
        ok = sink.commit(_make_package(f"action-{i}", f"resource-{i}"))
        assert ok, f"commit {i} failed unexpectedly"
    return sink


# ---------------------------------------------------------------------------
# Chain structure
# ---------------------------------------------------------------------------

class TestChainStructure:
    """Verify that committed packages have the correct chain fields."""

    def test_first_package_anchored_at_genesis(self):
        sink = _populated_sink(1)
        pkg = sink.packages[0]
        assert pkg["previous_hash"] == "genesis"

    def test_second_package_links_to_first(self):
        sink = _populated_sink(2)
        first_hash = sink.packages[0]["content_hash"]
        assert sink.packages[1]["previous_hash"] == first_hash

    def test_content_hash_is_sha256_of_canonical_json(self):
        sink = _populated_sink(1)
        pkg = sink.packages[0]
        stored_hash = pkg["content_hash"]
        # Recompute without content_hash field
        payload = {k: v for k, v in pkg.items() if k != "content_hash"}
        canonical = json.dumps(payload, sort_keys=True, default=str)
        expected = hashlib.sha256(canonical.encode()).hexdigest()
        assert stored_hash == expected

    def test_sequence_numbers_are_monotonic(self):
        n = 5
        sink = _populated_sink(n)
        for i, pkg in enumerate(sink.packages):
            assert pkg["sequence_number"] == i

    def test_chain_head_matches_last_content_hash(self):
        sink = _populated_sink(3)
        assert sink._chain_head == sink.packages[-1]["content_hash"]


# ---------------------------------------------------------------------------
# verify_integrity — intact chains
# ---------------------------------------------------------------------------

class TestVerifyIntegrityIntact:

    def test_empty_chain_is_valid(self):
        sink = EvidenceSink()
        result = sink.verify_integrity()
        assert result.valid
        assert result.total_packages == 0

    def test_single_package_chain_is_valid(self):
        sink = _populated_sink(1)
        result = sink.verify_integrity()
        assert result.valid
        assert result.total_packages == 1

    def test_multi_package_chain_is_valid(self):
        sink = _populated_sink(10)
        result = sink.verify_integrity()
        assert result.valid
        assert result.total_packages == 10
        assert result.broken_at_index == -1


# ---------------------------------------------------------------------------
# verify_integrity — tamper detection
# ---------------------------------------------------------------------------

class TestTamperDetection:

    def test_field_modification_detected(self):
        """Changing a field in a committed package breaks the content_hash."""
        sink = _populated_sink(3)
        # Tamper: modify a field in the middle package
        sink._packages[1]["action_type"] = "TAMPERED"
        result = sink.verify_integrity()
        assert not result.valid
        assert result.broken_at_index == 1
        assert "tampered" in result.detail.lower()

    def test_previous_hash_modification_detected(self):
        """Changing previous_hash breaks the chain linkage check."""
        sink = _populated_sink(3)
        sink._packages[2]["previous_hash"] = "forged-hash"
        result = sink.verify_integrity()
        assert not result.valid
        assert result.broken_at_index == 2
        assert "chain break" in result.detail.lower()

    def test_package_deletion_detected(self):
        """Removing a middle package breaks the previous_hash linkage."""
        sink = _populated_sink(4)
        # Delete package at index 1 — package 2's previous_hash now points
        # to a hash that no longer matches the new predecessor
        del sink._packages[1]
        result = sink.verify_integrity()
        assert not result.valid
        # The break is detected at the new index 1 (formerly index 2)
        assert result.broken_at_index == 1

    def test_package_insertion_detected(self):
        """Inserting a forged package breaks the chain at the insertion point."""
        sink = _populated_sink(3)
        forged = copy.deepcopy(sink._packages[0])
        forged["action_type"] = "forged-insert"
        forged["sequence_number"] = 99
        # Insert after index 0 — package at new index 2 will have wrong previous_hash
        sink._packages.insert(1, forged)
        result = sink.verify_integrity()
        assert not result.valid

    def test_content_hash_field_zeroed_detected(self):
        """Zeroing the content_hash field is detected as tampering."""
        sink = _populated_sink(2)
        sink._packages[0]["content_hash"] = "0" * 64
        result = sink.verify_integrity()
        assert not result.valid
        assert result.broken_at_index == 0

    def test_first_package_tampered_detected(self):
        """Tampering with the first package (genesis anchor) is detected."""
        sink = _populated_sink(3)
        sink._packages[0]["target_resource"] = "tampered-resource"
        result = sink.verify_integrity()
        assert not result.valid
        assert result.broken_at_index == 0

    def test_last_package_tampered_detected(self):
        """Tampering with the last package is detected."""
        sink = _populated_sink(3)
        sink._packages[-1]["actor"] = "tampered-actor"
        result = sink.verify_integrity()
        assert not result.valid
        assert result.broken_at_index == len(sink._packages) - 1


# ---------------------------------------------------------------------------
# Fail-closed behavior (C5)
# ---------------------------------------------------------------------------

class TestFailClosed:

    def test_commit_fails_when_sink_unavailable(self):
        """C5: if evidence sink is down, commit returns False."""
        sink = EvidenceSink()
        sink.set_available(False)
        result = sink.commit(_make_package("read", "docs:secret"))
        assert result is False
        assert len(sink.packages) == 0

    def test_commit_succeeds_when_sink_available(self):
        """Positive case: sink available → commit succeeds."""
        sink = EvidenceSink()
        result = sink.commit(_make_package("read", "docs:public"))
        assert result is True
        assert len(sink.packages) == 1

    def test_sink_can_be_re_enabled(self):
        """Sink toggled off then on — commits resume correctly."""
        sink = EvidenceSink()
        sink.commit(_make_package("read", "r1"))
        sink.set_available(False)
        assert not sink.commit(_make_package("write", "r2"))
        sink.set_available(True)
        assert sink.commit(_make_package("read", "r3"))
        assert len(sink.packages) == 2  # only the two successful commits
        result = sink.verify_integrity()
        assert result.valid
        assert result.total_packages == 2

    def test_chain_integrity_preserved_after_failed_commit(self):
        """A failed commit (sink down) does not corrupt the chain."""
        sink = _populated_sink(2)
        sink.set_available(False)
        sink.commit(_make_package("write", "r-fail"))  # should fail silently
        sink.set_available(True)
        sink.commit(_make_package("read", "r-resume"))
        result = sink.verify_integrity()
        assert result.valid
        assert result.total_packages == 3
