"""Tests for apc_approval — approval token lifecycle."""

import time

from apc.approval import ApprovalStatus, ApprovalStore, ApprovalToken, compute_action_hash


class TestActionHash:
    def test_deterministic(self):
        h1 = compute_action_hash("read", "docs:contract-1", {"format": "pdf"})
        h2 = compute_action_hash("read", "docs:contract-1", {"format": "pdf"})
        assert h1 == h2

    def test_different_params_different_hash(self):
        h1 = compute_action_hash("read", "docs:contract-1", {"format": "pdf"})
        h2 = compute_action_hash("read", "docs:contract-1", {"format": "txt"})
        assert h1 != h2

    def test_different_action_different_hash(self):
        h1 = compute_action_hash("read", "docs:contract-1", {})
        h2 = compute_action_hash("write", "docs:contract-1", {})
        assert h1 != h2


class TestApprovalToken:
    def test_valid_token(self):
        token = ApprovalToken(
            token_id="tok-1",
            action_hash="abc123",
            target_resource="docs:x",
            scope_snapshot={},
            approver_id="user:admin",
            approved_at=time.time(),
            expires_at=time.time() + 300,
            policy_version="1.0",
            task_session_id="session-001",
        )
        assert token.is_valid
        assert token.status == ApprovalStatus.GRANTED

    def test_expired_token(self):
        token = ApprovalToken(
            token_id="tok-2",
            action_hash="abc123",
            target_resource="docs:x",
            scope_snapshot={},
            approver_id="user:admin",
            approved_at=time.time() - 600,
            expires_at=time.time() - 1,
            policy_version="1.0",
            task_session_id="session-001",
        )
        assert not token.is_valid
        assert token.status == ApprovalStatus.EXPIRED

    def test_consumed_token(self):
        token = ApprovalToken(
            token_id="tok-3",
            action_hash="abc123",
            target_resource="docs:x",
            scope_snapshot={},
            approver_id="user:admin",
            approved_at=time.time(),
            expires_at=time.time() + 300,
            policy_version="1.0",
            task_session_id="session-001",
        )
        token.consume()
        assert token.status == ApprovalStatus.CONSUMED
        assert not token.is_valid

    def test_revoked_token(self):
        token = ApprovalToken(
            token_id="tok-4",
            action_hash="abc123",
            target_resource="docs:x",
            scope_snapshot={},
            approver_id="user:admin",
            approved_at=time.time(),
            expires_at=time.time() + 300,
            policy_version="1.0",
            task_session_id="session-001",
        )
        token.revoke()
        assert token.status == ApprovalStatus.REVOKED

    def test_validate_for_action_hash_mismatch(self):
        token = ApprovalToken(
            token_id="tok-5",
            action_hash="abc123",
            target_resource="docs:x",
            scope_snapshot={},
            approver_id="user:admin",
            approved_at=time.time(),
            expires_at=time.time() + 300,
            policy_version="1.0",
            task_session_id="session-001",
        )
        result = token.validate_for_action("different_hash", "session-001")
        assert not result.valid
        assert "action_hash mismatch" in result.errors

    def test_validate_for_session_mismatch(self):
        token = ApprovalToken(
            token_id="tok-6",
            action_hash="abc123",
            target_resource="docs:x",
            scope_snapshot={},
            approver_id="user:admin",
            approved_at=time.time(),
            expires_at=time.time() + 300,
            policy_version="1.0",
            task_session_id="session-001",
        )
        result = token.validate_for_action("abc123", "session-999")
        assert not result.valid


class TestApprovalStore:
    def test_issue_and_get(self, approval_store):
        token = approval_store.issue(
            token_id="tok-10",
            action_type="delete",
            target_resource="db:production",
            parameters={"table": "users"},
            scope_snapshot={"resources": ["db:production"]},
            approver_id="user:admin",
            policy_version="1.0",
            task_session_id="session-001",
        )
        assert approval_store.get("tok-10") is token
        assert token.is_valid

    def test_consume(self, approval_store):
        approval_store.issue(
            token_id="tok-11",
            action_type="delete",
            target_resource="db:production",
            parameters={},
            scope_snapshot={},
            approver_id="user:admin",
            policy_version="1.0",
            task_session_id="session-001",
        )
        assert approval_store.consume("tok-11")
        assert not approval_store.get("tok-11").is_valid

    def test_revoke(self, approval_store):
        approval_store.issue(
            token_id="tok-12",
            action_type="delete",
            target_resource="db:production",
            parameters={},
            scope_snapshot={},
            approver_id="user:admin",
            policy_version="1.0",
            task_session_id="session-001",
        )
        assert approval_store.revoke("tok-12")
        assert not approval_store.get("tok-12").is_valid

    def test_audit_log(self, approval_store):
        approval_store.issue(
            token_id="tok-13",
            action_type="read",
            target_resource="docs:x",
            parameters={},
            scope_snapshot={},
            approver_id="user:admin",
            policy_version="1.0",
            task_session_id="session-001",
        )
        approval_store.consume("tok-13")
        log = approval_store.audit_log
        assert len(log) == 2
        assert log[0]["event"] == "issued"
        assert log[1]["event"] == "consumed"
