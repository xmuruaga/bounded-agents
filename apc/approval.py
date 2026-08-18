"""
apc_approval — Approval token lifecycle.

Single-use, action-hash-bound, expiring authorization artifacts.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any


class ApprovalStatus(Enum):
    PENDING = "pending"
    GRANTED = "granted"
    CONSUMED = "consumed"
    EXPIRED = "expired"
    REVOKED = "revoked"


@dataclass
class ApprovalToken:
    """Single-use authorization artifact bound to an exact action instance."""

    token_id: str
    action_hash: str
    target_resource: str
    scope_snapshot: dict[str, Any]
    approver_id: str
    approved_at: float
    expires_at: float
    policy_version: str
    task_session_id: str
    max_uses: int = 1
    _use_count: int = 0
    _status: ApprovalStatus = ApprovalStatus.GRANTED

    @property
    def status(self) -> ApprovalStatus:
        if self._status == ApprovalStatus.REVOKED:
            return ApprovalStatus.REVOKED
        if time.time() > self.expires_at:
            return ApprovalStatus.EXPIRED
        if self._use_count >= self.max_uses:
            return ApprovalStatus.CONSUMED
        return self._status

    @property
    def is_valid(self) -> bool:
        return self.status == ApprovalStatus.GRANTED

    def validate_for_action(self, action_hash: str, task_session_id: str) -> TokenValidation:
        """Validate token against a specific action instance."""
        errors: list[str] = []

        if self.status != ApprovalStatus.GRANTED:
            errors.append(f"token status is {self.status.value}, expected granted")

        if self.action_hash != action_hash:
            errors.append("action_hash mismatch")

        if self.task_session_id != task_session_id:
            errors.append("task_session_id mismatch")

        return TokenValidation(valid=len(errors) == 0, errors=tuple(errors))

    def consume(self) -> None:
        """Mark token as consumed after successful action execution."""
        self._use_count += 1

    def revoke(self) -> None:
        self._status = ApprovalStatus.REVOKED


@dataclass(frozen=True)
class TokenValidation:
    valid: bool
    errors: tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# Action hashing
# ---------------------------------------------------------------------------

def compute_action_hash(
    action_type: str,
    target_resource: str,
    parameters: dict[str, Any],
) -> str:
    """Deterministic hash of an action instance.

    Parameters must be JSON-serializable (strings, numbers, booleans,
    lists, dicts, None). Non-serializable values raise TypeError.
    """
    payload = json.dumps({
        "action_type": action_type,
        "target_resource": target_resource,
        "parameters": parameters,
    }, sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Approval Token Store (in-memory for reference impl)
# ---------------------------------------------------------------------------

class ApprovalStore:
    """Infrastructure-side token store with audit log."""

    def __init__(self) -> None:
        self._tokens: dict[str, ApprovalToken] = {}
        self._audit_log: list[dict[str, Any]] = []

    def issue(
        self,
        token_id: str,
        action_type: str,
        target_resource: str,
        parameters: dict[str, Any],
        scope_snapshot: dict[str, Any],
        approver_id: str,
        policy_version: str,
        task_session_id: str,
        ttl_seconds: float = 300.0,
    ) -> ApprovalToken:
        action_hash = compute_action_hash(action_type, target_resource, parameters)
        now = time.time()
        token = ApprovalToken(
            token_id=token_id,
            action_hash=action_hash,
            target_resource=target_resource,
            scope_snapshot=scope_snapshot,
            approver_id=approver_id,
            approved_at=now,
            expires_at=now + ttl_seconds,
            policy_version=policy_version,
            task_session_id=task_session_id,
        )
        self._tokens[token_id] = token
        self._log("issued", token_id, approver_id)
        return token

    def get(self, token_id: str) -> ApprovalToken | None:
        return self._tokens.get(token_id)

    def consume(self, token_id: str) -> bool:
        token = self._tokens.get(token_id)
        if token and token.is_valid:
            token.consume()
            self._log("consumed", token_id)
            return True
        return False

    def revoke(self, token_id: str) -> bool:
        token = self._tokens.get(token_id)
        if token:
            token.revoke()
            self._log("revoked", token_id)
            return True
        return False

    @property
    def audit_log(self) -> list[dict[str, Any]]:
        return list(self._audit_log)

    def _log(self, event: str, token_id: str, actor: str = "infrastructure") -> None:
        self._audit_log.append({
            "event": event,
            "token_id": token_id,
            "actor": actor,
            "timestamp": time.time(),
        })
