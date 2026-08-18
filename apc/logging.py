"""
apc_logging — Structured logging for APC security events.

Provides a structured logging interface for security-relevant events:
admissions, denials, evidence commits, rate limit hits, and revocations.

Uses Python's standard logging module with structured extra fields,
so production deployments can route to any log aggregator (CloudWatch,
Splunk, ELK, etc.) by configuring the appropriate handler.

Usage:
    from apc.logging import apc_logger, SecurityEvent

    apc_logger.admission("read", "docs:x", "user:alice", "session-1")
    apc_logger.denial("delete", "db:prod", "agent:evil", "session-1",
                      reasons=["resource not in scope"])
"""

from __future__ import annotations

import logging
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class SecurityEvent(Enum):
    """Categories of APC security events."""

    ADMISSION = "admission"
    DENIAL = "denial"
    EVIDENCE_COMMIT = "evidence_commit"
    EVIDENCE_FAILURE = "evidence_failure"
    RATE_LIMIT = "rate_limit"
    REVOCATION_CHECK = "revocation_check"
    BUDGET_EXHAUSTION = "budget_exhaustion"
    ENVELOPE_EXPIRED = "envelope_expired"
    INTEGRITY_CHECK = "integrity_check"
    PARAMETER_VIOLATION = "parameter_violation"


@dataclass
class SecurityLogEntry:
    """Structured log entry for APC security events."""

    event: SecurityEvent
    action_type: str = ""
    target_resource: str = ""
    actor: str = ""
    session_id: str = ""
    timestamp: float = field(default_factory=time.time)
    details: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["event"] = self.event.value
        return d


class APCLogger:
    """Structured logger for APC security events.

    Wraps Python's standard logging module with typed methods for
    each security event category. Each method logs at the appropriate
    level (INFO for admissions, WARNING for denials, ERROR for failures).
    """

    def __init__(self, name: str = "apc.security") -> None:
        self._logger = logging.getLogger(name)

    @property
    def logger(self) -> logging.Logger:
        """Access the underlying Python logger for handler configuration."""
        return self._logger

    def admission(
        self,
        action_type: str,
        target_resource: str,
        actor: str,
        session_id: str,
        **details: Any,
    ) -> None:
        entry = SecurityLogEntry(
            event=SecurityEvent.ADMISSION,
            action_type=action_type,
            target_resource=target_resource,
            actor=actor,
            session_id=session_id,
            details=details,
        )
        self._logger.info(
            "ADMITTED %s on %s by %s",
            action_type, target_resource, actor,
            extra={"apc_entry": entry.as_dict()},
        )

    def denial(
        self,
        action_type: str,
        target_resource: str,
        actor: str,
        session_id: str,
        reasons: list[str] | None = None,
        **details: Any,
    ) -> None:
        entry = SecurityLogEntry(
            event=SecurityEvent.DENIAL,
            action_type=action_type,
            target_resource=target_resource,
            actor=actor,
            session_id=session_id,
            details={"reasons": reasons or [], **details},
        )
        self._logger.warning(
            "DENIED %s on %s by %s: %s",
            action_type, target_resource, actor,
            "; ".join(reasons or ["unknown"]),
            extra={"apc_entry": entry.as_dict()},
        )

    def evidence_commit(
        self, session_id: str, sequence_number: int, **details: Any,
    ) -> None:
        entry = SecurityLogEntry(
            event=SecurityEvent.EVIDENCE_COMMIT,
            session_id=session_id,
            details={"sequence_number": sequence_number, **details},
        )
        self._logger.info(
            "Evidence committed: session=%s seq=%d",
            session_id, sequence_number,
            extra={"apc_entry": entry.as_dict()},
        )

    def evidence_failure(
        self, session_id: str, reason: str, **details: Any,
    ) -> None:
        entry = SecurityLogEntry(
            event=SecurityEvent.EVIDENCE_FAILURE,
            session_id=session_id,
            details={"reason": reason, **details},
        )
        self._logger.error(
            "Evidence commit FAILED: session=%s reason=%s",
            session_id, reason,
            extra={"apc_entry": entry.as_dict()},
        )

    def rate_limit(
        self, actor: str, current_count: int, max_allowed: int, **details: Any,
    ) -> None:
        entry = SecurityLogEntry(
            event=SecurityEvent.RATE_LIMIT,
            actor=actor,
            details={"current_count": current_count, "max_allowed": max_allowed, **details},
        )
        self._logger.warning(
            "Rate limit exceeded: actor=%s count=%d/%d",
            actor, current_count, max_allowed,
            extra={"apc_entry": entry.as_dict()},
        )

    def budget_exhaustion(
        self, session_id: str, actor: str, **details: Any,
    ) -> None:
        entry = SecurityLogEntry(
            event=SecurityEvent.BUDGET_EXHAUSTION,
            actor=actor,
            session_id=session_id,
            details=details,
        )
        self._logger.warning(
            "Budget exhausted: session=%s actor=%s",
            session_id, actor,
            extra={"apc_entry": entry.as_dict()},
        )

    def parameter_violation(
        self,
        action_type: str,
        target_resource: str,
        actor: str,
        session_id: str,
        violations: list[str] | None = None,
        **details: Any,
    ) -> None:
        entry = SecurityLogEntry(
            event=SecurityEvent.PARAMETER_VIOLATION,
            action_type=action_type,
            target_resource=target_resource,
            actor=actor,
            session_id=session_id,
            details={"violations": violations or [], **details},
        )
        self._logger.warning(
            "Parameter violation: %s on %s by %s: %s",
            action_type, target_resource, actor,
            "; ".join(violations or ["unknown"]),
            extra={"apc_entry": entry.as_dict()},
        )


# Module-level singleton for convenience
apc_logger = APCLogger()
