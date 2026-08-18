"""Extended evidence sink for AgentDojo evaluation."""
from __future__ import annotations
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class SessionEvidenceSink:
    session_id: str
    decisions: list[dict[str, Any]] = field(default_factory=list)
    _admit_count: int = 0
    _deny_count: int = 0
    _latencies_ns: list[int] = field(default_factory=list)

    def record_decision(self, tool_name: str, action_type: str, admitted: bool,
                        reason: str, latency_ns: int) -> None:
        self.decisions.append({
            "tool_name": tool_name, "action_type": action_type,
            "admitted": admitted, "reason": reason,
            "latency_ns": latency_ns, "timestamp": time.time(),
        })
        if admitted:
            self._admit_count += 1
        else:
            self._deny_count += 1
        self._latencies_ns.append(latency_ns)

    @property
    def admit_count(self) -> int: return self._admit_count
    @property
    def deny_count(self) -> int: return self._deny_count
    @property
    def total_decisions(self) -> int: return self._admit_count + self._deny_count

    @property
    def latency_p50_us(self) -> float:
        if not self._latencies_ns: return 0.0
        s = sorted(self._latencies_ns)
        return s[len(s) // 2] / 1000.0

    @property
    def latency_p99_us(self) -> float:
        if not self._latencies_ns: return 0.0
        s = sorted(self._latencies_ns)
        return s[min(int(len(s) * 0.99), len(s) - 1)] / 1000.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "admit_count": self._admit_count, "deny_count": self._deny_count,
            "total_decisions": self.total_decisions,
            "latency_p50_us": self.latency_p50_us, "latency_p99_us": self.latency_p99_us,
            "decisions": self.decisions,
        }
