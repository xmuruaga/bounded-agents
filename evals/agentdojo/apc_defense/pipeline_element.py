"""APCDefenseElement — BasePipelineElement that enforces APC on tool calls."""
from __future__ import annotations
import time, sys
from collections.abc import Sequence
from typing import Any
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent))

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionsRuntime
from agentdojo.types import ChatMessage, ChatToolResultMessage, text_content_block_from_string

from apc.core import glob_match
from apc.intent import IntentEnforcementMode
from apc.pdp import ProposedAction

from apc_defense.action_classifier import ActionClassifier
from apc_defense.evidence_sink import SessionEvidenceSink
from apc_defense.scope_registry import SuiteScope
from apc_defense.session_state import SessionState


class APCDefenseElement(BasePipelineElement):
    name = "apc-defense"

    def __init__(self, suite_scope: SuiteScope, classifier: ActionClassifier,
                 intent_mode=IntentEnforcementMode.STRICT, approval_threshold=0.5,
                 auto_approve_c4=False):
        self._suite_scope = suite_scope
        self._classifier = classifier
        self._intent_mode = intent_mode
        self._approval_threshold = approval_threshold
        self._auto_approve_c4 = auto_approve_c4
        self._sessions: dict[str, SessionState] = {}
        self._evidence: dict[str, SessionEvidenceSink] = {}
        self._run_counter: int = 0

    def get_or_create_session(self, task_id, query):
        if task_id not in self._sessions:
            session = SessionState.create(
                session_id=task_id, suite_scope=self._suite_scope,
                user_task_prompt=query, approval_threshold=self._approval_threshold,
                intent_mode=self._intent_mode,
            )
            self._sessions[task_id] = session
            self._evidence[task_id] = SessionEvidenceSink(session_id=task_id)
        return self._sessions[task_id], self._evidence[task_id]

    def query(self, query, runtime, env=EmptyEnv(), messages=[], extra_args={}):
        if not messages or messages[-1]["role"] != "assistant":
            return query, runtime, env, messages, extra_args
        if messages[-1]["tool_calls"] is None or len(messages[-1]["tool_calls"]) == 0:
            return query, runtime, env, messages, extra_args

        task_id = extra_args.get("task_id", f"session-{self._run_counter}")
        session, evidence = self.get_or_create_session(task_id, query)
        last_msg = messages[-1]

        denied_results = []
        admitted_tool_calls = []

        for tool_call in last_msg["tool_calls"]:
            tool_name = tool_call.function
            tool_args = dict(tool_call.args) if tool_call.args else {}
            t0 = time.perf_counter_ns()
            admitted, reason = self._evaluate_tool_call(session, tool_name, tool_args)
            latency_ns = time.perf_counter_ns() - t0
            profile = self._classifier.classify(tool_name)
            action_type = profile.action_type if profile else "unknown"
            evidence.record_decision(tool_name=tool_name, action_type=action_type,
                                     admitted=admitted, reason=reason, latency_ns=latency_ns)
            if not admitted:
                denied_results.append(ChatToolResultMessage(
                    role="tool",
                    content=[text_content_block_from_string(
                        f"APC_DENIED: {reason}. Choose a different action.")],
                    tool_call_id=tool_call.id, tool_call=tool_call,
                    error=f"APC_DENIED: {reason}",
                ))
            else:
                admitted_tool_calls.append(tool_call)

        if denied_results:
            all_denied = []
            for tool_call in last_msg["tool_calls"]:
                if tool_call in admitted_tool_calls:
                    all_denied.append(ChatToolResultMessage(
                        role="tool",
                        content=[text_content_block_from_string(
                            "Action blocked: another action in this turn was denied.")],
                        tool_call_id=tool_call.id, tool_call=tool_call,
                        error="APC: turn denied",
                    ))
                else:
                    for dr in denied_results:
                        if dr["tool_call_id"] == tool_call.id:
                            all_denied.append(dr)
                            break
            return query, runtime, env, list(messages) + all_denied, extra_args

        return query, runtime, env, messages, extra_args

    def _evaluate_tool_call(self, session, tool_name, tool_args):
        profile = self._classifier.classify(tool_name)
        if profile is None:
            return True, "unknown tool, fail-open"
        target_resource = tool_args.get("resource", tool_args.get("target",
                          tool_args.get("file_id", tool_name)))
        target_resource = self._infer_resource(tool_name, target_resource)
        resolved = self._resolve_resource_in_scope(
            target_resource, session.envelope.effective_scope.resources)
        if resolved is None:
            return False, f"DENIED: resource {target_resource} not in scope"
        action = ProposedAction(
            action_type=profile.action_type, target_resource=resolved,
            parameters=tool_args,
            actor_principal_id=session.envelope.chain[-1].principal_id,
            task_session_id=session.session_id,
            policy_version=session.envelope.policy_version,
            sensitivity_class=profile.default_sensitivity,
            blast_radius=profile.blast_radius,
            irreversible_effects=profile.irreversible_effects,
            is_cross_domain=profile.is_cross_domain,
            compute_cost=profile.compute_cost,
            irreversibility_score=profile.irreversibility_score,
            blast_radius_score=profile.blast_radius_score,
            sensitivity_score=profile.sensitivity_score,
        )
        decision = session.pdp.evaluate(
            action, session.envelope, session.budget,
            session.composition_checker, intent_checker=session.intent_checker,
        )
        if not decision.admitted and self._auto_approve_c4:
            # Check if C4 (approval) is the ONLY failing condition
            conds = decision.condition_results or {}
            c4_failed = not conds.get("approval_binding", type("", (), {"passed": True})).passed
            other_failures = [k for k, v in conds.items()
                              if k != "approval_binding" and not v.passed]
            if c4_failed and not other_failures:
                # Auto-generate approval token and re-evaluate
                import uuid as _uuid
                token_id = f"auto-{_uuid.uuid4().hex[:8]}"
                session.approval_store.issue(
                    token_id=token_id,
                    action_type=action.action_type,
                    target_resource=action.target_resource,
                    parameters=action.parameters,
                    scope_snapshot={},
                    approver_id="simulated-human",
                    policy_version=action.policy_version,
                    task_session_id=session.session_id,
                )
                decision = session.pdp.evaluate(
                    action, session.envelope, session.budget,
                    session.composition_checker,
                    approval_token_id=token_id,
                    intent_checker=session.intent_checker,
                )
        return (True, "ADMITTED") if decision.admitted else (False, decision.summary)

    def _resolve_resource_in_scope(self, resource, scope_resources):
        if resource in scope_resources:
            return resource
        for pattern in scope_resources:
            if glob_match(pattern, resource):
                return pattern
        return None

    def _infer_resource(self, tool_name, raw_target):
        raw = str(raw_target) if raw_target else tool_name
        if tool_name in ("get_current_day", "get_current_time"):
            return "calendar:current"
        if "email" in tool_name or "mail" in tool_name:
            return f"email:{raw}"
        if "calendar" in tool_name or "event" in tool_name:
            return f"calendar:{raw}"
        if "file" in tool_name or "list_files" == tool_name:
            return f"files:{raw}"
        # Travel — check before generic "contact" to catch get_contact_information_for_restaurants
        if "restaurant" in tool_name or "cuisine" in tool_name or "dietary" in tool_name or "opening_hours" in tool_name:
            return f"restaurants:{raw}"
        if "hotel" in tool_name:
            return f"hotels:{raw}"
        if "flight" in tool_name:
            return f"flights:{raw}"
        if "car" in tool_name and ("rental" in tool_name or "fuel" in tool_name or "price" in tool_name or "type" in tool_name):
            return f"cars:{raw}"
        if tool_name in ("reserve_hotel",):
            return f"hotels:{raw}"
        if tool_name in ("reserve_restaurant",):
            return f"restaurants:{raw}"
        if tool_name in ("reserve_car_rental",):
            return f"cars:{raw}"
        if tool_name in ("get_user_information",):
            return f"user:{raw}"
        # Generic contact (after travel-specific checks)
        if "contact" in tool_name:
            return f"contacts:{raw}"
        # Banking
        if tool_name in ("get_balance", "get_iban", "get_user_info",
                         "get_most_recent_transactions", "get_scheduled_transactions",
                         "update_user_info", "update_password", "read_file"):
            return f"account:{raw}"
        if tool_name in ("send_money", "schedule_transaction", "update_scheduled_transaction"):
            return f"transaction:{raw}"
        # Slack
        if "channel" in tool_name:
            return f"channels:{raw}"
        if "inbox" in tool_name or "direct_message" in tool_name:
            return f"messages:{raw}"
        if "user" in tool_name and "slack" in tool_name:
            return f"users:{raw}"
        if tool_name in ("add_user_to_channel",):
            return f"channels:{raw}"
        # Web
        if "webpage" in tool_name or "web" in tool_name:
            return f"web:{raw}"
        return raw

    @property
    def all_evidence(self):
        return dict(self._evidence)

    def new_run(self):
        self._run_counter += 1

    def reset(self):
        self._sessions.clear()
        self._evidence.clear()
        self._run_counter = 0
