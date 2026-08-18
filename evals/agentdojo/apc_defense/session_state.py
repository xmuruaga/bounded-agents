"""Per-session APC state for AgentDojo tasks."""
from __future__ import annotations
import time, sys
from dataclasses import dataclass, field
from typing import Any
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent))

from apc.approval import ApprovalStore
from apc.budget import BudgetState
from apc.calibrate import ImpactWeights
from apc.compose import CompositionChecker
from apc.core import AuthorizationEnvelope, ExecutionRole, Principal
from apc.intent import IntentChecker, IntentEnforcementMode, IntentSpec
from apc.pdp import EvidenceSink, PolicyDecisionPoint
from apc_defense.scope_registry import SuiteScope

SIGNING_KEY = b"agentdojo-apc-evaluation-key-2026"


@dataclass
class SessionState:
    session_id: str
    envelope: AuthorizationEnvelope
    budget: BudgetState
    composition_checker: CompositionChecker
    intent_checker: IntentChecker
    pdp: PolicyDecisionPoint
    approval_store: ApprovalStore
    evidence_sink: EvidenceSink
    call_log: list[dict[str, Any]] = field(default_factory=list)

    @staticmethod
    def create(session_id, suite_scope, user_task_prompt,
               impact_weights=None, approval_threshold=0.5,
               intent_mode=IntentEnforcementMode.STRICT):
        if impact_weights is None:
            impact_weights = ImpactWeights(alpha=0.4, beta=0.35, gamma=0.25)
        user = Principal("agentdojo-user", ExecutionRole.AS_USER, suite_scope.scope)
        agent = Principal("agentdojo-agent", ExecutionRole.AS_AGENT, suite_scope.scope)
        envelope = AuthorizationEnvelope(
            envelope_id=f"env-{session_id}", task_session_id=session_id,
            originating_principal=user, effective_scope=suite_scope.scope,
            budget_spec=suite_scope.budget_spec, expires_at=time.time() + 7200,
        )
        envelope.sign(SIGNING_KEY)
        agent_envelope = envelope.narrow(agent, SIGNING_KEY)
        approval_store = ApprovalStore()
        evidence_sink = EvidenceSink()
        pdp = PolicyDecisionPoint(
            signing_key=SIGNING_KEY, impact_weights=impact_weights,
            approval_threshold=approval_threshold,
            approval_store=approval_store, evidence_sink=evidence_sink,
        )
        budget = BudgetState(spec=suite_scope.budget_spec)
        intent_spec = _parse_intent_from_prompt(user_task_prompt, intent_mode)
        # Derive composition overrides from the declared intent.
        # If the user's prompt explicitly requires both sides of a prohibited
        # pair (e.g., read + send_external), the pair is overridden for this
        # session. This implements the paper's model: explicit user
        # authorization can override composition closure for declared workflows.
        composition_overrides = _derive_composition_overrides(
            intent_spec, agent_envelope.effective_scope.composition_restrictions,
        )
        composition_checker = CompositionChecker(
            restrictions=agent_envelope.effective_scope.composition_restrictions,
            class_mapping=suite_scope.class_mapping,
            k_tuple_restrictions=suite_scope.k_tuple_restrictions,
            composition_overrides=composition_overrides,
        )
        intent_checker = IntentChecker(intent_spec=intent_spec)
        return SessionState(
            session_id=session_id, envelope=agent_envelope, budget=budget,
            composition_checker=composition_checker, intent_checker=intent_checker,
            pdp=pdp, approval_store=approval_store, evidence_sink=evidence_sink,
        )


def _derive_composition_overrides(intent_spec, restrictions):
    """Derive composition overrides from the declared intent.

    For each prohibited pair (A, B) in the restriction set, if the intent
    explicitly permits both A and B as action sequences, the pair is
    overridden — the user has declared a workflow that requires this
    composition.

    This is the mechanism by which explicit user authorization (§5 C4/C5)
    overrides composition closure (§5 C2b) for declared workflows.
    Without this, read→send_external is always blocked even when the user
    explicitly requests "read file X and email it to Y."
    """
    if intent_spec is None:
        return frozenset()
    permitted = set(intent_spec.permitted_action_sequences)
    if not permitted:
        return frozenset()
    overrides = set()
    for source, target in restrictions:
        if source in permitted and target in permitted:
            overrides.add((source, target))
    return frozenset(overrides)


def _parse_intent_from_prompt(prompt, mode=IntentEnforcementMode.STRICT):
    """Parse a user prompt into a structured IntentSpec.

    This is a deterministic, keyword-based parser — no LLM involved.
    It operates in two phases:

    Phase 1 (resource detection): identify which resource domains the
    prompt references (email, calendar, files, contacts, etc.).

    Phase 2 (action-resource binding): for each detected resource domain,
    determine which action types the prompt requires *on that domain*.
    This is the key refinement over a flat action list: "reschedule my
    dental check-up" grants write on calendar:* but NOT write on files:*.

    The result uses IntentSpec's action_resource_map for fine-grained
    per-domain action binding, with coarse-grained patterns as fallback
    for actions not tied to a specific domain (e.g., read is always
    permitted on detected resources).
    """
    prompt_lower = prompt.lower()

    # Word-boundary matching to avoid substring false positives
    # (e.g., "facebook" matching "book", "invited" matching "invite").
    import re
    _word_cache = {}

    def _has_word(word):
        """Check if `word` appears as a word-start in the prompt.

        Uses \\b on the left (word must start at a boundary) but allows
        common suffixes (plurals, -ed, -ing, -s) on the right. This
        prevents "facebook" from matching "book" while allowing "emails"
        to match "email" and "appointments" to match "appointment".
        """
        if word not in _word_cache:
            _word_cache[word] = bool(
                re.search(r'\b' + re.escape(word) + r'(?:s|ed|ing|es|er)?\b', prompt_lower)
            )
        return _word_cache[word]

    def _has_any_word(words):
        return any(_has_word(w) for w in words)

    def _has_any_phrase(phrases):
        """Check if any multi-word phrase appears (substring match is fine for phrases)."""
        return any(p in prompt_lower for p in phrases)

    # --- Detect delegated / open-ended tasks ---
    is_delegated = _has_any_phrase([
        "do the actions", "perform the actions", "execute the actions",
        "follow the instructions", "do what it says", "as specified in",
        "as described in", "as mentioned in", "according to the email",
        "do all the tasks", "perform the following tasks",
        "follow the instructions precisely",
    ])

    # ================================================================
    # Phase 1: Resource domain detection
    # ================================================================
    has_email = _has_any_word([
        "email", "mail", "inbox", "message",
    ])
    has_calendar = _has_any_word([
        "calendar", "event", "meeting", "schedule",
        "appointment", "lunch", "dinner", "trip", "hiking",
        "reunion", "free", "busy", "available",
        "check-up", "checkup", "dental",
    ])
    # Temporal queries ("when is my next X") imply calendar lookup
    if not has_calendar:
        has_calendar = _has_any_phrase([
            "when is my next", "when is the next", "my next",
        ])
    has_files = _has_any_word([
        "file", "document", "doc", "folder", "minutes",
        "drive", "packing",
    ]) or _has_any_phrase([
        ".txt", ".docx", ".pdf", ".xlsx",
    ])
    has_contacts = _has_any_word(["contact", "address"])
    has_banking = _has_any_word([
        "balance", "account", "transaction", "transfer", "bank",
        "spending", "spend", "payment", "refund", "bill",
        "rent", "subscription", "iban",
    ]) or _has_any_phrase([
        "pay the", "send them", "send her", "send him",
        "how much", "total spending",
    ])
    has_web = _has_any_word([
        "web", "url", "http", "page", "link", "password",
        "website",
    ]) or _has_any_phrase([
        "www.", ".com", "websites",
    ])
    has_travel = _has_any_word([
        "hotel", "flight", "restaurant", "car", "rental",
        "book", "reserve", "reservation", "trip",
        "cuisine", "vegan", "rating", "price",
        "city", "paris", "london", "tokyo", "angeles",
    ]) or _has_any_phrase([
        "car rental", "looking to book", "heading to",
        "going to", "arriving in", "planning a trip",
        "planning to visit",
    ])
    has_slack = _has_any_word([
        "channel", "slack", "dm",
    ]) or _has_any_phrase([
        "post the", "post to", "invite ", "add ",
        "direct message", "send it to",
        "read the content", "summarize the",
    ])

    resource_patterns = []
    if has_email:
        resource_patterns.append("email:*")
    if has_calendar:
        resource_patterns.append("calendar:*")
    if has_files:
        resource_patterns.append("files:*")
    if has_contacts:
        resource_patterns.append("contacts:*")
    if has_banking:
        resource_patterns.extend(["account:*", "transaction:*"])
    if has_web:
        resource_patterns.append("web:*")
    if has_travel:
        for r in ["hotels:*", "flights:*", "restaurants:*", "cars:*", "user:*"]:
            if r not in resource_patterns:
                resource_patterns.append(r)
    if has_slack:
        for r in ["channels:*", "messages:*", "users:*"]:
            if r not in resource_patterns:
                resource_patterns.append(r)

    if is_delegated:
        for r in ["email:*", "calendar:*", "files:*", "contacts:*",
                   "channels:*", "messages:*", "users:*", "web:*"]:
            if r not in resource_patterns:
                resource_patterns.append(r)

    # ================================================================
    # Phase 2: Action-resource binding (fine-grained)
    # ================================================================

    # --- Read intent (universal — applies to all detected resources) ---
    # Note: "invited", "participants" etc. use word-boundary matching
    # to avoid "invited" triggering write/invite intent.
    has_read_intent = _has_any_word([
        "read", "get", "find", "search", "check", "look", "show",
        "who", "what", "when", "where", "which", "how", "list",
        "tell", "give", "provide", "display", "retrieve", "fetch",
        "summarize", "summary", "review", "see", "view", "open",
        "invited", "participants", "attendees", "recipients",
        "scores",
    ]) or _has_any_phrase([
        "based on", "according to", "from the", "am i", "do i have",
        "if so", "if not",
    ])

    # --- Send intent (email-specific) ---
    has_send_intent = _has_any_word([
        "send", "reply", "forward", "notify",
    ]) or _has_any_phrase([
        "write to", "reach out",
        "send email", "send mail", "send a mail", "send an email",
        "email them", "email her", "email him", "email it",
        "mail them", "mail her", "mail him", "mail it",
    ])

    # --- Write intent: detect WHAT the user wants to write/create ---
    # Calendar write: create/schedule/reschedule/book events
    # "book" uses word boundary to avoid "facebook" matching
    has_cal_write = has_calendar and (_has_any_word([
        "create", "schedule", "reschedule", "book", "arrange",
    ]) or _has_any_phrase([
        "set up", "add ", "invite ", "participant",
    ]))

    # File write: create/add/append/modify files
    has_file_write = has_files and _has_any_word([
        "create", "add", "write", "append", "suggest", "update",
        "edit", "modify", "rename", "move", "share",
    ])

    # Generic write (no specific domain detected — fallback)
    has_generic_write = (not has_cal_write and not has_file_write) and _has_any_word([
        "create", "add", "write", "update", "set", "change",
        "modify", "schedule", "book", "arrange", "edit",
        "rename", "move",
    ])

    # --- Delete intent: detect WHAT the user wants to delete ---
    has_cal_delete = has_calendar and _has_any_word(["delete", "remove", "cancel"])
    has_file_delete = has_files and _has_any_word(["delete", "remove"])
    has_email_delete = has_email and _has_any_word(["delete", "remove"])
    has_generic_delete = (
        not has_cal_delete and not has_file_delete and not has_email_delete
    ) and _has_any_word(["delete", "remove", "cancel"])

    # --- Transfer intent ---
    has_transfer = _has_any_word(["transfer", "pay", "refund"]) or _has_any_phrase([
        "send money", "send them the", "send her the", "send him the",
        "pay the bill", "adjust my", "set up a recurring",
    ])

    # --- Invite intent (calendar-specific send_internal) ---
    # "invite" as imperative verb, not "invited" as past participle (read intent)
    has_invite = _has_any_word(["invite"]) and not _has_any_word(["invited"])
    if not has_invite:
        has_invite = _has_any_phrase(["participant"])

    # --- Travel write intent (book/reserve) ---
    has_travel_write = has_travel and (_has_any_word([
        "book", "reserve", "suggest", "recommend",
    ]) or _has_any_phrase([
        "looking to book", "help me find",
    ]))

    # --- Slack write intent (post/send/invite) ---
    has_slack_write = has_slack and (_has_any_word([
        "post", "write", "reply", "invite", "add",
    ]) or _has_any_phrase([
        "send it to", "message them", "post the",
    ]))
    has_slack_send = has_slack and (_has_any_word([
        "send", "post", "message", "write",
    ]) or _has_any_phrase([
        "send it to", "message them",
    ]))

    # --- Banking write intent (update account, schedule) ---
    has_banking_write = has_banking and _has_any_word([
        "update", "adjust", "change", "set", "schedule",
    ])

    # ================================================================
    # Build action_resource_map (fine-grained binding)
    # ================================================================
    arm = {}  # action_type -> set of resource patterns

    # Read is permitted on all detected resource domains
    if has_read_intent or is_delegated or has_travel or has_slack or has_banking:
        all_res = tuple(resource_patterns)
        arm["read"] = all_res
        arm["read_sensitive"] = all_res
        # read_external: prefer web:* if detected; for slack tasks, always
        # include web:* because channel posts commonly contain URLs
        re_resources = tuple(r for r in resource_patterns if r in ("web:*",))
        if not re_resources and has_slack:
            re_resources = ("web:*",)
        arm["read_external"] = re_resources or all_res

    # Send: on email domain + slack if detected
    if has_send_intent or is_delegated:
        arm["send_external"] = ("email:*",)
        arm["send_internal"] = ("email:*",)
        # If slack is detected and user wants to send/reply, include slack channels
        if has_slack:
            existing_int = set(arm.get("send_internal", ()))
            existing_int.update(["channels:*", "messages:*", "users:*"])
            arm["send_internal"] = tuple(sorted(existing_int))
    if has_slack_send:
        existing_ext = set(arm.get("send_external", ()))
        existing_int = set(arm.get("send_internal", ()))
        existing_int.update(["channels:*", "messages:*", "users:*"])
        arm["send_internal"] = tuple(sorted(existing_int))
        # post_webpage is send_external on web:*
        if has_web:
            existing_ext.add("web:*")
            arm["send_external"] = tuple(sorted(existing_ext))

    # Write: bound to the specific domain(s) the user mentioned
    write_resources = set()
    if has_cal_write or is_delegated:
        write_resources.add("calendar:*")
    if has_file_write or is_delegated:
        write_resources.add("files:*")
    if has_travel_write:
        write_resources.update(["hotels:*", "restaurants:*", "cars:*", "calendar:*"])
    if has_slack_write:
        write_resources.update(["channels:*", "messages:*", "users:*"])
    if has_banking_write:
        write_resources.update(["account:*", "transaction:*"])
    if has_generic_write:
        # Fallback: permit write on all detected resources
        write_resources.update(resource_patterns)
    if write_resources:
        arm["write"] = tuple(sorted(write_resources))

    # Delete: bound to the specific domain(s)
    delete_resources = set()
    if has_cal_delete or is_delegated:
        delete_resources.add("calendar:*")
    if has_file_delete or is_delegated:
        delete_resources.add("files:*")
    if has_email_delete or is_delegated:
        delete_resources.add("email:*")
    if has_generic_delete:
        delete_resources.update(resource_patterns)
    if delete_resources:
        arm["delete"] = tuple(sorted(delete_resources))

    # Transfer
    if has_transfer or is_delegated:
        arm["transfer"] = ("account:*", "transaction:*")

    # Invite (send_internal on calendar)
    if has_invite:
        existing = set(arm.get("send_internal", ()))
        existing.add("calendar:*")
        arm["send_internal"] = tuple(sorted(existing))

    # ================================================================
    # Build coarse-grained fallback (permitted_action_sequences)
    # ================================================================
    action_sequences = list(arm.keys())

    # Multi-step: if write/send are present, ensure read is included
    if any(a in action_sequences for a in ["write", "send_external", "send_internal"]):
        for a in ["read", "read_sensitive"]:
            if a not in action_sequences:
                action_sequences.append(a)

    action_sequences = list(dict.fromkeys(action_sequences))

    # Convert arm to the tuple format expected by IntentSpec
    action_resource_map = tuple(
        (action, tuple(sorted(set(resources))))
        for action, resources in sorted(arm.items())
    )

    return IntentSpec(
        task_objective=prompt,
        permitted_resource_patterns=tuple(resource_patterns),
        permitted_action_sequences=tuple(action_sequences),
        negative_constraints=(),
        enforcement_mode=mode,
        action_resource_map=action_resource_map,
    )
