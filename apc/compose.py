"""
apc_compose — Composition closure checker.

Implements semantic action classes, restriction templates,
and incremental enforcement.

Supports two levels of composition restrictions:
  - Pairwise (k=2): O(|exercised_classes|) per check. Unordered — any
    co-occurrence of the pair in the session triggers a violation.
  - k-tuple (k≥2): O(|history| * |k-tuple restrictions|) per check.
    Order-preserving subsequence match — the k actions must appear in
    the specified order (not necessarily consecutively) in the session.

Resource-qualified k-tuples additionally constrain which resources
participate in the sequence, enabling fine-grained restrictions like
"read from email:* THEN write to calendar:* THEN send_internal"
without blocking the individual actions in other contexts.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

from apc.core import CompositionPair, CompositionSequence


# ---------------------------------------------------------------------------
# Semantic Action Classes
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ActionClassMapping:
    """Maps concrete tool operations to semantic action classes."""

    _mapping: tuple[tuple[str, str], ...] = ()

    def classify(self, action_type: str) -> str:
        """Return the semantic class for a concrete action type.

        Exact match first, then longest-prefix match for determinism.
        """
        mapping = dict(self._mapping)
        if action_type in mapping:
            return mapping[action_type]
        # Sort by key length descending so longest prefix wins
        for pattern, cls in sorted(self._mapping, key=lambda x: len(x[0]), reverse=True):
            if action_type.startswith(pattern):
                return cls
        return action_type  # fallback: action is its own class

    @staticmethod
    def from_dict(mapping: dict[str, str]) -> ActionClassMapping:
        return ActionClassMapping(_mapping=tuple(mapping.items()))


# ---------------------------------------------------------------------------
# Restriction Templates
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RestrictionTemplate:
    """Parameterized composition restriction.

    DENY_COMPOSE(source_class, target_class) generates the pair.
    """

    source_class: str
    target_class: str

    @property
    def pair(self) -> CompositionPair:
        return (self.source_class, self.target_class)

    @staticmethod
    def deny_compose(source: str, target: str) -> RestrictionTemplate:
        return RestrictionTemplate(source_class=source, target_class=target)


def compile_templates(templates: list[RestrictionTemplate]) -> frozenset[CompositionPair]:
    """Compile templates into a concrete restriction set X."""
    return frozenset(t.pair for t in templates)


# ---------------------------------------------------------------------------
# k-tuple Restriction Templates
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class KTupleRestriction:
    """A prohibited ordered sequence of k action classes.

    Unlike pairwise restrictions (which are unordered — any co-occurrence
    triggers), k-tuple restrictions are order-preserving: the actions must
    appear in the specified order as a subsequence of the session history.

    Resource qualifiers optionally constrain which resources participate.
    A None qualifier means "any resource for this step".

    Example:
        KTupleRestriction(
            sequence=("read", "write", "send_internal"),
            resource_qualifiers=(("email:*",), None, None),
        )
    Blocks: read(email:msg-1) → write(file:x) → send_internal(calendar:y)
    Allows: write(file:x) → read(email:msg-1) → send_internal(calendar:y)
            (wrong order — read must come before write)
    """

    sequence: CompositionSequence
    resource_qualifiers: tuple[tuple[str, ...] | None, ...] = ()

    def __post_init__(self) -> None:
        if len(self.sequence) < 2:
            raise ValueError("k-tuple restriction must have k >= 2")
        if self.resource_qualifiers and len(self.resource_qualifiers) != len(self.sequence):
            raise ValueError(
                f"resource_qualifiers length ({len(self.resource_qualifiers)}) "
                f"must match sequence length ({len(self.sequence)})"
            )

    @property
    def k(self) -> int:
        return len(self.sequence)

    @staticmethod
    def deny_sequence(*action_classes: str) -> KTupleRestriction:
        """Create a k-tuple restriction without resource qualifiers."""
        return KTupleRestriction(sequence=tuple(action_classes))

    @staticmethod
    def deny_qualified_sequence(
        steps: list[tuple[str, tuple[str, ...] | None]],
    ) -> KTupleRestriction:
        """Create a resource-qualified k-tuple restriction.

        Args:
            steps: list of (action_class, resource_patterns_or_None) tuples.
        """
        sequence = tuple(s[0] for s in steps)
        qualifiers = tuple(s[1] for s in steps)
        return KTupleRestriction(sequence=sequence, resource_qualifiers=qualifiers)


# ---------------------------------------------------------------------------
# Composition Closure Checker (incremental, pairwise + k-tuple)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _HistoryEntry:
    """A recorded action in the session history with its resource context."""
    action_class: str
    resource: str = ""


class CompositionChecker:
    """Incremental composition closure enforcement.

    Maintains a running set of exercised action classes (for pairwise)
    and an ordered history (for k-tuple checks).

    Thread-safe: all state access is protected by a lock.

    Pairwise check: O(|exercised_classes|) per action.
    k-tuple check: O(|history| * |k-tuple restrictions|) per action.
    """

    def __init__(
        self,
        restrictions: frozenset[CompositionPair] = frozenset(),
        class_mapping: ActionClassMapping | None = None,
        k_tuple_restrictions: tuple[KTupleRestriction, ...] = (),
        composition_overrides: frozenset[CompositionPair] = frozenset(),
    ) -> None:
        self._restrictions = restrictions
        self._class_mapping = class_mapping or ActionClassMapping()
        self._k_tuple_restrictions = k_tuple_restrictions
        self._composition_overrides = composition_overrides
        self._exercised_classes: set[str] = set()
        self._action_history: list[str] = []
        self._history_entries: list[_HistoryEntry] = []
        self._lock = threading.Lock()

    def check(self, action_type: str, resource: str = "") -> CompositionCheckResult:
        """Check if adding this action violates composition closure.

        Does NOT record the action — call record() after execution.
        """
        action_class = self._class_mapping.classify(action_type)
        violations: list[CompositionPair] = []
        k_tuple_violations: list[CompositionSequence] = []

        with self._lock:
            # --- Pairwise check ---
            # Composition overrides allow pre-authorized pairs to bypass
            # pairwise restrictions. This implements the paper's model where
            # explicit user authorization (C4/C5) can override composition
            # closure (C2b) for declared workflows.
            #
            # Iterate in sorted order so the reported violation tuple is
            # deterministic across processes. Set iteration order depends on
            # string hash randomization, which would otherwise make the
            # emitted evaluation artifacts differ run to run. Admissibility
            # itself depends only on whether the list is empty, so this
            # affects reporting order only.
            for exercised in sorted(self._exercised_classes):
                pair_fwd = (exercised, action_class)
                if pair_fwd in self._restrictions and pair_fwd not in self._composition_overrides:
                    violations.append(pair_fwd)
                pair_rev = (action_class, exercised)
                if pair_rev in self._restrictions and pair_rev not in self._composition_overrides:
                    violations.append(pair_rev)

            # --- k-tuple check ---
            if self._k_tuple_restrictions:
                candidate_entry = _HistoryEntry(action_class=action_class, resource=resource)
                candidate_history = self._history_entries + [candidate_entry]

                for restriction in self._k_tuple_restrictions:
                    if _is_subsequence_match(candidate_history, restriction):
                        k_tuple_violations.append(restriction.sequence)

        all_violations = violations
        has_k_violations = len(k_tuple_violations) > 0

        return CompositionCheckResult(
            allowed=len(all_violations) == 0 and not has_k_violations,
            violations=tuple(all_violations),
            action_class=action_class,
            k_tuple_violations=tuple(k_tuple_violations),
        )

    def record(self, action_type: str, resource: str = "") -> None:
        """Record an executed action in the session history."""
        action_class = self._class_mapping.classify(action_type)
        with self._lock:
            self._exercised_classes.add(action_class)
            self._action_history.append(action_type)
            self._history_entries.append(_HistoryEntry(action_class=action_class, resource=resource))

    def check_and_record(self, action_type: str, resource: str = "") -> CompositionCheckResult:
        """Check then record if allowed. Atomic under lock."""
        action_class = self._class_mapping.classify(action_type)
        violations: list[CompositionPair] = []
        k_tuple_violations: list[CompositionSequence] = []

        with self._lock:
            # Sorted for deterministic reporting order; see check().
            for exercised in sorted(self._exercised_classes):
                pair_fwd = (exercised, action_class)
                if pair_fwd in self._restrictions and pair_fwd not in self._composition_overrides:
                    violations.append(pair_fwd)
                pair_rev = (action_class, exercised)
                if pair_rev in self._restrictions and pair_rev not in self._composition_overrides:
                    violations.append(pair_rev)

            if self._k_tuple_restrictions:
                candidate_entry = _HistoryEntry(action_class=action_class, resource=resource)
                candidate_history = self._history_entries + [candidate_entry]
                for restriction in self._k_tuple_restrictions:
                    if _is_subsequence_match(candidate_history, restriction):
                        k_tuple_violations.append(restriction.sequence)

            result = CompositionCheckResult(
                allowed=len(violations) == 0 and len(k_tuple_violations) == 0,
                violations=tuple(violations),
                action_class=action_class,
                k_tuple_violations=tuple(k_tuple_violations),
            )

            if result.allowed:
                self._exercised_classes.add(action_class)
                self._action_history.append(action_type)
                self._history_entries.append(
                    _HistoryEntry(action_class=action_class, resource=resource)
                )

        return result

    @property
    def exercised_classes(self) -> frozenset[str]:
        with self._lock:
            return frozenset(self._exercised_classes)

    @property
    def action_history(self) -> list[str]:
        with self._lock:
            return list(self._action_history)

    def reset(self) -> None:
        with self._lock:
            self._exercised_classes.clear()
            self._action_history.clear()
            self._history_entries.clear()


def _is_subsequence_match(
    history: list[_HistoryEntry],
    restriction: KTupleRestriction,
) -> bool:
    """Check if the restriction's sequence appears as an ordered subsequence.

    Greedy left-to-right scan: for each step in the restriction sequence,
    find the earliest matching entry in the history after the previous match.

    With resource qualifiers: the entry's resource must match at least one
    of the qualifier patterns (using glob matching).
    """
    from apc.core import glob_match

    seq = restriction.sequence
    qualifiers = restriction.resource_qualifiers
    has_qualifiers = bool(qualifiers)

    seq_idx = 0  # next step in the restriction to match
    for entry in history:
        if seq_idx >= len(seq):
            break
        if entry.action_class == seq[seq_idx]:
            # Check resource qualifier if present
            if has_qualifiers and qualifiers[seq_idx] is not None:
                patterns = qualifiers[seq_idx]
                if not any(glob_match(p, entry.resource) for p in patterns):
                    continue  # resource doesn't match, skip this entry
            seq_idx += 1

    return seq_idx >= len(seq)


@dataclass(frozen=True)
class CompositionCheckResult:
    allowed: bool
    violations: tuple[CompositionPair, ...] = ()
    action_class: str = ""
    k_tuple_violations: tuple[CompositionSequence, ...] = ()
