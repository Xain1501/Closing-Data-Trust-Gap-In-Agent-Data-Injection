"""Ephemeral, per-run store for external values and field tags."""
from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
from threading import RLock
from typing import Any


@dataclass(frozen=True)
class StoredValue:
    normalized_value: str
    source_tag_id: str
    source_interception_id: str | None
    source_path: str
    batch_id: int | None = None
    provenance: str = "EXTERNAL"
    has_forgery: bool = False
    has_mimicry: bool = False
    stripped_value: str = ""            # no spaces, dashes or punctuation: IBAN groups, phones


def number_key(value: float | int) -> str:
    """One text form per number, so 98.7, 98.70 and "98.70" compare equal."""
    as_float = float(value)
    return str(int(as_float)) if as_float.is_integer() else repr(as_float)


# Retain the original exported type name for callers that only store EXTERNAL values.
StoredExternalValue = StoredValue


@dataclass
class RunState:
    run_id: str
    user_prompt: str | None = None
    max_values: int = 10_000
    max_chars: int = 2_000_000
    min_length: int = 4
    overflowed: bool = False
    blind: bool = False
    dropped_values: int = 0
    dropped_chars: int = 0
    values: list[StoredValue] = field(default_factory=list)
    prompts: list[str] = field(default_factory=list)   # every user prompt of a multi-turn run
    # (untrusted leaf tag id, mentioned field tag id): a field's value written inside
    # another untrusted field of the same result. Graph edges, never forgery flags.
    mentions: list[tuple[str, str]] = field(default_factory=list)
    tags_by_interception: dict[str, tuple[Any, ...]] = field(default_factory=dict)
    _char_count: int = 0
    _lock: RLock = field(default_factory=RLock, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not self.run_id:
            raise ValueError("run_id must not be empty")
        if self.max_values < 0 or self.max_chars < 0 or self.min_length < 1:
            raise ValueError("RunState limits must be non-negative and min_length positive")
        if self.user_prompt and not self.prompts:
            self.prompts.append(self.user_prompt)
        self._seen: set[tuple[str | None, str]] = set()

    def add_result_tags(self, tags: list[Any], fields: list[Any], batch_id: int | None = None) -> None:
        """Index normalized SYSTEM/EXTERNAL string leaves; never export raw values."""
        from provenance.lineage import normalise, stripped
        from trust_graph.tagging import Provenance

        by_path = {field.path: field for field in fields}
        with self._lock:
            if tags and tags[0].interception_id:
                key = tags[0].interception_id
                self.tags_by_interception[key] = (
                    *self.tags_by_interception.get(key, ()), *tags
                )
            for tag in tags:
                source = by_path.get(tag.path)
                if source is None or tag.provenance not in (Provenance.SYSTEM, Provenance.EXTERNAL):
                    continue
                if (source.value_type == "number" and isinstance(source.value, (int, float))
                        and not isinstance(source.value, bool)):
                    value = number_key(source.value)    # numbers: canonical text, no length rule
                elif source.value_type == "string" and isinstance(source.value, str):
                    value = normalise(source.value)
                    # Short values are indexed too: lineage matches them only against
                    # a whole field, cell or token, never inside text.
                    if not value:
                        continue
                else:
                    continue
                seen_key = (tag.interception_id, value)
                if seen_key in self._seen:
                    continue                    # a cell equal to its whole leaf: index once
                if len(self.values) >= self.max_values or self._char_count + len(value) > self.max_chars:
                    self.overflowed = True
                    self.blind = True           # dropped values leave lineage incomplete
                    self.dropped_values += 1
                    self.dropped_chars += len(value)
                    continue
                self.values.append(
                    StoredValue(value, tag.tag_id, tag.interception_id, tag.path,
                                batch_id, tag.provenance.value, tag.has_forgery,
                                getattr(tag, "has_mimicry", False), stripped(value))
                )
                self._char_count += len(value)
                self._seen.add(seen_key)

    def add_mentions(self, tags: list[Any], fields: list[Any]) -> None:
        """Record where one result field's value is written inside another untrusted field
        of the same result ("CC @eqy" mentions the real login field)."""
        from provenance.lineage import normalise
        from trust_graph.tagging import Provenance

        by_path = {f.path: f for f in fields}
        own = [(t, by_path.get(t.path)) for t in tags if ".@" not in t.path]
        values = [(t, normalise(f.value)) for t, f in own
                  if f is not None and f.key is not None and isinstance(f.value, str)
                  and len(f.value.strip()) >= 4]
        found: list[tuple[str, str]] = []
        for leaf_tag, leaf in own:
            if (leaf is None or not isinstance(leaf.value, str) or leaf_tag.provenance is not Provenance.EXTERNAL
                    or len(found) >= 200):
                continue
            text = normalise(leaf.value)
            for other_tag, value in values:
                if other_tag.path == leaf_tag.path or value == text:
                    continue
                if other_tag.path.startswith(leaf_tag.path) or leaf_tag.path.startswith(other_tag.path):
                    continue
                if value in text:
                    found.append((leaf_tag.tag_id, other_tag.tag_id))
        with self._lock:
            self.mentions.extend(found)

    def snapshot_values(self) -> tuple[StoredValue, ...]:
        """The indexed values, read under the lock (another thread may be appending)."""
        with self._lock:
            return tuple(self.values)

    def record_argument_tags(self, tags: list[Any]) -> None:
        with self._lock:
            for tag in tags:
                if tag.interception_id:
                    current = self.tags_by_interception.get(tag.interception_id, ())
                    self.tags_by_interception[tag.interception_id] = (*current, tag)

    def clear(self) -> None:
        """Forget prompts, raw-derived values, and tags at the end of a run."""
        with self._lock:
            self.user_prompt = None
            self.prompts.clear()
            self.mentions.clear()
            self._seen.clear()
            self.values.clear()
            self.tags_by_interception.clear()
            self._char_count = 0
            self.overflowed = False
            self.blind = False
            self.dropped_values = 0
            self.dropped_chars = 0


class RunStateStore:
    """Thread-safe lookup for active run states; callers explicitly end each run."""

    def __init__(self, *, max_runs: int = 1024, **state_limits: int) -> None:
        if max_runs < 1:
            raise ValueError("max_runs must be positive")
        self.max_runs = max_runs
        self.state_limits = state_limits
        self._states: OrderedDict[str, RunState] = OrderedDict()
        self._expired: OrderedDict[str, None] = OrderedDict()
        self._lock = RLock()

    def get_or_create(self, run_id: str, user_prompt: str | None = None) -> RunState:
        if not run_id:
            raise ValueError("run_id must not be empty")
        with self._lock:
            state = self._states.get(run_id)
            if state is None:
                while len(self._states) >= self.max_runs:
                    expired_id, expired = self._states.popitem(last=False)
                    expired.clear()
                    self._expired[expired_id] = None
                    while len(self._expired) > self.max_runs:
                        self._expired.popitem(last=False)
                state = RunState(run_id=run_id, user_prompt=user_prompt, **self.state_limits)
                if run_id in self._expired:
                    state.blind = True
                    self._expired.pop(run_id, None)
                self._states[run_id] = state
            else:
                self._states.move_to_end(run_id)
                if user_prompt is not None:
                    if state.user_prompt is None:
                        state.user_prompt = user_prompt
                    if user_prompt not in state.prompts:
                        # A later turn of a multi-turn chat: every prompt the user wrote
                        # can ground a value. (Setting blind here made every real chat blind.)
                        state.prompts.append(user_prompt)
            return state

    def get(self, run_id: str) -> RunState | None:
        with self._lock:
            return self._states.get(run_id)

    def end_run(self, run_id: str) -> bool:
        with self._lock:
            state = self._states.pop(run_id, None)
        if state is None:
            return False
        state.clear()
        return True

    def clear(self) -> None:
        with self._lock:
            states = list(self._states.values())
            self._states.clear()
            self._expired.clear()
        for state in states:
            state.clear()
