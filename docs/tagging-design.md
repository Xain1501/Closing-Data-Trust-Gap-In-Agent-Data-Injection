# Tagging Stage — Design

Status: **approved for implementation (Phase 1)** · Branch: `zain/tagging` · Owner: Zain
Scope of this document: the field-level tagging stage and its run-level lineage. The graph, classifier and
detector wiring are referenced only where tagging must stay compatible with them.

## Current implementation update (`zain/experimental`)

The active project policy supersedes the older no-profile `UNKNOWN` rule below: object/array structure is
`SYSTEM`, and every scalar leaf is `EXTERNAL` unless a caller supplies an approved profile override.
`FieldTag.has_forgery` maps counted findings to true result fields; when a raw result skeleton is available,
structural scanning uses those source values instead of fields reconstructed from formatted text. Lineage
evidence carries a source field's forgery flag into the risk graph. Lineage supports prompt matches, exact
whole-field `SYSTEM_LINK`s, and exact/bounded-substring `EXTERNAL_LINK`s. `SYSTEM_LINK` is
available when a caller supplies a profile marking a string field as `SYSTEM`; the default policy has no
SYSTEM scalar leaves. Automatic profile loading, call screening, and a separate AuditTrail are not yet wired.

---

## 1. Purpose and position in the pipeline

```
clone -> parser -> TAGGING -> trust-provenance graph -> WL kernel + SVM -> risk gate -> review
```

Tagging answers, for every field of one intercepted message: **where did this value come from
(provenance), may it be trusted (trust), and what part does it play (role)?**

Inputs tagging may use — and nothing else:

| Input | Source |
|---|---|
| The cloned payload | the copy the clone hands to a detector. Pre-hop: `{"tool": name, "args": {...}}`. Post-hop: the formatted result string. |
| The parsed fields of that payload | `ParseResult.fields` / `ParsedField` from `src/parser/models.py` |
| The tool trust profile entry | static, read-only (Section 5) |
| A `RunState` | passed in explicitly by the caller (Section 4) |

Tagging never reads calls or results from the agent, the framework or a tool directly, and never imports
`clone.adapters` or `agentdojo`. It may import framework-neutral clone modules (`clone.core` types,
`clone.tvm`).

---

## 2. Data model

### 2.1 Provenance (where the value came from)

| Value | Meaning |
|---|---|
| `SYSTEM` | produced by the trusted application layer (ids, timestamps, counts, enums the tool itself generates) |
| `USER` | supplied by the user (argument value found in the user prompt) |
| `EXTERNAL` | content a third party can write (email bodies, event descriptions, file contents, web text) |
| `DERIVED` | an argument value produced by the agent; may be linked to its sources |
| `UNKNOWN` | no usable profile (tool not in the profile, or entry still `draft`) |

### 2.2 Trust (computed, never set directly)

| Provenance | Trust |
|---|---|
| `SYSTEM`, `USER` | `T` |
| `EXTERNAL`, `UNKNOWN` | `UT` |
| `DERIVED` | worst of its sources: `UT` if any source is `UT`; `T` only if it has sources and all are `T`. A `DERIVED` value with **no** sources is `UT`. |

Uses the parser's existing `Trust` enum (`T`, `UT`) unchanged.

> **Note (v1):** only `EXTERNAL` values are stored in the RunState, so every link points to an `UT` source and a
> `DERIVED` field with sources is **always `UT`**. In v1 trust alone does not separate a linked value from an
> unlinked one — the useful signal is `lineage_status` and `derived_from` (Section 2.4).

### 2.3 Role

| Role | Meaning |
|---|---|
| `AUTHORITY_ARG` | an argument that decides *who/where/how much*: recipient, URL, path, amount, invitee |
| `CONTENT` | free text (bodies, descriptions, messages) |
| `IDENTIFIER` | ids, handles, keys |
| `OTHER` | everything else |

### 2.4 FieldTag and Evidence (frozen dataclasses)

**FieldTag**

| Field | Type | Notes |
|---|---|---|
| `run_id` | `str` | from `RunState` |
| `interception_id` | `str \| None` | supplied by the caller; `None` until the clone context carries it |
| `direction` | `"pre" \| "post"` | same values as `clone.core.DetectorContext.direction` |
| `path` | `str` | the parser's JSON path, e.g. `$[0].body` |
| `tag_id` | `str` | UUID4 |
| `created_at` | `float` | OS timestamp from an injectable clock (default `time.time`) |
| `provenance` | `Provenance` | |
| `trust` | `Trust` | computed from provenance (2.2) |
| `role` | `Role` | |
| `parent_path` | `str \| None` | from the parser field |
| `value_type` | `str` | parser `ValueType` |
| `length` | `int \| None` | normalised length of string leaves; `None` for non-strings |
| `lineage_status` | `LineageStatus` | `USER_MATCH` \| `EXTERNAL_LINK` \| `UNLINKED` \| `BELOW_MIN` (Section 4.3) |
| `derived_from` | `tuple[Evidence, ...]` | **only real links** to source tags; empty otherwise |

`lineage_status` for **result fields** (post-hop) and for non-string argument fields is always `UNLINKED`:
lineage is only computed for argument string leaves.

**Evidence**

| Field | Type | Notes |
|---|---|---|
| `source_tag_id` | `str \| None` | the linked source tag; `None` only for evidence with no source (not produced in v1) |
| `match_type` | `"equal" \| "substring"` | |
| `matched_length` | `int` | normalised length of the matched argument value |

Because `derived_from` holds only real links, **`if tag.derived_from:` means "linked"**.

**Never stored in a tag: the raw value.** Tags live in a **side record** keyed by JSON path; the payload is
never modified.

**Identifiers** (`tag_id`, `created_at`, hashes, `run_id`, `interception_id`) are for identity and edges only.
They never enter graph or WL labels.

---

## 3. Tagging rules

### 3.1 Results (post-hop) — decisions 4, 5, 6

1. Look up the tool's profile entry.
2. **No entry, or `review_status == "draft"`** → every field `UNKNOWN` (trust `UT`). Not an exception.
3. **`result_format == "text"`** → the whole result is one field `$`, tagged `result_default`.
   Clean prose is **not** `UNKNOWN`.
4. **`result_format == "json"`** → each field is matched against `result_fields`
   (`json_path_pattern → SYSTEM | EXTERNAL`; `[*]` matches any list index). Unmatched fields get
   `result_default` (normally `EXTERNAL`).
5. **Containment:** every field nested inside an `EXTERNAL` field is `EXTERNAL`, whatever its own pattern says
   (applies to nested JSON the parser exposed inside an external value).
6. **Roles of result fields:**

   | Provenance | `value_type` | Role |
   |---|---|---|
   | `EXTERNAL` | string | `CONTENT` |
   | `EXTERNAL` | number, boolean, null, object, array | `OTHER` |
   | `SYSTEM` | string | `IDENTIFIER` |
   | `SYSTEM` | number, boolean, null, object, array | `OTHER` |
   | `UNKNOWN` | any | `OTHER` |

### 3.2 Arguments (pre-hop) — decision 7

- Provenance comes from **lineage** (Section 4), not from the profile.
- The profile only supplies **roles** (which arguments are `AUTHORITY_ARG`); other arguments take the role the
  profile lists, or `OTHER`.
- No entry / `draft` entry: roles default to `OTHER`; lineage still runs.

### 3.3 Expected cases never raise (decision 11)

Unknown tool, draft entry, plain-text result, empty payload → tags are returned. Genuine programming errors
may raise; the clone treats a detector exception as a fail-closed detector error.

---

## 4. RunState and lineage v1 (decisions 8, 12)

### 4.1 RunState

An explicit object passed in by the caller (not read from the clone yet):

- `run_id`
- `user_prompt` (text)
- the `EXTERNAL` leaf values seen so far in the run, each kept as *(normalised value, tag_id)*.

Post-hop tagging **adds** its `EXTERNAL` string leaves to the RunState; pre-hop tagging **reads** them.

**Handling of raw external values.** They are held **in memory only**, inside the RunState. They are **never
exported, logged or written into a tag**, and they are **cleared at the end of the run** (`RunState.clear()`).

**Caps (configurable).**

| Setting | Default |
|---|---|
| `max_values` — maximum number of stored external values | 10,000 |
| `max_chars` — maximum total characters of stored external values | 2,000,000 |

**At the cap:** the RunState **stops storing new values and keeps the earliest ones**. It never drops silently:
it sets `overflowed = True` and counts `dropped_values` and `dropped_chars`. Consequence: after the cap a later
argument may be `UNLINKED` only because its source was not stored (a false negative); consumers must check
`run_state.overflowed`. (Alternative considered and rejected for v1: evicting the oldest values — it keeps recent
sources but has the same flooding weakness.)

### 4.2 Normalisation

Leaf strings are normalised in this order:

1. **percent-decode** — one pass, never recursive (`%2540` becomes `%40`, not `@`)
2. **Unicode NFKC**
3. **casefold**
4. **strip** surrounding whitespace

All length checks use the **final normalised string**. A match requires normalised length **≥ `min_length`**
(default **4**, configurable).

### 4.3 Matching order

For each argument string leaf, in this order:

a) **USER** — the whole normalised argument value appears as a substring of the normalised user prompt.
b) **EXTERNAL source** — the whole normalised argument value **equals**, or is a **substring of**, a
   normalised earlier `EXTERNAL` leaf value.
   The reverse direction (external text inside a longer argument) is **not** matched in v1; it may be added
   later as a separate `match_type` with a higher minimum.

**Boundary rule for identifier-like values.** A match must not be flanked by these characters on either side:

| Value kind | Forbidden flanking characters |
|---|---|
| email address | `[A-Za-z0-9._+-]` |
| URL, path | defined in step 1.3 (Section 9) |

So `bob@x.com` does **not** match inside `evil.bob@x.com` or inside `bob@x.com.evil.com`.

Outcome:

| Result | Provenance | `lineage_status` | `derived_from` |
|---|---|---|---|
| value shorter than `min_length` | `DERIVED` | `BELOW_MIN` | empty |
| (a) matched | `USER` | `USER_MATCH` | empty |
| (b) matched | `DERIVED` | `EXTERNAL_LINK` | one `Evidence` per matched source (`equal` / `substring`, `matched_length`) |
| neither | `DERIVED` | `UNLINKED` | empty |

A below-minimum value is **never** `USER` and **never** linked. If a value is found in both the prompt and an
external field, (a) wins: it is `USER`.

### 4.4 Worked examples

| Scenario | Provenance | `lineage_status` | `derived_from` | Trust |
|---|---|---|---|---|
| Email body (EXTERNAL) contains `mark.black-2134@gmail.com`; agent calls `send_email(recipients=["mark.black-2134@gmail.com"])`; prompt doesn't contain it | `DERIVED` (role `AUTHORITY_ARG`) | `EXTERNAL_LINK` | → the email body's tag, `substring` | `UT` |
| Same call, but the user typed the address in the prompt | `USER` | `USER_MATCH` | empty | `T` |
| Argument `"Hi"` | `DERIVED` | `BELOW_MIN` | empty | `UT` |
| Argument `"quarterly report"`, found nowhere | `DERIVED` | `UNLINKED` | empty | `UT` |

---

## 5. Tool trust profile (Phase 2 — schema only here)

Per `(tool_name, expected_keys)`, extending the existing matrix entries:

| Key | Meaning |
|---|---|
| `impact_tier`, `impact_tier_source` | as today |
| `args` | `{name: {role, type}}` |
| `result_format` | `json` \| `text` |
| `result_fields` | `{json_path_pattern: SYSTEM \| EXTERNAL}`, `[*]` for list items |
| `result_default` | normally `EXTERNAL` |
| `review_status` | `draft` \| `approved` |
| `reviewed_by` | reviewer name |

`schema_version` is bumped; existing entries stay valid. The profile file references no framework.

**Phase 1:** a plain profile-entry data class lives in the tagging package (no file loading). The loader,
validation and drafting tools arrive in Phase 2 (blocked until explicitly approved).

---

## 6. Code layout (decided)

| Path | Contents |
|---|---|
| `src/trust_graph/tagging.py` | **updated**: `Provenance`, `Role`, `LineageStatus`, `Evidence`, `FieldTag`, profile-entry data class, new `tag_fields(direction, tool_name, fields, profile_entry, run_state)` |
| `src/provenance/run_state.py` | `RunState` (the package was scaffolded for provenance and is otherwise empty) |
| `src/provenance/lineage.py` | matching (Section 4), from step 1.3. `normalise()` lives in `tagging.py` during step 1.2 (needed for `FieldTag.length`) and moves here in step 1.3. |
| `tests/unit/test_tagging.py` | step 1.2 fixtures |
| `tests/unit/test_provenance.py` | step 1.3 fixtures (file exists, currently empty) |

**Compatibility:** `src/pipeline/risk_detector.py` and a pipeline test call the old
`tag_fields(parse_result, field_trust_classes)` and use `TaggedField.trust`, and `graph.py` consumes
`TaggedField`. Those files are outside this work's edit scope. Until the wiring step, `tagging.py` keeps the
old two-argument call working unchanged (recognised by its `ParseResult` first argument) and marks it
deprecated. The parser's `TaggedField` stub is not modified.

---

## 7. Limits of v1 (documented, not handled)

- Transformed copies are not traced: base64/hex/URL-shortened forms, paraphrases, translations, partial pieces.
- External text pasted *into* a longer argument (reverse containment) is not matched.
- Values shorter than `min_length` cannot be traced.
- Percent-decoding is one pass only, so double-encoded values are not traced.
- Lineage is per run only; nothing carries across runs or sessions.
- **RunState cap:** after `max_values` / `max_chars` new external values are not stored, so later arguments
  can be `UNLINKED` falsely; an attacker could try to flood a run past the cap. Visible via `overflowed`.
- `interception_id` and the user prompt are supplied by the caller until the clone's `DetectorContext` carries them.
- Plain-text and YAML results are a single field `$`, so lineage sources from them are whole-result strings.

---

## 8. Open questions (resolved 2026-11-08)

| # | Question | Decision |
|---|---|---|
| 1 | New module or update `tagging.py`? | Update `tagging.py`; keep the old call working until wiring (Section 6). |
| 2 | Direction values | `"pre"` / `"post"`, matching `DetectorContext`. |
| 3 | Where RunState/lineage live | `src/provenance/` (Section 6). |
| 4 | Phase-1 profile type | Plain data class in the tagging package. |
| 5 | Containment direction | Argument inside earlier external value only (4.3 b). |
| 6 | USER minimum length | Same `min_length`; below-minimum values never `USER` (4.3). |

## 9. Still open (to settle in the stated step)

| Item | Step | Proposal |
|---|---|---|
| Flanking character sets for **URLs** and **paths** | 1.3 | to be defined and recorded here |
| What counts as "identifier-like" | 1.3 | role `IDENTIFIER` / `AUTHORITY_ARG`, or the value looks like an email address, URL, path or id |
| Evidence for list-valued arguments (`recipients: [...]`) | 1.3 | per element |
| AgentDojo result format and the three development decisions (D1–D3) | before Phase 2 | see Section 11 |

---

## 10. Test fixtures

**Step 1.2 — tagging without lineage** (`tests/unit/test_tagging.py`)

- an email result (body/subject EXTERNAL, id/timestamp SYSTEM)
- a calendar result (description EXTERNAL)
- a GitHub-comment result
- a text-format result (one field `$`, `result_default`)
- a tool with no profile (all `UNKNOWN`)
- a draft entry (all `UNKNOWN`)
- containment: nested fields inside an EXTERNAL field are EXTERNAL
- result-field roles per the table in 3.1

**Step 1.3 — RunState and lineage** (`tests/unit/test_provenance.py`)

- poisoned email body whose address becomes a `send_email` recipient → `DERIVED`, `EXTERNAL_LINK`, evidence
- the same address typed in the user prompt → `USER`, `USER_MATCH`, no link
- a value present in **both** the prompt and an external field → `USER`
- a short value → `DERIVED`, `BELOW_MIN`, no link
- percent-encoded and Unicode look-alike copies (one decoding pass only)
- duplicate values in several external fields
- nested JSON inside an EXTERNAL string
- list-valued arguments report evidence **per element**
- boundary: `bob@x.com` inside `evil.bob@x.com` → **no match**
- boundary: `bob@x.com` inside `bob@x.com.evil.com` → **no match**
- injectable clock for `created_at`

**Step 1.4 — edge cases**

- empty strings, very long fields, very large lists, deeply nested objects
- RunState at the cap: `overflowed`, dropped counts, nothing stored past the cap

---

## 11. AgentDojo result format (Step B findings, 2026-11-09)

Read-only investigation of how AgentDojo turns a tool result into the string the clone passes to detectors.
It decides whether `result_fields` paths (e.g. `$[*].body`) can match AgentDojo results.

### 11.1 The formatter

`tool_result_to_str` in `agent_pipeline/tool_execution.py` is the default `tool_output_formatter` of
`ToolsExecutor`:

```python
def __init__(self, tool_output_formatter: Callable[[FunctionReturnType], str] = tool_result_to_str) -> None:
    self.output_formatter = tool_output_formatter
```

The two AgentDojo copies in this project **disagree on its default**:

| Copy | File | Default `dump_fn` |
|---|---|---|
| Vendored | `agentdojo/src/agentdojo/agent_pipeline/tool_execution.py` (line 23) | `json.dumps` → **JSON** |
| pip, agentdojo 0.1.35 | `.venv/Lib/site-packages/agentdojo/agent_pipeline/tool_execution.py` (line 23) | `yaml.safe_dump` → **YAML** |

The vendored file has a single commit (`1a3ddf8`, the upstream ADI benchmark release); the JSON default was
not introduced by this team. Two vendored docstrings still say YAML (`tool_execution.py` line 57,
`agent_pipeline.py` line 148), and in the vendored copy `tool_output_format="yaml"` still produces JSON
(`agent_pipeline.py` lines 197–200).

### 11.2 Which copy runs (verified)

| How the code is run | Copy imported | Output |
|---|---|---|
| `pytest` (`pytest.ini`: `pythonpath = src agentdojo/src`) | vendored | JSON |
| plain `.venv` Python | pip | YAML |
| clone README setup (`llm-benchmark/.venv` + editable `./agentdojo`) | vendored | JSON — but that environment does not exist on the reviewer's machine |

### 11.3 What the clone adapter does with no formatter

`src/clone/adapters/agentdojo.py` calls `super().__init__()` when `tool_output_formatter is None`, so it
inherits the default of **whichever AgentDojo copy was imported**.

### 11.4 Consequences for tagging

| Tool returns | JSON default | YAML default |
|---|---|---|
| Pydantic model or list of models (emails, events, files) | per-field paths work | parser gives `not_json`/`invalid_json` → one field `$` → per-field tagging lost |
| dict | paths work | one field `$` |
| list of str/int | JSON list of strings (ints become strings) | YAML |
| `str`, `None`, int (web pages, Slack actions) | `str(...)` → plain text → one field `$` | same |

### 11.5 Decisions needed for development

| # | Decision | Recommendation | Who | Blocks |
|---|---|---|---|---|
| **D1** | How the executor formats results | Always build `TrustVerificationToolsExecutor` with an explicit JSON formatter, `tool_output_formatter=partial(tool_result_to_str, dump_fn=json.dumps)`, so the format never depends on which AgentDojo copy is imported | Tasbiha (clone adapter); team agreement | Phase 2 profile entries, any end-to-end tagging run |
| **D2** | Which AgentDojo copy everyone uses | Pick one (vendored fork or pip 0.1.35), pin it in `requirements.txt` and `.vscode/settings.json`, and use one virtual environment | Team | Reproducible results |
| **D3** | Profiles for tools that return `str` / `None` / numbers | Give them `result_format: "text"` so the whole result is one field `$` tagged by `result_default` (Section 3.1, rule 3) | Zain (Phase 2.4 review) | Phase 2 profile entries |

Step 1.2 does not depend on D1–D3: its fixtures are hand-made JSON results.
