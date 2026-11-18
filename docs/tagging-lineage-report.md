# Tagging and lineage: implementation report

## Scope

This report describes the implementation on `zain/experimental`. It follows data from the AgentDojo clone adapter through parsing, tagging, the per-run value store, and argument lineage on a later tool call.

The current default tagging rule is:

- Object and array nodes describe structure and are tagged `SYSTEM`.
- Scalar leaves, including strings, numbers, booleans, and nulls, are tagged `EXTERNAL` unless an approved profile overrides them.
- A string argument is linked to the user prompt, an exact whole SYSTEM string leaf, or an earlier EXTERNAL string leaf. EXTERNAL matches may be exact or bounded substrings. The link is evidence about the value's source; it does not, by itself, authorize the tool action.
- Each tag has a `has_forgery` flag when a counted parser finding maps to that true field (the nearest owning field in the skeleton for post-hop results).

## What each part does

| Stage | Code | Data it receives | Result |
|---|---|---|---|
| Clone adapter | `src/clone/adapters/agentdojo.py` | User prompt, assistant tool call, runtime result object | Assigns a `run_id` and a batch number; sends pre-call args and post-call formatted text plus the original result object to the core. |
| Interception core | `src/clone/core.py` | Tool name, args/result, trusted schema, IDs | Creates ledger records and a `DetectorContext` with `run_id`, `interception_id`, `user_prompt`, `batch_id`, and, after a tool runs, `raw_result` and `result_format`. The post record points back to the corresponding pre record. |
| Parser analysis | `src/pipeline/parser_analysis.py` | Pre-call args, or post-call formatted text and raw result | Parses and checks the visible payload. For structured post results it also builds a skeleton from `raw_result`, preserving the actual field boundaries. |
| Tagging stage | `src/pipeline/tagging_stage.py`, `src/trust_graph/tagging.py` | Parsed arguments or true result fields, plus the detector context | Creates side-record `FieldTag`s. Tags do not contain raw values. For text results, even JSON-looking text is represented as one opaque external leaf for lineage. |
| Per-run state | `src/provenance/run_state.py` | Prompt, tags, normalized SYSTEM/EXTERNAL string leaves | Keeps values and tags in bounded memory for the current run, indexed by interception ID. Overflow or missing parse visibility is recorded as incomplete state. |
| Lineage | `src/provenance/lineage.py` | Current string arguments, prompt, earlier SYSTEM/EXTERNAL leaves | Marks an argument `USER_MATCH`, `SYSTEM_LINK`, `EXTERNAL_LINK`, `UNLINKED`, or `BELOW_MIN`. Links carry the source leaf's `tag_id` as evidence. Results from the same tool-call batch cannot be used as earlier sources. |
| Consumer | `src/pipeline/clone_parser_detector.py` or `src/pipeline/risk_detector.py` | Parser analysis and tags | The default parser detector records tags/lineage but still decides from parser policy. The opt-in risk detector includes tags in its trust graph and risk assessment. |

## Example: a result value reaches a later tool argument

This example follows the adapter-level test in `tests/pipeline/test_tagging_stage.py`. The test uses a small local tool matrix; it is not a claim that the production matrix has already classified these example tools.

The user's prompt is:

```text
Continue with the latest record.
```

### 1. First assistant tool call

The model asks to read a record:

```json
{
  "tool": "read_record",
  "args": {}
}
```

The adapter creates a run ID and batch ID. The core captures the call and sends the detector a pre-hop context, abbreviated here:

```json
{
  "direction": "pre",
  "tool_name": "read_record",
  "tool_call_id": "read-1",
  "run_id": "run-abc",
  "interception_id": "pre-101",
  "user_prompt": "Continue with the latest record.",
  "batch_id": 1,
  "payload": {"tool": "read_record", "args": {}}
}
```

The parser bridge unwraps `args` for pre-hop analysis. In this case it sees an empty argument object. It tags the parsed fields, but there is no string argument value to link.

### 2. Tool result and post-hop tagging

The tool returns the real Python string `Use account acct-12345`. The formatter produces the same visible text. The adapter sends both representations:

```json
{
  "direction": "post",
  "tool_name": "read_record",
  "tool_call_id": "read-1",
  "run_id": "run-abc",
  "interception_id": "post-102",
  "user_prompt": "Continue with the latest record.",
  "batch_id": 1,
  "result_format": "text",
  "payload": "Use account acct-12345",
  "raw_result": "Use account acct-12345"
}
```

The parser still analyzes the visible text. Since the raw result is a string, it has no trustworthy inner object boundaries. Tagging therefore stores one leaf rather than treating any JSON-like or delimiter-like text as real structure:

```json
{
  "path": "$",
  "direction": "post",
  "provenance": "EXTERNAL",
  "trust": "UT",
  "role": "CONTENT",
  "interception_id": "post-102"
}
```

The tag itself has no value text. The run state stores a normalized string value and its join information:

```json
{
  "normalized_value": "use account acct-12345",
  "source_tag_id": "tag-source-1",
  "source_interception_id": "post-102",
  "source_path": "$",
  "batch_id": 1
}
```

### 3. A later assistant tool call

On the next model turn, the assistant proposes:

```json
{
  "tool": "use_account",
  "args": {"value": "acct-12345"}
}
```

The adapter keeps the same `run_id` and increments the batch ID:

```json
{
  "direction": "pre",
  "tool_name": "use_account",
  "tool_call_id": "use-1",
  "run_id": "run-abc",
  "interception_id": "pre-103",
  "user_prompt": "Continue with the latest record.",
  "batch_id": 2,
  "payload": {"tool": "use_account", "args": {"value": "acct-12345"}}
}
```

The parser bridge extracts the argument object. The lineage stage normalizes `acct-12345`, does not find it in the prompt, then finds it inside the earlier external result string. The argument tag carries this evidence:

```json
{
  "path": "$.value",
  "direction": "pre",
  "provenance": "DERIVED",
  "trust": "UT",
  "lineage_status": "EXTERNAL_LINK",
  "derived_from": [
    {
      "source_tag_id": "tag-source-1",
      "match_type": "substring",
      "matched_length": 10
    }
  ],
  "interception_id": "pre-103"
}
```

The source tag ID resolves to the post-hop field tag stored under `post-102`. The run ID keeps both calls in the same state, and `batch_id: 1 < 2` confirms the source result came from an earlier assistant turn. If both calls were in batch 1, this result would not be eligible as a source. If an approved profile tags a whole string field as SYSTEM and the argument exactly equals it, lineage returns `SYSTEM_LINK` with trust `T`; the selected default has no SYSTEM scalar leaves, so this case requires a profile override.

### 4. Decision and cleanup

With `parser_detector`, the parser decision is returned as before; lineage is recorded for inspection but does not change that detector's allow/block rule. With `make_risk_detector`, tags and lineage are features in the trust graph and risk assessment. The checked-in matrix now marks selected resource selectors and side-effect controls as `AUTHORITY_ARG` for 58 of its 70 entries; the 12 entries without arguments have empty lists. These assignments are an initial policy mapping and should be reviewed against the intended risk policy.

At the end of a normal AgentDojo turn sequence, the adapter calls the detector's `end_run` hook when available. This clears the run's prompt, external strings, and tags. Wrapping detectors should expose/forward that hook or explicitly end the run; the trace recorder does so explicitly.

## What is implemented and what remains limited

- Structured results use their raw-object skeleton for true field paths; strings and scalar results are opaque leaves.
- Counted parser findings are mapped back onto the closest owning true field through `FieldTag.has_forgery`.
- The `index_values` API keeps normalized SYSTEM and EXTERNAL string leaves in bounded per-run state. An incomplete parse, an oversized skeleton, or storage overflow is reflected in run state; the risk detector review-routes high-impact cases when lineage state is incomplete.
- Lineage checks in order: short-value guard, bounded prompt match, exact SYSTEM-field match, then exact or bounded-substring EXTERNAL match. All matching applies the identifier boundary rule from the design.
- Lineage uses normalized text matching, not model-internal provenance. It can miss paraphrased, encoded, split, or value-free attacks, and substring matching can produce imperfect attribution.
- `ProfileEntry` supports approved path overrides in the tagger API, but profile loading and profile selection are not yet wired into `analyze_and_tag`. The current default SYSTEM-structure/EXTERNAL-leaf rule is active.
- The checked-in TVM's `field_trust_classes` are `unclassified`; they do not assign trusted result fields or SYSTEM scalar leaves. `authority_arguments` are now populated for entries with relevant parameters.
- Local adapter and stage tests verify the handoff and a cross-turn value link. They do not prove behavior with every live provider, tool formatter, or adversarial encoding.

## Verification

The focused clone-to-lineage suite passed **623 tests, with 6 expected failures**, across clone interception, parser skeletons, tagging, lineage, the parser bridge, trace recording, and risk evaluation. The adapter integration test exercises a tool result flowing to a later tool argument, and the tests cover batch isolation and cleanup. `compileall` and `git diff --check` also completed. The tool matrix loads with 70 entries; 58 entries have non-empty authority-argument lists. Pytest emitted a cache warning because this environment denied writes to `.pytest_cache`; it did not affect the test result.

This review also fixed a graph-labeling error: lineage source nodes were always labeled `EXTERNAL`, even when an approved profile had produced a `SYSTEM_LINK`. Evidence now carries source provenance, and a regression test checks that the graph labels the source `SYSTEM`.

Passing local tests does not establish correctness for every live provider or tool formatter. In particular, profile loading is not wired automatically, and the default `parser_detector` records lineage but does not use it to alter its decision. Use `make_risk_detector` if lineage is meant to feed the risk graph. Matrix authority-argument assignments are initial policy choices and need domain review. Text matching can still miss transformed or paraphrased values.
