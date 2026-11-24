# Changes Needed in the WL-SVM / Classifier Work

For: Madiha (and any agent working on `src/classifier`, `src/pipeline/classifier_gate.py`, `src/pipeline/risk_gate.py`).
Base: `zain/experimental` with the anomaly check (commit "Parser: anomaly check for unknown-format structure") or later.

## Read first: what is yours, what is done

| Area | Owner | State |
|---|---|---|
| Parser, skeleton, inner nodes, mimicry, anomaly (`src/parser/*`) | Tasbiha | done, final |
| Tagging, lineage, run state (`src/trust_graph/tagging.py`, `src/provenance/*`) | Tasbiha | done, final |
| **Graph builder** (`src/trust_graph/graph.py`): nodes, labels, edges, relation nodes | Tasbiha | **done, final** (contract below) |
| **Dataset builder** `src/classifier/graph_dataset.py` | **Madiha** | needs fixes A1, A2, A7 and section B |
| **WL-SVM** `src/classifier/wl_svm.py` (features, calibration) | **Madiha** | needs fixes A3, A4, A5 |
| **Evaluation** `train.py`, `evaluate.py`, `ablation.py`, `robustness.py` | **Madiha** | needs fix A6, baselines, intervals |
| **Risk gate** `src/pipeline/risk_gate.py`, `classifier_gate.py` | **Madiha** | needs fix A10 |
| Data and reports (`out/`, `docs/wl-svm-teammate-report.md`, `docs/fyp1-offline-evaluation.md`) | **Madiha** | rebuild and re-run all figures |

So the graph is already built: the work left is the dataset builder, the WL-SVM, evaluation, the risk gate, and the data. **Do not change** `graph.py`, `tagging.py`, `lineage.py`, `run_state.py` or `src/parser/*` without agreeing it with Tasbiha; add features in `wl_svm.py`.

## Timing

- **Tags are now final** (the anomaly check has landed). Fix sections A and B, then **rebuild the dataset and retrain once** with the current code. Every graph, model and figure made before this is stale.
- Rebuild the shape baseline only through `scripts/build_shape_baseline.py`, and only from benign traces.

## Final graph contract (what `graph.py` produces)

Field node label, parts joined by `:` in this order:

```
<trust>:<provenance>:<role>:<lineage_status>:<value_type>:depth=<n>:direction=<pre|post>:forgery=<true|leaf|false>:mimicry=<true|false>:anomaly=<true|false>
```

- `trust`: `T` / `UT`. `provenance`: `USER`, `SYSTEM`, `EXTERNAL`, `DERIVED`. `role`: `AUTHORITY_ARG`, `CONTENT`, `IDENTIFIER`, `OTHER`.
- `lineage_status`: `USER_MATCH`, `SYSTEM_LINK`, `EXTERNAL_LINK`, `UNLINKED`, `NOT_APPLICABLE` (`BELOW_MIN` no longer produced).
- `forgery=true`: forgery on this node; `leaf`: inside a forged field but not on this node's line; `false`.
- `mimicry=true`: the node copies a real field of the same result (separate from forgery).
- `anomaly=true`: the field (or its leaf) has structure outside its benign shape; weak, never counted.

Other nodes:

- Source node (a lineage source outside this graph): `source:<provenance>:string:forgery=<true|leaf|false>`.
- Finding node: `finding:<kind>`, kinds include `illegal_delimiter`, `record_conflict`, `mimicry`, `duplicate_key`, `embedded_json`, `unexpected_key`. Located findings (detail starts `located:`) pin a hit to its line; they are not extra hits.
- Relation nodes: `rel:mimics` (claim → real field it copies), `rel:mentions` (field → field it mentions).
- Node ids: `event:<n>:<path>` in run graphs; inner paths use `.@row[i]`, `.@col[j]`, `.@tok[k]`.

Edges: parent → child, lineage source → argument, field → finding, and through relation nodes. Built by `build_trace_graph(groups, findings, mentions=...)` for both training and live.

## What changed upstream (why the old graphs are stale)

Since `6b1f578` the tags and graphs changed:

- Result fields and argument containers: `lineage_status = NOT_APPLICABLE`.
- Numbers, booleans and nulls: `SYSTEM`; strings `EXTERNAL`.
- Inner nodes inside string fields: rows, cells, tokens (`.@row[i]`, `.@col[j]`, `.@tok[k]`), including text results.
- Flags: `has_forgery` (pinned to the line), `leaf_forged` (weaker, rest of a forged field), `has_mimicry` (separate from forgery).
- Graph labels: `forgery=true|leaf|false`, `mimicry=true|false`; relation nodes `rel:mimics`, `rel:mentions`.
- Lineage evidence: every source, with `match_strength`, `match_form`, `untrusted_also`.
- The live risk detector now builds the **run graph** (`build_trace_graph` over all interceptions, with findings and mentions), the same builder as `graph_dataset`.
- The parser never blocks; it marks payloads `suspicious`.
- Anomaly check: string fields with structure outside their benign shape get `has_anomaly` and the `anomaly=true` label; lineage evidence carries `source_has_anomaly`. Payload label `suspicious:anomaly`; not a counted hit.
- Broken-JSON forgeries (an open string left to be closed by the real quote) now give keyed cells, so forged author or role claims are compared (mimicry).

Every graph file, model and figure built before this is stale.

## A. Code-level bugs

| # | Where | Problem | Fix |
|---|---|---|---|
| 1 | `graph_dataset._benchmark_events` | Attack traces have no real result object: `raw_result` is rebuilt by re-parsing the formatted text, while benign traces carry the real object. The two classes get differently built graphs, so the model can learn the format instead of the attack. | Record attack runs through the clone executor (`scripts/record_traces.py` style) so they carry `raw_result`. Until then, mark text-derived traces and never mix them with real ones in one training set. |
| 2 | `_recorded_events` vs `_benchmark_events` | Batch numbers differ: recorded traces give every call its own batch; benchmark traces one batch per assistant message. The "same batch never links" rule behaves differently per class. | One rule: one batch per assistant message. |
| 3 | `wl_svm.wl_features` | `summary:forgery_true` ignores `forgery=leaf`; no counts for mimicry, mentions, mimics or anomaly. | Add `forgery_leaf`, `mimicry_true`, `anomaly_true`, `rel_mimics`, `rel_mentions`. |
| 4 | `wl_svm.wl_features` | Summary counts are raw (`node_count` in the hundreds) with a linear SVM: graph size dominates, and scripted benign runs differ in size from LLM attack runs. | `log1p`, per-node ratios, or a scaler. |
| 5 | `wl_svm.fit` | Calibration uses `StratifiedKFold`, not task groups: one task can be in a training and a calibration fold, so probabilities are over-confident. | `StratifiedGroupKFold` / `GroupKFold` with the group ids it already receives. |
| 6 | `ablation._transform` | Only removes `:forgery=true/false`; `forgery=leaf` and `mimicry=` leak into the "without forgery labels" run. | Remove every flag part, or build labels from an explicit list of kept fields. |
| 7 | `graph_dataset._matrix_entry` | Its fallback (argument keys ⊆ expected keys) duplicates TVM v2's name lookup and can pick a different same-name entry. | Use `matrix.lookup(tool, keys)` only; keep `keys_match` for reporting. |
| 8 | Evaluation graphs | Must use the same builder as live: `build_trace_graph(groups, findings, mentions=...)`. `graph_dataset` already passes mentions; keep it that way. | Rebuild with the current code. |
| 9 | `out/fyp1_all_available_attacks/wl_svm.joblib` (committed) | Loading a joblib file can execute code; committed models go stale when tags change. | Don't commit model files. Rebuild locally, store the SHA-256 in the report, load only your own files. |
| 10 | `risk_gate.assess_risk` | Any structural hit forces review. With located, mimicry and anomaly findings, review volume grows. | Use `hit_count` (already excludes located findings; anomaly findings are uncounted). An anomaly must never force review on its own. |

## B. Dataset and method

1. **Benign and attack come from different sources.** Benign = ground-truth replays with a scripted model; attack = real LLM runs (gpt-oss, llama). The model can separate "scripted vs LLM". Fix: benign runs from the same models, through the same executor, as the attacks.
2. **The model mostly re-reads the parser's flags.** Your ablation: without finding nodes and forgery labels, attack recall is 9.5%. Report this honestly. The graph's own value must come from lineage and authority features (EXTERNAL_LINK on authority arguments, `untrusted_also`, `rel:mimics`); test with parser flags removed.
3. **Attack labels ignore success.** Every trace from an attack run is "attack", even when the model ignored the injection. Decide the label: "injected data present" (data-level, matches a detector) or "attack succeeded". Report both, or train on the first and break results down by `attack_success`.
4. **Small test set:** 21 attacks. Add confidence intervals (bootstrap by task group). Leave-one-suite-out already shows Slack at 74%.
5. **Not reproducible:** `runs/` is not tracked. Record traces into `tests/fixtures/traces/attack/` (or store run metadata and hashes).
6. **Default suites** are `travel`, `workspace` only, while the docs report all four. Make defaults match the reported runs.
7. **Rebuild once** with the current code (tags are final); re-run every figure in `docs/wl-svm-teammate-report.md` and `docs/fyp1-offline-evaluation.md`.

## C. Suggestions

- Graph features to add in `wl_svm.py`: authority argument from an EXTERNAL source with no user match; `untrusted_also`; `match_strength`; `leaf_forged`; `has_mimicry`; `has_anomaly`.
- Evaluate per decision point (each pre-hop call), not only per run: blocking happens at calls.
- Report baselines next to WL-SVM: parser flags only (a rule), and logistic regression on summary features. This shows whether the graph adds value.
- Keep one graph contract: any new node label or relation node is agreed and listed in `src/trust_graph/graph.py`'s docstring.

## Implementation status (24 November 2026)

The classifier-side fixes in this note are implemented without changing the parser,
tagging, lineage, run-state, graph builder, or benchmark source files:

- `graph_dataset.py` now records text-derived traces and trace hashes, uses exact TVM
  lookup, supports all four default suites, and rejects mixed raw-object/text-derived
  datasets unless `--allow-text-derived-mix` is explicit.
- `wl_svm.py` now includes leaf-forgery, mimicry, anomaly, relation, and normalized
  provenance features and calibrates with grouped folds when group IDs are present.
- `ablation.py` removes all structural flag fields, including leaf, mimicry, and
  anomaly markers.
- `risk_gate.py` uses counted structural hits for review; structural density by
  itself cannot force review.
- `evaluate.py` reports attack-success metadata and task-group bootstrap intervals.

The current mixed dataset was rebuilt only with the explicit exploratory override;
the default builder will stop if real-object and text-derived traces are mixed.
