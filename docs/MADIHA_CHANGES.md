# Changes Needed in the WL-SVM / Classifier Work

For: Madiha (and any agent working on `src/classifier`, `src/pipeline/classifier_gate.py`, `src/pipeline/risk_gate.py`).
Base: `zain/experimental` at `4547109` or later.

## Read first: timing

- **Do now:** the code fixes in section A and the dataset fixes in section B. They don't depend on the final tags.
- **Wait before the final rebuild and retrain:** an anomaly check is being added to the parser and tagging stages (`anomaly` flag on tags, a new graph label). Tags will also be finalised after the Groq API test. Rebuild the dataset and retrain **once**, after that lands. Until then, numbers are provisional.
- **Don't edit without checking with Tasbiha:** `src/trust_graph/tagging.py`, `src/provenance/lineage.py`, `src/provenance/run_state.py`, `src/trust_graph/graph.py`, `src/parser/*`. They carry the provenance contract. New features belong in `src/classifier/wl_svm.py`; new graph labels go through an agreed list.

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

Every graph file, model and figure built before this is stale.

## A. Code-level bugs

| # | Where | Problem | Fix |
|---|---|---|---|
| 1 | `graph_dataset._benchmark_events` | Attack traces have no real result object: `raw_result` is rebuilt by re-parsing the formatted text, while benign traces carry the real object. The two classes get differently built graphs, so the model can learn the format instead of the attack. | Record attack runs through the clone executor (`scripts/record_traces.py` style) so they carry `raw_result`. Until then, mark text-derived traces and never mix them with real ones in one training set. |
| 2 | `_recorded_events` vs `_benchmark_events` | Batch numbers differ: recorded traces give every call its own batch; benchmark traces one batch per assistant message. The "same batch never links" rule behaves differently per class. | One rule: one batch per assistant message. |
| 3 | `wl_svm.wl_features` | `summary:forgery_true` ignores `forgery=leaf`; no counts for mimicry, mentions, mimics (and later anomaly). | Add `forgery_leaf`, `mimicry_true`, `rel_mimics`, `rel_mentions` (and `anomaly_true` when it lands). |
| 4 | `wl_svm.wl_features` | Summary counts are raw (`node_count` in the hundreds) with a linear SVM: graph size dominates, and scripted benign runs differ in size from LLM attack runs. | `log1p`, per-node ratios, or a scaler. |
| 5 | `wl_svm.fit` | Calibration uses `StratifiedKFold`, not task groups: one task can be in a training and a calibration fold, so probabilities are over-confident. | `StratifiedGroupKFold` / `GroupKFold` with the group ids it already receives. |
| 6 | `ablation._transform` | Only removes `:forgery=true/false`; `forgery=leaf` and `mimicry=` leak into the "without forgery labels" run. | Remove every flag part, or build labels from an explicit list of kept fields. |
| 7 | `graph_dataset._matrix_entry` | Its fallback (argument keys ⊆ expected keys) duplicates TVM v2's name lookup and can pick a different same-name entry. | Use `matrix.lookup(tool, keys)` only; keep `keys_match` for reporting. |
| 8 | Evaluation graphs | Must use the same builder as live: `build_trace_graph(groups, findings, mentions=...)`. `graph_dataset` already passes mentions; keep it that way. | Rebuild with current code (after the anomaly check lands). |
| 9 | `out/fyp1_all_available_attacks/wl_svm.joblib` (committed) | Loading a joblib file can execute code; committed models go stale when tags change. | Don't commit model files. Rebuild locally, store the SHA-256 in the report, load only your own files. |
| 10 | `risk_gate.assess_risk` | Any structural hit forces review. With located, mimicry and (soon) anomaly findings, review volume grows. | Use `hit_count` (already excludes located findings); an anomaly signal must never force review alone. |

## B. Dataset and method

1. **Benign and attack come from different sources.** Benign = ground-truth replays with a scripted model; attack = real LLM runs (gpt-oss, llama). The model can separate "scripted vs LLM". Fix: benign runs from the same models, through the same executor, as the attacks.
2. **The model mostly re-reads the parser's flags.** Your ablation: without finding nodes and forgery labels, attack recall is 9.5%. Report this honestly. The graph's own value must come from lineage and authority features (EXTERNAL_LINK on authority arguments, `untrusted_also`, `rel:mimics`); test with parser flags removed.
3. **Attack labels ignore success.** Every trace from an attack run is "attack", even when the model ignored the injection. Decide the label: "injected data present" (data-level, matches a detector) or "attack succeeded". Report both, or train on the first and break results down by `attack_success`.
4. **Small test set:** 21 attacks. Add confidence intervals (bootstrap by task group). Leave-one-suite-out already shows Slack at 74%.
5. **Not reproducible:** `runs/` is not tracked. Record traces into `tests/fixtures/traces/attack/` (or store run metadata and hashes).
6. **Default suites** are `travel`, `workspace` only, while the docs report all four. Make defaults match the reported runs.
7. **Rebuild once** after the anomaly check and Groq finalisation; re-run every figure in `docs/wl-svm-teammate-report.md` and `docs/fyp1-offline-evaluation.md`.

## C. Suggestions

- Graph features to add: authority argument from an EXTERNAL source with no user match; `untrusted_also`; `match_strength`; `leaf_forged`; `has_mimicry`; later `anomaly`.
- Evaluate per decision point (each pre-hop call), not only per run: blocking happens at calls.
- Report baselines next to WL-SVM: parser flags only (a rule), and logistic regression on summary features. This shows whether the graph adds value.
- Keep one graph contract: any new node label or relation node is agreed and listed in `src/trust_graph/graph.py`'s docstring.
