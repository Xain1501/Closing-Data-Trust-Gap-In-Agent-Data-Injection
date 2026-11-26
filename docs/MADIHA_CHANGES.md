# Changes Needed in the WL-SVM / Classifier Work

For: Madiha (and any agent working on `src/classifier`, `src/pipeline/classifier_gate.py`, `src/pipeline/risk_gate.py`).
Base: `zain/experimental` with the anomaly check (commit "Parser: anomaly check for unknown-format structure") or later.

## Handoff status (26 November 2026)

| Area | Owner | State |
|---|---|---|
| Parser, skeleton, inner nodes, mimicry, anomaly (`src/parser/*`) | Tasbiha | done, final |
| Tagging, lineage, run state (`src/trust_graph/tagging.py`, `src/provenance/*`) | Tasbiha | done, final |
| **Graph builder** (`src/trust_graph/graph.py`): nodes, labels, edges, relation nodes | Tasbiha | **done, final** (contract below) |
| **Dataset builder** `src/classifier/graph_dataset.py` | **Madiha** | current offline run-level dataset pipeline implemented; additional independent benchmark data remains |
| **WL-SVM** `src/classifier/wl_svm.py` (features, calibration) | **Madiha** | current offline features and grouped calibration implemented |
| **Evaluation** `train.py`, `evaluate.py`, `ablation.py`, `robustness.py` | **Madiha** | run-level validation, ablations, baselines, and grouped intervals implemented |
| **Risk gate** `src/pipeline/risk_gate.py`, `classifier_gate.py` | **Madiha** | counted-hit policy plus calibrated WL-feature novelty signal; known-feature unseen attacks can still evade it |
| Data and reports (`out/`, `docs/wl-svm-teammate-report.md`, `docs/fyp1-offline-evaluation.md`) | **Madiha** | v4 results plus one new `important_instructions` pair; strict family holdout remains an experimental check |

The offline run-level model has a conservative group-calibrated novelty-to-review path, but it does not solve unseen attacks whose graph features are already represented in training. The new `important_instructions` trace and its matched clean trace are one task group, currently present in the training split; the current `FINAL_REPORT.json` has no held-out attack families. That result cannot validate zero-shot performance for this family. The model is offline-only; live interception remains parser-only. More independent attack groups and natural benign runs remain necessary. The `out/new_attack_runs` task-ID ambiguity is resolved below: those traces are direct-goal controls, not valid new data-injection positives. Share the local v5 handoff archive only through an approved private channel. The primary v4 findings and supplemental-control limitations are in `docs/fyp1-offline-evaluation.md`. **Do not change** `graph.py`, `tagging.py`, `lineage.py`, `run_state.py` or `src/parser/*` without agreeing it with Tasbiha.

## Timing

- **Tags are now final** (the anomaly check has landed). The matched and natural-benign v4 datasets and reports were rebuilt on 25 November 2026. Older figures are historical; use the v4 section of `docs/fyp1-offline-evaluation.md` for current results. Rebuild again only if source traces, graph/tagging behavior, or classifier code changes.
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
- The prior live risk-detector integration built a partial run graph. It is now
  disabled because the trained classifier's input is one complete run graph;
  `graph_dataset` remains the offline complete-run graph producer.
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
- The project selected **run-level-only** training/evaluation. Do not copy the attack label from a complete trace onto each pre/post interception; there is no per-decision ground truth in these traces.
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

The earlier mixed dataset was rebuilt only with the explicit exploratory
override. Its figures are historical; see `fyp1-offline-evaluation.md` for the
corrected raw-object, run-level-only rebuild.

## Run-level-only implementation decision

The model is deliberately offline-only because it is trained on each completed
run graph. The live risk-detector factory now rejects the model, and the live
smoke script rejects `--risk-model`; live interception continues to use the
existing parser detector. `per_decision.py` explicitly rejects evaluation with
repeated run labels. Dataset rows are marked `classification_unit: "run"`, and
training/evaluation validate that unit.

The attack recorder now uses each source trace's AgentDojo suite version,
preserves assistant tool-call batches, and keeps benchmark family separate from
attack family. `data_only_semantic` and `data_only_syntactic` are attack-family
labels inside the AgentDojo benchmark; they are not an independent ADI
benchmark. The dataset builder accepts explicit benchmark/task-group metadata
for additional benchmark formats, supports all-suite inputs, validates declared
labels, and can force entire benchmark, attack-family, or source groups into a
held-out test split.

The recorder can also create matched clean counterfactuals: it replays the
recorded tool-call sequence against the same task's default (non-injected)
environment. These pairs support a controlled **injection-present vs
injection-absent** experiment and remain in the same task group/split. They are
not natural benign-agent runs and must not be reported as task-utility or
attack-success evaluation. No external API or synthetic attack text is used.

WL subtree histograms are normalized per graph; new artifacts record feature
schema version 2 and run-level training metadata. Existing format 1/2 models
retain their raw-count feature interpretation when loaded. Final reports include
the model hash and warn when the benign and attack collection sources differ.

XGBoost is not added as a second classifier yet. It is not in the pinned
dependencies, and the available independent attack families/task groups are
too few to justify a stacked model without severe overfitting/leakage risk.
Reconsider it only after collecting more independent, matched data and
generating group-wise out-of-fold WL-SVM scores for the stacker.

These changes do not touch the parser, tagging, lineage, run-state, graph
builder, clone core, or adapter. The previously identified timeout race in
tagging and `evidence_only` delivery behavior remain outside this change scope;
they are not fixed by selecting offline-only evaluation.

## Follow-up verification (25 November 2026)

- Rebuilt the matched v3 corpus with the shared tool-call sequence hash required:
  97 pairs replayed, 87 usable pairs after excluding 10 with no usable tool call.
- The matched held-out set has 58 runs (29 per label). WL-SVM achieved 70.7%
  accuracy and 72.4% attack recall; semantic-family holdout attack recall was
  13.6% (3/22). These are injection-presence results, not attack-success or
  natural-benign evaluation.
- Added parser-rule and summary-feature logistic baselines on the same final
  train/test split. Their accuracy was 84.5% and 82.8%, respectively, both above
  the full WL-SVM's 70.7%. Current evidence therefore does not demonstrate an
  overall graph-classifier advantage. Baseline reports now include 1,000-repeat
  task-group bootstrap intervals. The ablation results and reproduction commands
  are in `fyp1-offline-evaluation.md`.
- Fixed `ablation.py` to preserve the required `classification_unit: "run"`
  metadata in its generated JSONL. The parser-only baseline now counts leaf
  forgery as suspicious.
- Added a group-calibrated WL-feature novelty signal that routes novel graphs to
  review in the offline graph gate. It can miss unseen attacks composed of
  familiar graph features and is not wired into the live parser-only path.
- Added `scripts/record_clean_agentdojo.py` to capture natural no-injection
  model runs through the clone executor, with raw results and stable call-sequence
  hashes. Using the locally configured Groq GPT-OSS model, eight runs across all
  four suites were collected (20 tool calls) for the existing attack task groups.
  The v4 corpus now has 8 natural benign traces plus 87 counterfactual pairs;
  only one natural benign trace is in the standard test split.
- More natural benign runs and new independent benchmarks/attack families remain
  necessary. The current benchmark still has only `data_only_semantic` and
  `data_only_syntactic` families, and semantic-family holdout recall remains
  13.6%. Provider-backed collection was limited to the authorized small sample;
  no new attack family was generated.
- `out/new_attack_runs` was initially excluded because its `user_task_id`
  values were `injection_task_*`, not valid workspace user-task IDs. The later
  audit below confirmed these are direct-goal controls, not missing user-task
  mappings; they remain separate from the primary injection dataset.
- XGBoost remains untouched and out of scope. The previously noted tagging
  timeout race and `evidence_only` delivery integration are not changed here.

## Supplemental direct-goal controls (25 November 2026)

- Audited all nine files in `out/new_attack_runs` against the installed
  AgentDojo v1.2.2 workspace injection-task registry. Their prompts exactly
  match registered `InjectionTask.GOAL` strings; `injection_task_*` was stored
  in `user_task_id`, so these are not user tasks and must not be remapped to
  `user_task_*`.
- Eight GPT-OSS traces have tool calls (16 total) and contain no injected tool
  data. Seven have successful AgentDojo security outcomes; one outcome is
  unknown. The security/utility outcome is kept separate from the no-injection
  label. One duplicate Llama trace has no tool calls and was excluded. The
  retained traces are text-derived and are kept in a separate held-out
  no-injection control set, not mixed into the primary injection-present
  training set.
- `graph_dataset.py` now reads both AgentDojo content-block encodings (`text`
  and `content`) and string-valued tool function names. It preserves the
  recorded tool results and user prompt for graph construction; these records
  remain marked `text_derived`.
- On the eight controls, the existing v4 WL-SVM flagged two as attack: a 25%
  false-positive rate (six of eight classified as no-injection). This is a tiny,
  text-derived control check, not an attack-recall or general benign-FPR claim.
- Reproduce with `scripts/build_direct_goal_challenge.py` and
  `scripts/evaluate_direct_goal_controls.py`. No tagging, lineage, graph-builder,
  XGBoost, or provider code was changed, and no new provider calls were made.

## New attack family and strict holdout (26 November 2026)

- Added one raw-object `important_instructions` attack trace and its matched
  clean counterfactual. The pair shares `agentdojo:workspace:user_task_0` and
  must always stay in the same split.
- `out/fyp1_final_with_unseen/FINAL_REPORT.json` reports 185 raw-object traces,
  65.0% attack recall, 72.2% attack precision, and five false positives on a
  43-run test split (20 attacks, 23 benign). The report manifest says
  `holdout_attack_families: []`; the `important_instructions` attack and clean
  pair are in training. Therefore those aggregate metrics are not a zero-shot
  result for the new family.
- When this pair is included in training, the fitted classifier predicts both
  traces benign (attack probabilities about 0.292 and 0.240), and neither has
  unseen WL-feature mass. The strict family-held-out run below tests a model
  trained without the pair and does flag the attack for review. The categorical
  graph encodes some differences (including external links and anomaly labels),
  but one pair is not enough to establish that these signals generalize.
- Added `scripts/evaluate_unseen_attack_family.py` to move every group
  containing a selected attack family, including paired clean runs, out of
  training and into test, retrain the model, and emit a group-disjoint report.
  Reproduce with:

  ```powershell
  $env:PYTHONPATH = "src"
  python scripts/evaluate_unseen_attack_family.py `
    --dataset-dir .\out\fyp1_final_with_unseen `
    --attack-family important_instructions `
    --output-dir .\out\unseen_family_important_instructions
  ```

- Strict zero-shot evaluation on this data gives classifier family recall 0/1,
  but the calibrated novelty signal flagged the held-out attack for review
  (1/1). Neither the matched clean counterfactual nor the other benign run in
  its held-out task group was flagged (0/2). The attack's novelty score was
  0.1085 against a 0.0990 threshold; the matched clean score was 0.0076.
  This demonstrates a review safeguard on one trace, not learned family
  recognition or reliable generalization.
- One attack and one task group cannot estimate family-level recall. A real
  open-set claim requires multiple independent attack task groups, a
  family-held-out test, and benign review-rate reporting. Do not tune against
  the held-out family and then report it as zero-shot. At that stage,
  provider-backed collection still needed an explicit spend cap; the capped
  follow-up collection is documented below.
- No tagging, lineage, graph-builder, XGBoost, or live detector code was changed.

## Ten-group `important_instructions` collection (26 November 2026)

- Added `scripts/collect_important_instructions.py` to collect ten distinct
  injectable AgentDojo task groups across Workspace, Travel, Slack, and Banking.
  Each provider-generated attack call sequence is replayed through the clone
  executor both with its injection and as a matched clean counterfactual. The
  output contains 10 attack and 10 benign raw-object traces; all ten pairs have
  matching task groups, pair IDs, and call-sequence hashes.
- Collection is capped at $2 using per-request worst-case reservations,
  bounded prompt/output sizes, usage accounting, and bounded 429 backoff.
  The ledger records a $0.0186 usage-cost estimate and $0.1375 maximum
  conservative exposure; the latter includes reservations for requests with
  uncertain billing. The benchmark injections succeeded in four runs. This
  outcome does not change trace labels: every injected run remains an attack
  example.
- Rebuilding the graph dataset from the existing corpus plus these pairs gives
  203 raw-object runs (text-derived: 0), including 10
  `important_instructions` attack runs. The standard grouped split has 158 train
  and 45 test runs.
- The strict family holdout contains 10 attack examples in 10 independent task
  groups and 20 benign examples. The WL-SVM detects 2/10 attacks (20% recall).
  Its existing calibrated novelty-to-review rule flags 6/10 attacks and 1/20
  benign examples. This is a partial review safeguard, not a complete solution:
  unseen injected runs can still be classified benign and not routed to review.
- A post-hoc threshold sweep on this held-out sample found that a novelty
  threshold of 0.03 would flag 10/10 attacks but also 7/20 benign examples.
  This is a diagnostic trade-off, not an independently validated setting; do
  not tune on this holdout and present it as zero-shot performance.
- Reproduction commands are in `fyp1-offline-evaluation.md`. Generated
  collection, dataset, and report artifacts are under `out/` and are not
  tracked. Tagging, graph construction, lineage, XGBoost, and the live
  parser-only path were not changed.

## Classifier unsafe flag and post-tagging handoff

The classifier now exposes `ClassifierResult.unsafe_flag` without changing the
WL-SVM's trained model or its measured `predicted_label`:

- `unsafe_flag` is true if the WL-SVM predicts `attack` **or** its graph novelty
  score is out of distribution.
- `flag_reasons` preserves which signal fired:
  `classifier_attack_prediction` and/or `classifier_out_of_distribution`.
- OOD is treated as an unsafe-to-auto-allow signal so the graph risk gate routes
  it to human review. It is not proof that the run is malicious. This flag does
  not automatically block or execute a tool.
- `classify_and_assess` also makes an SVM attack prediction independently force
  review, even when the calibrated probability/impact product is small. The
  risk tier still controls which human actions are allowed. No parser or
  XGBoost code is involved in this classifier-side change.

On the strict ten-group `important_instructions` holdout, the raw SVM predicted
attack for 2/10 examples and the novelty signal marked 6/10 OOD. The combined
`unsafe_flag` also marked 6/10 attacks, while marking 5/20 held-out benign runs.
Thus, for this sample, the attack predictions added no new attack captures
beyond OOD and did add benign reviews. Four unseen-family attacks still had no
classifier unsafe flag. The change improves explicit handoff of the existing
signals; it does not solve unseen attacks.

### Data flow after tagging and lineage

1. **Parser analysis supplies structured evidence.** For each pre-hop tool
   argument or post-hop result, `pipeline.parser_analysis.analyze_clone_payload`
   parses the displayed payload and, when available, compares it with the true
   result object's skeleton. It records parse/schema/structural findings and
   anomalies. This stage does not create the run-level classifier decision.
2. **Tagging labels fields.** `pipeline.tagging_stage.analyze_and_tag` chooses
   true object fields when available, calls `trust_graph.tagging.tag_fields`,
   and returns a `TaggingResult` containing the analysis, field tags, and run
   state. Tags carry trust/provenance, role, direction, path/type/depth,
   forgery, mimicry, anomaly, and lineage status. Approved tool-matrix profiles
   may supply authority/provenance details; draft profiles are not applied.
3. **Lineage connects values across the run.** `RunStateStore` keeps bounded,
   ephemeral per-run prompts, normalized SYSTEM/EXTERNAL result leaves,
   interception tags, findings, and same-result mentions. On a later
   pre-hop, `provenance.lineage.link_arguments` compares argument values with
   user prompts and earlier results. Matches retain source tags and match
   strength; an unlinked value becomes DERIVED/UNTRUSTED. This is provenance
   evidence, not proof that an action is authorized. Run state is cleared when
   the run ends; overflow or missed/late observations mark the run blind.
4. **Graph construction encodes those relationships.**
   `trust_graph.graph.build_trace_graph` creates a node per tagged field with
   categorical labels (trust, provenance, role, lineage, type, depth,
   direction, forgery, mimicry, anomaly). Parent/child paths become edges;
   lineage connects source and derived nodes; structural findings become
   finding nodes; mimicry and mentions become typed relation nodes. The
   classifier consumes graph structure and labels, not raw field values.
5. **Dataset construction uses complete runs.** `classifier.graph_dataset`
   reads recorded pre/post events, rebuilds tags, lineage, and the graph, then
   stores one graph per run with its label, task group, family/source metadata,
   and attack-success outcome. “Attack” means injection present; it does not
   mean the benchmark attack succeeded. Paired clean/attack runs and all other
   variants in a task group stay together during splitting.
6. **WL-SVM prediction and novelty are separate outputs.** `WLGraphSVM`
   converts categorical graphs into normalized Weisfeiler-Lehman features
   (default two refinement iterations), then uses a calibrated linear SVM for
   `predicted_label` and `attack_probability`. Separately, `novelty_score` is
   the fraction of feature mass absent from the fitted vocabulary; the
   training-group-calibrated threshold determines `out_of_distribution`.
7. **Classifier handoff is explicit.** `unsafe_flag` is the OR of the SVM attack
   prediction and OOD flag; `flag_reasons` preserves both causes. In
   `classify_and_assess`, either cause routes to `human_review`. The graph-risk
   review options are then constrained by risk/impact; `evidence_only` prevents
   a pre-hop tool call or withholds raw post-hop content.

**Integration boundary:** this classifier consumes a complete run graph and is
offline-only. `pipeline.risk_detector.make_risk_detector` deliberately rejects
using it as a per-interception live detector. The parser-only live path is
unchanged. The next teammate can consume `unsafe_flag` and `flag_reasons` as
classifier inputs, but any XGBoost fusion and final live action policy remain
separate work and must be validated end to end.
