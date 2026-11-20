# Clone → parser → tagging → lineage → graph → WL-SVM

## Purpose

This document explains the implemented path and the validation run for teammates. The system keeps the original tool result available long enough to recover its real structure, marks where values came from, builds a provenance graph, and optionally uses a trained classifier as evidence for the risk gate.

## What happens to one tool turn

```text
AgentDojo/clone adapter
  → InterceptionCore (IDs, prompt, batch, raw result)
  → parser + schema/structure checks
  → nested field tagging (SYSTEM structure, EXTERNAL leaves)
  → per-run value ledger
  → next-call argument lineage
  → trust graph (parent/child, lineage, forgery/finding evidence)
  → WL subtree features
  → calibrated linear SVM probability
  → impact/risk gate and review decision
```

The parser-only detector remains available. The graph and classifier path is opt-in through `make_risk_detector` or the live smoke script's `--risk-model` option.

## Implemented pieces

### 1. Clone and parser handoff

`src/clone/adapters/agentdojo.py` and `src/clone/core.py` pass the run ID, interception ID, user prompt, batch ID, formatted payload, and the original `raw_result` object. The raw object matters because formatting can make text inside a real field look like a second field.

`src/pipeline/parser_analysis.py` parses the visible payload and, for structured post results, builds a skeleton from the raw object. Parser findings are attached to their owning true field.

### 2. Nested tagging and forgery attribution

`src/trust_graph/tagging.py` and `src/pipeline/tagging_stage.py` create side-record tags with stable paths and IDs. The active default is:

- object/array structure: `SYSTEM`;
- scalar leaves: `EXTERNAL`;
- approved profiles may override a field.

`FieldTag.has_forgery` records whether structural scanning found a counted forged-field pattern inside that true field. This is field-level attribution, including nested fields. The raw skeleton is used whenever available, so fake delimiters in a body string do not become trusted siblings.

### 3. Lineage

`src/provenance/run_state.py` stores bounded per-run source values and tags. `src/provenance/lineage.py` links a later string argument to, in order, the prompt, an exact SYSTEM value, or an exact/bounded EXTERNAL value. Each link carries the source tag ID, interception ID, path, match type, and forgery flag. Batch IDs prevent a call from using a sibling call's result as an earlier source. State is cleared at run end.

### 4. Graph

`src/trust_graph/graph.py` builds nodes for fields and arguments, parent/child edges for nesting, lineage edges for value flow, and optional finding nodes. Node labels preserve provenance, role, direction, depth, and `forgery=true/false`.

`src/classifier/graph_dataset.py` replays the recorded traces through the same tagging/lineage code. Each complete task/run is one graph group, so related events stay together during splitting. Attack/benign labels come from the source trace category; an `attack` label means an attack trace, not proof that the attack succeeded.

### 5. WL-SVM

`src/classifier/wl_svm.py` counts Weisfeiler-Lehman subtree labels at iterations 0–2. A linear SVM receives these sparse counts, and sigmoid calibration produces an attack probability. The artifact records the training group IDs so evaluation can reject train/test group overlap.

Training and evaluation are exposed by `classifier.train` and `classifier.evaluate`. Generated data and models are under `out/` and are intentionally ignored by Git.

## Data used in this run

The dataset builder used checked-in benign traces and completed baseline attack runs for the `travel` and `workspace` suites.

| split | graphs | benign | attack | groups |
|---|---:|---:|---:|---:|
| train | 80 | 47 | 33 | 80 |
| test | 24 | 12 | 12 | 12 |
| total | 104 | 59 | 45 | 92 |

Three traces without a usable tool call were skipped. No group appeared in both splits. This is a small fixture evaluation, not a live Groq/provider evaluation.

## Validation commands run

```powershell
$env:PYTHONPATH = "src;agentdojo/src"
python -m classifier.graph_dataset --output-dir .\out\wl_svm_data
python -m classifier.train .\out\wl_svm_data\graphs_train.jsonl .\out\wl_svm_data\wl_svm.joblib
python -m classifier.evaluate .\out\wl_svm_data\wl_svm.joblib .\out\wl_svm_data\graphs_test.jsonl

$env:PYTHONPATH = "src"
python -m classifier.ablation `
  --train .\out\wl_svm_data\graphs_train.jsonl `
  --test .\out\wl_svm_data\graphs_test.jsonl `
  --output-dir .\out\wl_svm_ablation
pytest -q
```

The full test suite completed with **628 passed, 6 expected failures, and one pytest cache-permission warning**.

## Held-out classifier result

The full graph model produced:

| metric | result |
|---|---:|
| accuracy | 0.958 |
| balanced accuracy | 0.958 |
| attack precision | 1.000 |
| attack recall | 0.917 |
| attack F1 | 0.957 |
| ROC-AUC | 0.986 |
| PR-AUC | 0.988 |
| Brier score | 0.067 |

Its confusion matrix, ordered as `attack, benign`, was `[[11, 1], [0, 12]]`.

## Ablation result

The same 80 training and 24 held-out graphs were used for every variant. Only graph features were removed.

| variant | accuracy | attack recall | attack F1 | ROC-AUC | Brier |
|---|---:|---:|---:|---:|---:|
| full | 0.958 | 0.917 | 0.957 | 0.986 | 0.067 |
| without finding nodes | 0.958 | 0.917 | 0.957 | 0.986 | 0.089 |
| without forgery markers | 0.958 | 0.917 | 0.957 | 0.986 | 0.077 |
| without both | 0.625 | 0.250 | 0.400 | 0.771 | 0.210 |

Full JSON metrics and the four fitted artifacts are in `out/wl_svm_ablation/metrics.json` and its variant subdirectories.

### How to read this

On this fixture, finding nodes and forgery markers are partly redundant with the other graph labels: removing either alone does not change the hard predictions, although probability calibration worsens. Removing both causes a large drop. This supports keeping both signals, but it is not proof that either feature independently generalizes. The dataset is small and the attack traces may contain other correlated cues.

The score is therefore a useful regression result, not a production accuracy claim. Before publication, add more independent tasks/providers, report confidence intervals across repeated grouped splits, and use group-aware cross-validation for the SVM calibration folds. The current external train/test split is group-separated; the SVM's internal calibration uses ordinary stratified folds.

## How to run the complete path

Regenerate data and train the artifact with the commands above. Then use:

```powershell
$env:PYTHONPATH = "src;agentdojo/src"
python scripts/live_clone_parser_smoke.py --risk-model .\out\wl_svm_data\wl_svm.joblib
```

The model artifact must be regenerated when graph labels, tagging rules, source traces, or feature schema change. Only load artifacts produced by this repository because `joblib` uses pickle serialization.

## Current boundaries and follow-up work

- The default matrix has conservative unclassified fields; profile loading is not automatic.
- Text-only tool results have no trustworthy inner skeleton and remain one external leaf.
- Exact/bounded text matching misses paraphrased, encoded, split, or value-free attacks.
- The model path is opt-in; parser-only mode does not use the SVM.
- Post-hop review can stop a result reaching the agent but cannot undo a side effect already executed by a tool.
- The current run used local recorded traces. A Groq-backed AgentDojo run is still required before claiming live-provider compatibility.

