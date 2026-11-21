# FYP 1 offline evaluation

## Scope

FYP 1 evaluates the detector on recorded task suites. It does not claim live traffic or live Groq compatibility. The traces are under `tests/fixtures/traces/benign`; completed attack traces are under the two baseline run directories. The task suites available in the fixture directory are `travel`, `workspace`, `slack`, and `banking`.

## Dataset used

The dataset builder replayed every usable trace through the same clone-to-lineage code used by the detector:

```text
trace → parser analysis → nested tags → run-state values → lineage → trust graph
```

The final all-suite run contained:

| split | total | benign | attack |
|---|---:|---:|---:|
| train | 117 | 73 | 44 |
| held-out test | 44 | 23 | 21 |
| total | 161 | 96 | 65 |

Nine traces with no tool call were skipped. Every task group stayed entirely in one split. Attack examples are now present for all four suites; the newly generated Banking and Slack traces use the Groq `openai/gpt-oss-120b` baseline.

## Models compared

1. Full graph: nested structure, lineage, parser finding nodes, and forgery labels.
2. Without finding nodes.
3. Without forgery labels.
4. Without both finding nodes and forgery labels.

The full graph is built by `classifier.graph_dataset`, trained by `classifier.train`, evaluated by `classifier.evaluate`, and ablated by `classifier.ablation`.

## Held-out results

| model | accuracy | balanced accuracy | attack precision | attack recall | attack F1 | ROC-AUC |
|---|---:|---:|---:|---:|---:|---:|
| Full graph | 95.5% | 95.2% | 100.0% | 90.5% | 95.0% | 98.6% |
| Without finding nodes | 95.5% | 95.2% | 100.0% | 90.5% | 95.0% | 98.8% |
| Without forgery labels | 93.2% | 93.1% | 95.0% | 90.5% | 92.7% | 97.1% |
| Without both | 56.8% | 54.8% | 100.0% | 9.5% | 17.4% | 76.0% |

The full model made two attack false negatives and no benign false positives on this holdout. The result is encouraging, but the attack portion is only 21 examples, so confidence intervals and larger independent test sets are still needed.

## Generalization sanity checks

Two additional checks show why the main score must be treated cautiously:

### Label shuffle

After randomly shuffling the training labels ten times, mean performance fell to **52.0% accuracy**, **49.8% balanced accuracy**, and **1.0% attack recall**. This is close to chance and is a useful check that the normal score is not produced by an evaluation bug alone.

### Leave-one-suite-out

Each suite was held out entirely and the model was trained on the other suites:

| held-out suite | accuracy | balanced accuracy | attack recall |
|---|---:|---:|---:|
| Banking | 100.0% | 100.0% | 100.0% |
| Slack | 74.3% | 78.6% | 100.0% |
| Travel | 42.6% | 50.0% | 0.0% |
| Workspace | 84.2% | 87.0% | 94.4% |

The Travel result is a warning: the model does not reliably generalize from the other suites to Travel. The ordinary grouped split is therefore measuring performance on known suite distributions, not complete cross-suite generalization.

## Reproduction commands

Run from the repository root in PowerShell:

```powershell
$env:PYTHONPATH = "src;agentdojo/src"
python -m classifier.graph_dataset `
  --suites travel workspace slack banking `
  --output-dir .\out\wl_svm_data_all

$env:PYTHONPATH = "src"
python -m classifier.train `
  .\out\wl_svm_data_all\graphs_train.jsonl `
  .\out\wl_svm_data_all\wl_svm.joblib

python -m classifier.evaluate `
  .\out\wl_svm_data_all\wl_svm.joblib `
  .\out\wl_svm_data_all\graphs_test.jsonl

python -m classifier.ablation `
  --train .\out\wl_svm_data_all\graphs_train.jsonl `
  --test .\out\wl_svm_data_all\graphs_test.jsonl `
  --output-dir .\out\wl_svm_ablation_all
```

The generated metrics are in `out/wl_svm_ablation_all/metrics.json`. Generated JSONL and model artifacts remain under `out/` and are ignored by Git.

## What can be claimed in FYP 1

The defensible claim is:

> On the recorded task-suite benchmark, with task-group separation between training and testing, the full clone-to-lineage graph model achieved 95.5% accuracy and 90.5% attack recall. Removing both structural findings and forgery information reduced attack recall to 9.5%.

Do not claim that the detector is proven against live traffic, all providers, or unseen attack families. Also do not call the 95.5% number a final production accuracy: the held-out set is small and the SVM's internal probability calibration currently uses ordinary stratified folds rather than group-aware folds.

## Remaining FYP 1 work

- Add more attack traces per suite and multiple attack types; the new Slack and Banking runs use the available `data_only_syntactic` cases.
- Include the label-shuffle and leave-one-suite-out results in the evaluation discussion; do not present the ordinary split as universal accuracy.
- Add repeated grouped splits or confidence intervals.
- Report benign utility and false-positive rate alongside attack metrics.
- Include parser-only and rule-only baselines in the final comparison.
- Include two end-to-end examples showing tags, forgery attribution, lineage evidence, graph nodes, and final decision.
- Keep live provider testing as future work unless it becomes available and reproducible.

