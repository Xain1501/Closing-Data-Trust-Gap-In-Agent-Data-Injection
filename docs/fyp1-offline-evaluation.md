# FYP 1 offline evaluation

> **Run-level-only correction:** Earlier figures in this report were produced
> before the classifier input contract was made explicit. The copied-label
> per-decision metrics below are withdrawn and must not be used as per-call
> performance claims. The maintained WL-SVM is trained/evaluated on complete
> runs only and is not used for live interception.
>
> **Current result:** Use “Natural-benign supplement v4” below. It evaluates 182
> raw-object examples (87 injected, 87 matched clean counterfactual, 8 natural
> clean); the standard held-out split has 59 runs across 16 groups. WL-SVM
> accuracy is 71.2%, while the parser-rule and summary-feature baselines score
> 84.7% and 83.1%. Earlier results in this document are historical and must not
> be presented as the current v4 result.

## Scope

FYP 1 evaluates the detector on recorded task suites. It does not claim live
traffic or live Groq compatibility. Benign fixtures and recorded AgentDojo
attack traces are replayed through the clone executor to retain raw tool
results. The task suites are `travel`, `workspace`, `slack`, and `banking`.

## Historical dataset used (superseded)

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

## Historical claim (superseded; do not cite)

The following claim referred to an earlier dataset and model run. It is
superseded by the v4 results below:

> On the recorded task-suite benchmark, with task-group separation between training and testing, the full clone-to-lineage graph model achieved 95.5% accuracy and 90.5% attack recall. Removing both structural findings and forgery information reduced attack recall to 9.5%.

Do not use these numbers as current results. The current v4 evaluation uses grouped calibration, but remains offline-only and does not establish performance on live traffic, all providers, or unseen attack families.

## Historical follow-up checklist (superseded)

This checklist described work outstanding at the time of the earlier run. Baselines,
grouped intervals, and the natural-benign v4 supplement have since been added.
Further natural benign data, independent attack families, utility evaluation,
and validated live testing remain open; see “Natural-benign supplement v4.”

## Superseded exploratory all-available-trace run (24 November 2026)

I rebuilt the dataset from every locally available benign trace and every collected
syntactic or semantic attack trace in the four suites. This produced **178 usable
graphs** (131 train, 52 test); 10 traces were skipped because they contained no tool
calls. The split remains grouped by task, so a task cannot appear in both partitions.
The dataset contains 96 real-object traces and 87 text-derived benchmark traces;
the latter are explicitly marked and were included only with the exploratory
`--allow-text-derived-mix` option.

The current holdout result is:

| accuracy | balanced accuracy | attack precision | attack recall | attack F1 | ROC-AUC | PR-AUC |
|---:|---:|---:|---:|---:|---:|---:|
| 84.6% | 86.2% | 100.0% | 72.4% | 84.0% | 93.9% | 96.2% |

The lower score compared with the earlier syntactic-only run is expected: this run
includes the small set of semantic traces collected so far and is therefore a more
difficult, mixed-distribution check. The label-shuffle check stayed near chance
(48.1% accuracy, 13.4% attack recall). Leave-one-suite-out accuracy was 73.3% for
Banking, 64.4% for Slack, 57.1% for Travel, and 44.1% for Workspace; cross-suite
generalization remains variable and is not solved by adding a few semantic traces.
the main unseen-suite weakness.

The ablation run is saved under `out/fyp1_all_available_attacks/ablations/metrics.json`.
The full model reached 84.4% attack F1. The classifier now uses grouped calibration,
normalized summary features, leaf-forgery/mimicry/anomaly/relation features, and
complete structural-label ablations. Removing both findings and structural labels
reduced attack F1 to 50.0% in this run.
This supports retaining both signals, while the absolute score should be treated as
preliminary because semantic coverage is incomplete.

The final local artifacts are:

- `out/fyp1_all_available_attacks/graphs_train.jsonl`
- `out/fyp1_all_available_attacks/graphs_test.jsonl`
- `out/fyp1_all_available_attacks/wl_svm.joblib`
- `out/fyp1_all_available_attacks/ablations/metrics.json`

The local model SHA-256 is
`65681B394D47FAF09877314C26ACDA0B2E03ADDBF558D580540094256BAB880A`.
The model is intentionally not tracked in Git; rebuild it from the tracked graph
JSONL and verify this hash when comparing local runs.

The earlier dataset builder rejected accidental mixing of real-object and
text-derived traces by default. The preceding historical metrics used an
exploratory text-derived attack set; those results are superseded by the
corrected raw-object rebuild documented below. No synthetic examples were
added.

### Baselines and withdrawn decision-point analysis

On the same held-out set, the parser/findings rule achieved 84.6% accuracy and
72.4% attack recall. A logistic regression using only normalized summary features
achieved 82.7% accuracy and 69.0% attack recall. The WL-SVM therefore has a small
advantage over these baselines, but the gap is not large enough to claim that the
graph representation is the only source of value.

The historical per-decision calculation covered 544 decisions (272 pre and 272
post), with 62.9% accuracy and 45.3% attack recall. It copied each run's label
onto every interception, so it had no valid per-decision ground truth. These
numbers are withdrawn; the evaluator now rejects this calculation. A separate
decision-level model would require valid labels per decision and is not part of
the selected run-level-only design.

`dataset_manifest.json` records the suite, label, benchmark/attack family, and
SHA-256 for every source trace. The corrected dataset uses replayed raw-object
attack results; this is a new replay, not a reconstruction from formatted
benchmark messages.

The loader normalizes both graph serializations used by the team (`node_labels`
plus edge pairs, or node/link records), so the same contract is applied to training
and testing. Dataset construction also supports group-preserving benchmark,
attack-family, and source holdouts, and reports performance by those dimensions.

There is no separately labeled ADI benchmark corpus in the workspace. The
available attack recordings execute on AgentDojo; `data_only_*` describes an
attack family, not a separate benchmark family. The schema stores
`benchmark_family: "agentdojo"` separately from the concrete attack families
`data_only_semantic` and `data_only_syntactic`. Do not treat these family counts as
an ADI benchmark evaluation.

## Matched counterfactual v3 evaluation (superseded by v4 below)

The recorder replays each recorded attack tool-call sequence twice: once with its
injection and once in the same task's clean environment. Both traces carry the
same matched-pair ID and SHA-256 of the tool/function argument sequence; dataset
construction requires exactly one benign and one attack trace per pair with the
same hash. The fresh traces are in `out/paired_attack_v3` and
`out/paired_clean_v3`; 97 pairs replayed without failures. The generated dataset
and model report are in `out/wl_svm_matched_v3` and `out/fyp1_matched_v3`.

After excluding 10 pairs with no usable tool call, the dataset contains 174
run-level examples (87 injected, 87 clean counterfactuals); all have raw object
results (`text_derived: 0`). The group-preserving split used 80 training runs
(28 groups), 36 validation runs (12 groups), and 58 held-out test runs (16 groups).
On the held-out runs:

| metric | result |
|---|---:|
| accuracy | 0.707 |
| balanced accuracy | 0.707 |
| attack precision | 0.700 |
| attack recall | 0.724 |
| attack F1 | 0.712 |
| ROC-AUC | 0.759 |
| PR-AUC | 0.805 |

The confusion matrix (`attack`, `benign`) is `[[21, 8], [9, 20]]`. The
semantic-family subgroup attack recall is only 12.5% (1/8 held-out semantic
attacks); syntactic-family recall is 95.2% (20/21). These are small, grouped
subsets and not evidence of broad family generalization.

The strict semantic-family holdout is in `out/wl_svm_holdout_semantic_v3` and
`out/fyp1_holdout_semantic_v3`. It holds out all groups containing semantic
attacks, including their paired clean traces and any same-task variants. Its
test set has 112 runs (30 groups); semantic attack recall is 13.6% (3/22), while
overall attack recall is 55.4%. This indicates that current family coverage does
not establish unseen-attack readiness. A strict syntactic-family holdout remains
infeasible with the existing task groups because it leaves too little training
data.

## Baselines and ablations on the matched split

The parser-only rule and summary-feature logistic regression were trained on the
same 80 training runs and evaluated on the same 58 held-out runs as the WL-SVM.
The rule flags finding nodes, direct/leaf forgery, and mimicry; it is a
comparison baseline, not a separate live-detector result.

| model | accuracy | balanced accuracy | attack precision | attack recall | attack F1 |
|---|---:|---:|---:|---:|---:|
| Parser-flag rule | 0.845 | 0.845 | 1.000 | 0.690 | 0.816 |
| Summary-feature logistic regression | 0.828 | 0.828 | 1.000 | 0.655 | 0.792 |
| Full WL-SVM | 0.707 | 0.707 | 0.700 | 0.724 | 0.712 |

The parser rule and summary model have better accuracy and F1 on this split;
WL-SVM has 3.4 percentage points more attack recall than the parser rule. This
small test set does not show that the full graph classifier adds overall value.
Group-bootstrap 95% intervals (whole task groups, 1,000 resamples) are:

| model | accuracy interval | attack recall interval | attack F1 interval |
|---|---:|---:|---:|
| Parser-flag rule | 0.776–0.917 | 0.552–0.833 | 0.711–0.909 |
| Summary-feature logistic regression | 0.750–0.911 | 0.500–0.821 | 0.667–0.902 |
| Full WL-SVM | 0.615–0.788 | 0.595–0.870 | 0.650–0.780 |

These intervals are wide and overlap; the small test set does not establish a
statistically reliable ranking.

The ablation run is in `out/ablation_matched_v3/metrics.json`:

| WL-SVM variant | accuracy | attack recall |
|---|---:|---:|
| Full graph | 0.707 | 0.724 |
| Without finding nodes | 0.621 | 0.793 |
| Without forgery, mimicry, and anomaly markers | 0.690 | 0.724 |
| Without findings or those markers | 0.603 | 0.759 |

Removing features changes the precision/recall balance; this ablation does not
isolate provenance as the source of predictive value. The raw counters are
available in the generated report.

## Reproduction commands

These commands use the existing, local `runs/` attack recordings and do not call
an external model provider:

```powershell
$env:PYTHONPATH = "src;agentdojo/src"
python scripts/record_attack_traces.py `
  --input runs\baseline_llama-3.3-70b-versatile runs\baseline_openai_gpt-oss-120b `
  --output out\paired_attack_v3 `
  --paired-clean-output out\paired_clean_v3 `
  --overwrite
python -m classifier.graph_dataset --all-suites `
  --benign-traces out\paired_clean_v3 `
  --attack-runs out\paired_attack_v3 `
  --require-matched-pairs `
  --output-dir out\wl_svm_matched_v3
python scripts/final_prototype.py `
  --dataset out\wl_svm_matched_v3 `
  --output out\fyp1_matched_v3
python -m classifier.baselines `
  --train out\fyp1_matched_v3\graphs_train.jsonl `
  --test out\fyp1_matched_v3\graphs_test.jsonl
python -m classifier.ablation `
  --train out\fyp1_matched_v3\graphs_train.jsonl `
  --test out\fyp1_matched_v3\graphs_test.jsonl `
  --output-dir out\ablation_matched_v3
```

The `runs/` source recordings are local and are not tracked in Git. The generated
dataset manifest stores input hashes, but reproducing these exact figures on a
different checkout also requires those source recordings.

## Natural-benign supplement v4

The new collector recorded eight no-injection runs from the Groq-hosted
`openai/gpt-oss-120b` baseline across Banking, Slack, Travel, and Workspace. It
ran each task through the same clone executor in passthrough mode and stores raw
tool results. These are natural model-generated tool-call sequences, not clean
replays of an attack sequence. Their pipeline name matches the existing
GPT-OSS attack recordings. The source JSON files are under
`runs/natural_benign_gpt_oss_120b_v1_2_2`; each of the eight had at least one
tool call.

The v4 dataset (`out/wl_svm_natural_matched_v4`) combines these with the 87
matched counterfactual pairs: 182 usable examples total (87 injected, 87
counterfactual clean, 8 natural clean). All results are raw-object (`text_derived:
0`). The final evaluation (`out/fyp1_natural_matched_v4`) has 85 training runs,
38 validation runs, and 59 held-out runs across 16 test groups. Only one of the
eight natural runs falls in this test split; it was classified benign.

| metric | v4 held-out result |
|---|---:|
| accuracy | 0.712 |
| balanced accuracy | 0.712 |
| attack precision | 0.700 |
| attack recall | 0.724 |
| attack F1 | 0.712 |
| ROC-AUC | 0.763 |
| PR-AUC | 0.800 |

Group-bootstrap 95% intervals are 0.620–0.792 for accuracy,
0.595–0.870 for attack recall, and 0.650–0.780 for attack F1. Matching the
pipeline/model source improves provenance balance, but eight natural benign
runs are too few to establish real-world benign performance.

The v4 parser-rule baseline scores 0.847 accuracy (95% group interval
0.782–0.918), 0.690 attack recall (0.552–0.833), and 0.816 attack F1
(0.711–0.909). Summary-feature logistic regression scores 0.831 accuracy
(0.759–0.911), 0.655 attack recall (0.500–0.821), and 0.792 attack F1
(0.667–0.902). The full WL-SVM remains behind these baselines on accuracy and
F1, with slightly higher attack recall than the rule. The v4 ablation is in
`out/ablation_natural_matched_v4/metrics.json`; removing finding nodes gives
0.661 accuracy / 0.793 attack recall, removing structural flags gives 0.695 /
0.724, and removing both gives 0.610 / 0.724.
The v4 WL-SVM group-bootstrap intervals are 0.620–0.792 for accuracy,
0.595–0.870 for attack recall, and 0.650–0.780 for attack F1. Baseline
intervals overlap these ranges, so the small test set does not establish a
reliable ranking.

The v4 semantic-family holdout (`out/wl_svm_natural_holdout_semantic_v4`,
`out/fyp1_natural_holdout_semantic_v4`) contains 119 test examples in 30 groups.
Semantic-family attack recall remains 13.6% (3/22), and overall attack recall
is 55.4%. This remains insufficient evidence for unseen-attack readiness.

To collect the same eight natural runs again, this provider-backed command uses
the locally configured `GROQ_API_KEY` and can incur model usage:

```powershell
python scripts\record_clean_agentdojo.py `
  --task banking:user_task_1 --task banking:user_task_3 `
  --task slack:user_task_1 --task slack:user_task_4 `
  --task travel:user_task_0 --task travel:user_task_1 `
  --task workspace:user_task_0 --task workspace:user_task_1 `
  --model openai/gpt-oss-120b `
  --benchmark-version v1.2.2 `
  --max-iterations 6 `
  --output-dir runs\natural_benign_gpt_oss_120b_v1_2_2
```

Then rebuild the v4 dataset and report:

```powershell
$env:PYTHONPATH = "src;agentdojo/src"
python -m classifier.graph_dataset --all-suites `
  --benign-traces out\paired_clean_v3 runs\natural_benign_gpt_oss_120b_v1_2_2\openai_gpt-oss-120b `
  --attack-runs out\paired_attack_v3 `
  --require-matched-pairs `
  --output-dir out\wl_svm_natural_matched_v4
python scripts\final_prototype.py `
  --dataset out\wl_svm_natural_matched_v4 `
  --output out\fyp1_natural_matched_v4
python -m classifier.graph_dataset --all-suites `
  --benign-traces out\paired_clean_v3 runs\natural_benign_gpt_oss_120b_v1_2_2\openai_gpt-oss-120b `
  --attack-runs out\paired_attack_v3 `
  --require-matched-pairs `
  --holdout-attack-family data_only_semantic `
  --output-dir out\wl_svm_natural_holdout_semantic_v4
python scripts\final_prototype.py `
  --dataset out\wl_svm_natural_holdout_semantic_v4 `
  --output out\fyp1_natural_holdout_semantic_v4
```

The local, uncommitted `out/classifier_handoff_v5.zip` contains the paired replay
traces, eight natural benign traces, manifests, graph splits, reports, ablation
metrics, supplemental direct-goal controls, and these handoff documents. It
excludes serialized models. It is sufficient to rebuild the v4 datasets from
the recorded replay traces; regenerating those replay traces from the original
provider recordings requires the separate source runs, which are not included.
Share the archive only through an approved private channel, not a public
repository.

These are exploratory run-level results, not online or per-call performance.
The label means an injection/attack trace was present, not that an attack
succeeded. The v3 benign examples are counterfactual replays; v4 adds only eight
natural benign model runs. Matching source/model helps control a confound but
does not establish performance across naturally different benign behavior,
other sources, or unseen benchmarks. More independent task groups, attack
families, and benchmarks are needed before claiming unseen-attack readiness.

The run-level WL-SVM now computes a graph-novelty score: the fraction of WL
feature mass absent from its training vocabulary. Its threshold is the
95th-percentile novelty observed when each training group is held out from the
other training groups. A score above that threshold sets
`classifier_out_of_distribution`, which forces the offline graph risk gate to
human review even when attack probability is low. This is a conservative
novelty-to-review policy, not an "unsafe" prediction: distribution shift alone
does not prove an attack.

Measured on the existing splits, the standard v4 holdout flagged 2/59 runs
(1/29 attacks and 1/30 benign); the semantic-family holdout flagged 34/119
(17/56 attacks and 17/63 benign). Thus the heuristic catches only 17/56
semantic-family attacks at its group-calibrated operating point, while also
reviewing 17/63 benign runs. It is a concrete abstention safeguard, but these
results do not establish reliable unseen-attack detection; more independent
attack families and benign groups are required. The model remains offline-only,
and live interception remains parser-only. Retrain models with the current
`classifier.train` before using the calibrated novelty threshold: older format
1-3 artifacts have no such calibration and conservatively flag any nonzero
unseen-feature mass for review.

## Supplemental direct-goal no-injection controls

The nine traces in `out/new_attack_runs` were checked against the installed
AgentDojo v1.2.2 workspace injection-task registry. Their prompts match
registered `InjectionTask.GOAL` values exactly, but the trace files store those
IDs as `user_task_id`; they are not valid user tasks. These records contain no
environment injections, so they are not positive examples for the primary
injection-presence target and were not mixed into its training set.

Eight GPT-OSS traces have at least one tool call (16 calls total); seven have a
successful AgentDojo security outcome, while one outcome is unknown. A duplicate
Llama trace with no tool calls was excluded. Outcome success is retained
separately and does not determine the no-injection label. The retained traces
are text-derived and live in
`out/direct_goal_challenge_v1/graphs.jsonl` with explicit
`no_injection_direct_user_goal_control` labels. They are held-out controls,
not part of the v4 test split. The v4 model flagged two of eight as attack
(25% false-positive rate; 75% specificity) on this small control set. Do
not interpret this as attack recall or as a general benign false-positive rate.

Rebuild and score the controls locally:

```powershell
$env:PYTHONPATH = "src;agentdojo/src"
python scripts/build_direct_goal_challenge.py
python scripts/evaluate_direct_goal_controls.py
```

`graph_dataset.py` now handles AgentDojo's `content`-based text blocks and
string-valued tool-function field, preserving the prompt and result text while
marking the reconstructed observations as text-derived. No tagging code or
primary v4 training input was changed.

