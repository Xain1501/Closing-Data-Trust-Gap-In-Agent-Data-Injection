# RESEARCH CRITIQUE — "Closing the Data Trust Gap in Agent Data Injection"

Read-only research audit, 2026-11-15, branch `zain/experimental` (HEAD `66fec89`).
Companion to `PROJECT_UNDERSTANDING.md` (same directory), which holds the reconstruction and the
implementation-status tables this critique builds on. Every finding carries
**Severity / Confidence / Type** as defined there. "Observation" = seen in repo or paper;
"Interpretation" = my reading; "Recommendation" = suggested action.

---

## 1. Research assumptions and their validity

### A1. "No published defense separates content-trust from provenance-trust at field level"
- Observation: proposal §3, §5; deck slide 4.
- Interpretation: Partially true as phrased, but the phrasing hides that *data-flow / taint
  defenses already do field-level provenance tracking*, just with policies instead of a
  classifier. CaMeL ([arXiv:2503.18813](https://arxiv.org/abs/2503.18813)) attaches capabilities
  (provenance metadata) to every value flowing through its interpreter; FIDES
  ([arXiv:2505.23643](https://arxiv.org/abs/2505.23643)) does dynamic taint tracking with
  integrity/confidentiality labels on every value and reports blocking all AgentDojo injections
  with policy checks. The ADI paper the project is built on
  ([arXiv:2607.05120](https://arxiv.org/abs/2607.05120)) itself reports — per the vendored
  benchmark README and third-party summaries — that CaMeL-strict's data-flow tracking is the one
  defense that fully prevented ADI. So provenance tracking *is* the known answer to ADI; the gap
  the project can credibly claim is narrower: **a lightweight, framework-external, non-rewriting
  provenance layer that does not require re-architecting the agent as a CaMeL/FIDES interpreter.**
- Severity: High · Confidence: Strongly supported · Type: methodological concern (claim framing).
- Recommendation: Reframe the contribution as *retrofit provenance monitoring for black-box agents*
  and position against CaMeL/FIDES explicitly in the related-work table (both are absent from the
  proposal's comparison table rows except CaMeL as "requires policies").

### A2. "Trust-tag forgery is the threat"
- Observation: proposal §6.4/§8.4.3 ("mimicry of a trusted tag's shape", "tag forgery"); yet the
  design keeps tags in a side record, never in the payload (`docs/tagging-design.md` §2.4;
  `src/trust_graph/tagging.py:1-7`), and strips all metadata before the LLM sees content (§8).
- Interpretation: In the project's own architecture an attacker cannot reach the tags, so "is the
  trust label authentic?" is trivially yes. What the attacker *can* forge is content that imitates
  structure (delimiters, nested objects, pseudo-tool-calls) — which is exactly what the parser
  already detects. The "provenance-trust" vocabulary therefore describes the parser's job, not a
  new capability. The defensible provenance question is different: *did an authority argument of
  a proposed call originate in untrusted content?* — which is lineage (design doc §4), not
  implemented.
- Severity: High · Confidence: Strongly supported · Type: methodological concern (threat model).
- Recommendation: Rewrite the threat model around **untrusted-to-authority data flow** (post-hop
  EXTERNAL value → pre-hop AUTHORITY_ARG) and make lineage the headline mechanism.

### A3. "A non-LLM classifier gives deterministic guarantees"
- Observation: proposal §2, §7.2 contrast "deterministic" with LLM judges; the classifier is an
  SVM over WL features (`src/classifier/wl_svm.py:81-130`).
- Interpretation: An SVM is deterministic at inference but is still a *learned detector*; it
  carries the same adversarial-evasion and distribution-shift weaknesses that the design-patterns
  paper ([arXiv:2506.08837](https://arxiv.org/abs/2506.08837)) and adaptive-attack work
  (e.g. the Nasr et al. adaptive evaluation cited by the PROGRESS_LOG Part B and the Sophos
  summary of 100% human-red-team bypass) attribute to all detection-based defenses. Determinism of
  the *procedure* is not a security guarantee; CaMeL/FIDES guarantees come from *enforcement by
  construction*, not from determinism.
- Severity: Medium · Confidence: Strongly supported · Type: methodological concern.
- Recommendation: Drop "deterministic guarantee" language; claim "reproducible, auditable,
  CPU-cheap, no LLM in the decision loop", and plan an adaptive-attacker experiment (§7 below).

### A4. "The classifier can catch structurally clean, plain-language attacks" (proposal §6.5)
- Observation: Graph node labels are `f"{trust}:{value_type}:depth={depth}"` plus
  `finding:{kind}` nodes (`src/trust_graph/graph.py:18-23`). No lexical, length, role, or
  semantic feature enters the graph. WL features are histograms over these labels
  (`wl_svm.py:52-72`).
- Interpretation: **A benign inbox and the same inbox with a natural-language injection in one
  `body` field produce isomorphic graphs with identical labels**, hence identical WL feature
  vectors. The classifier cannot separate them even in principle. The only distinguishing
  signal available is the parser's finding nodes — so the classifier can at best re-learn the
  parser's output. This is the single most important flaw in the research design as implemented.
- Severity: Critical · Confidence: Confirmed (from code; empirical confirmation needs the
  experiment in §7.E1) · Type: architectural issue / methodological concern.
- Recommendation: Either (i) enrich node labels with role (`AUTHORITY_ARG`/`CONTENT`), lineage
  status, length buckets and cheap content statistics, and add cross-message edges
  (EXTERNAL source → DERIVED argument), so graphs for attacked vs benign *flows* differ; or
  (ii) abandon the claim that the classifier covers wording-only attacks and scope the
  classifier to structural/flow anomalies only.

### A5. "Impact tiers and trust classes can be fixed in advance in a TVM"
- Observation: `src/clone/tool_matrix.json`: 70 tools, all 105 field classes `unclassified`,
  tiers marked "policy default"; `tvm.py:39-55` falls back to unclassified.
- Interpretation: The assumption is reasonable (per-tool static policy is what CaMeL, FIDES and
  Progent also require) but is **not yet instantiated**; without it the provenance axis is a
  constant. The tagging design's tool profiles (§5) are the right replacement but are Phase 2.
- Severity: High · Confidence: Confirmed · Type: implementation defect (blocking the hypothesis).

### A6. "AgentDojo's paired task structure measures utility preservation"
- Observation: proposal §3, §6.8; `src/pipeline/evaluation.py:66-77`.
- Interpretation: Valid — AgentDojo defines benign utility, utility under attack and targeted ASR
  exactly as implemented ([arXiv:2406.13352](https://arxiv.org/abs/2406.13352),
  [github.com/ethz-spylab/agentdojo](https://github.com/ethz-spylab/agentdojo)). Two caveats:
  (1) AgentDojo's stock attacks are natural-language (`important_instructions`), which the parser
  does not target; ADI-style attacks exist only in the vendored compsec-snu fork
  (`data_only_syntactic`), so results depend on the fork (D7 in the understanding doc);
  (2) FPR/FNR at *message* level and ASR at *task* level are different populations — the
  project must state which level each metric is reported at.
- Severity: Medium · Confidence: Confirmed · Type: methodological concern.

## 2. Methodological soundness

| # | Issue | Severity | Confidence | Type |
|---|---|---|---|---|
| M1 | **Label leakage in classifier training**: finding nodes come from the parser; if training labels correlate with parser hits (they will, for syntactic ADI), the SVM learns "finding node present ⇒ attack" and its reported accuracy will be an artifact of the parser, not evidence of graph-level detection. | High | Strongly supported | methodological concern |
| M2 | **Train/test contamination risk**: the parser rules were tuned on generated ADI data; phase-1 README already notes near-duplicates and "only third pages are held-out" (`src/parser/README.md:124-125`). A classifier trained on graphs from the same generator will inherit this. No frozen held-out split exists in code. | High | Confirmed | testing gap |
| M3 | **Risk formula changed without re-justifying thresholds**: the 1/5 thresholds (proposal §6.6.1) were designed for `confidence = 1-(1-S)(1-C)`; the implementation uses `C × impact` (`risk_gate.py:53`) with the same thresholds, plus an override that any structural hit forces review (`risk_gate.py:57`). Net effect: the numeric gate is decorative for tier-1 tools and the override does the work. Thresholds need re-derivation from data (the PROGRESS_LOG Phase 2 "conformal / target-FPR" idea is the right direction). | Medium | Confirmed | unresolved design decision |
| M4 | **Human Approval Accuracy has no protocol**: no number of reviewers, blinding, case sampling, or inter-rater agreement is defined; the evidence panel exposes `untrusted_content` strings directly (`risk_detector.py:63-66`), so the reviewer sees the injection text — fine for accuracy, but the metric must be defined as reviewer-with-panel vs reviewer-without. | Medium | Confirmed | methodological concern |
| M5 | **Base-rate / reviewer-load not in the metric set**: with review forced on any hit, the fraction of traffic escalated (coverage) is the operationally decisive number (noted in PROGRESS_LOG Phase 2, Axelsson base-rate). It is not among the six metrics. | Medium | Strongly supported | methodological concern |
| M6 | **Post-hop blocking cannot undo side effects**: documented by the team (`src/parser/README.md:153`, `risk_gate.py:94-96`). The evaluation must therefore count a pre-hop-executed harmful call as an attack success even if the post-hop result is withheld. | Low | Confirmed | methodological concern |
| M7 | **Two AgentDojo copies, two result formats** (JSON vs YAML, `tagging-design.md` §11): any measured number is environment-dependent until D2 is decided and pinned. | High | Confirmed | reproducibility defect |
| M8 | **Over-defense (RQ4) is measurable now but unplanned**: the hard-benign set (9/33 flagged, `src/parser/README.md:119`) is the seed of a NotInject-style set; it should become a first-class evaluation artifact with a target FPR. | Medium | Confirmed | testing gap |

## 3. Novelty versus the literature

| Work | What it does | Similar to FYP | Different from FYP | Link |
|---|---|---|---|---|
| AgentDojo (Debenedetti et al., NeurIPS D&B 2024) | Executable multi-step benchmark; defines utility, utility-under-attack, targeted ASR; ships defenses (tool filter, PI detector, delimiting, repeat-prompt) | Same metrics; same harness | Benchmark, not a defense; stock attacks are NL, not ADI | [arXiv:2406.13352](https://arxiv.org/abs/2406.13352) |
| ADI paper (Choi et al., 2026) | Defines ADI / probabilistic delimiter injection; ports 9 defenses; finds only strict data-flow tracking stops it | Same threat; same vendored harness | Shows the known remedy is CaMeL-strict-style data flow, i.e. provenance *enforcement* | [arXiv:2607.05120](https://arxiv.org/abs/2607.05120) |
| CaMeL (Google DeepMind, 2025) | Privileged LLM writes a program; quarantined LLM parses untrusted data; capabilities (provenance) on every value; interpreter enforces policies; 77% AgentDojo utility with provable security | Provenance labels per value; policies by tool | Enforcement by construction, requires rewriting the agent; FYP is an external monitor with a classifier | [arXiv:2503.18813](https://arxiv.org/abs/2503.18813) |
| FIDES (Microsoft, 2025) | Dynamic taint tracking with integrity+confidentiality labels in the planner; formal model; blocks all AgentDojo injections under policy | Trust labels, flow from untrusted source to sink | Taint propagates through the planner's variables, not inferred by string matching post hoc; FYP's lineage v1 is substring matching | [arXiv:2505.23643](https://arxiv.org/abs/2505.23643) |
| Spotlighting (Hines et al., Microsoft 2024) | Delimiting / datamarking / encoding so the LLM can see data provenance; ASR >50% → <2% on GPT-family | Marks provenance | Prompt-level, relies on the LLM to honor marks — the proposal correctly classifies this as the weakness it avoids | [arXiv:2403.14720](https://arxiv.org/abs/2403.14720) |
| IsolateGPT (NDSS 2025) | Execution isolation between third-party apps and core; hub mediates cross-app flow with user permission | Mediation layer between agent and tools | OS-style isolation, not field-level inspection; no classifier | [arXiv:2403.04960](https://arxiv.org/abs/2403.04960) |
| Design Patterns for Securing LLM Agents (Beurer-Kellner et al., 2025) | Six architectural patterns (action-selector, plan-then-execute, map-reduce, dual LLM, code-then-execute, context-minimization); argues detection alone is insufficient | FYP's pre-hop gate resembles plan-then-execute with a monitor | Paper's thesis: constrain *what the agent can do* after reading untrusted data; detection-based filters are explicitly deprioritized | [arXiv:2506.08837](https://arxiv.org/abs/2506.08837) |
| IPIGuard (EMNLP 2025) | Tool Dependency Graph planned before reading data; untrusted data cannot add calls | The graph vocabulary the proposal borrows | TDG is call-to-call and enforced; FYP's graph is field-level and only classified | [arXiv:2508.15310](https://arxiv.org/abs/2508.15310) |
| MELON (ICML 2025), Task Shield (ACL 2025) | Behavioral / task-alignment detection via re-execution or LLM judgment | Detect at tool-call time | Both use the LLM; FYP avoids it | [arXiv:2502.05174](https://arxiv.org/abs/2502.05174), [arXiv:2412.16682](https://arxiv.org/abs/2412.16682) |
| NeuroTaint (2026), APPA (2026), PRUDENTIA (2026) | Newer IFC for agents: probabilistic taint, recoverable IFC against over-blocking, FIDES successors on AgentDojo/WASP | Address the same over-blocking vs security tension the FYP gate faces | Show the field is moving toward *graded* IFC, not binary T/UT | [arXiv:2604.23374](https://arxiv.org/abs/2604.23374), [arXiv:2607.24625](https://arxiv.org/abs/2607.24625), [arXiv:2602.11416](https://arxiv.org/abs/2602.11416) |
| WL kernel (Shervashidze et al., JMLR 2011) | Canonical WL subtree kernel | The feature map used in `wl_svm.py` | Proposal cites Kim & Oh 2024 (subgraph generalization) instead of the canonical reference | [jmlr.org/papers/v12/shervashidze11a.html](https://jmlr.org/papers/v12/shervashidze11a.html) |
| Defense via Tool Result Parsing (2026) | Deterministic parsing of tool results as IPI defense | Very close to the FYP's Stage 1 | Needs direct comparison — potential prior art for the parser contribution | [arXiv:2601.04795](https://arxiv.org/abs/2601.04795) |

**Novelty verdict.** (Informational, Strongly supported.) No prior work applies a WL graph
kernel + SVM to per-message field trust graphs for injection detection — that combination is
novel. But novelty of *method* is not the same as novelty of *capability*: the capability
(stopping ADI by provenance) is already shown by CaMeL-strict/FIDES, and the WL-SVM, as currently
featurized, adds no information beyond parser + static trust labels (A4). The genuinely new and
defensible slice is: **a retrofit, framework-external, bidirectional interception layer with
lineage from EXTERNAL results to AUTHORITY arguments, evaluated for the security/utility/
reviewer-load trade-off on AgentDojo ADI attacks** — plus the parser's structural rule set as an
independently useful, zero-FP-so-far detector for syntactic ADI. The arXiv:2601.04795 parsing
paper must be read and cited before claiming the parser as novel.

**What has already been shown not to work (literature):**
- Prompt-level marking alone (Spotlighting, delimiting) — defeated by adaptive attacks and, per
  the ADI paper, by delimiter-mimicry.
- Content classifiers (Prompt Guard, LlamaFirewall) — over-defense (InjecGuard/NotInject,
  [arXiv:2410.22770](https://arxiv.org/abs/2410.22770)) and adaptive bypass; the ADI fork ports
  these and the ADI paper reports they fail against ADI.
- Any detection-only defense under adaptive evaluation (design-patterns paper; Nasr et al.
  adaptive attacks) — reinforces that the FYP should pair detection with *enforcement* (the
  pre-hop gate) and measure under adaptive attackers.

## 4. Fundamental limitations

| # | Limitation | Severity | Confidence | Type |
|---|---|---|---|---|
| L1 | **Information-theoretic ceiling of the graph (A4)**: without content or flow features, benign and NL-attacked messages are indistinguishable; the classifier's reachable contribution is bounded by the parser's findings. | Critical | Confirmed | architectural issue |
| L2 | **Lineage v1 is string containment** (`tagging-design.md` §4.3, §7): paraphrase, encoding, split values, arithmetic transforms, and short values defeat it; the design documents this honestly. Taint-by-construction (FIDES) does not have this hole. | High | Confirmed | architectural issue |
| L3 | **Single-message graphs cannot model the attack**: ADI's harm is realized when a *later* pre-hop call carries attacker-derived authority arguments; proposal scope excludes "multi-hop or transitive trust across sequential calls" (§4.2), which excludes the very flow the detector most needs. Lineage via RunState partially re-admits it, contradicting the stated scope. | High | Strongly supported | unresolved design decision |
| L4 | **Utility pressure of fail-closed defaults**: plain text without a schema is blocked (`parser_analysis.py:24-34`); 13% of benign AgentDojo traffic is non-JSON (PROGRESS_LOG Phase 2, A#4); any hit forces review; no reviewer ⇒ deny. Expect measurable benign-utility loss until schemas and a UNKNOWN verdict exist. | High | Strongly supported | architectural issue |
| L5 | **Small-data classifier**: AgentDojo has 97 user tasks / 629 injection cases; graph-level labels are few and highly templated; calibration via `CalibratedClassifierCV` with ≤5 folds on this will be noisy (`wl_svm.py:99-115`). | Medium | Strongly supported | methodological concern |
| L6 | **Post-hop cannot undo side effects** (team-documented). Security guarantees are effectively pre-hop only. | Medium | Confirmed | architectural issue |
| L7 | **Adaptive attacker not modeled**: the parser's regexes are public and deterministic; an attacker can craft structure that evades `_COUNTED` patterns (`structural.py:38-48`) or floods RunState past its cap (`tagging-design.md` §4.1). | High | Strongly supported | research opportunity |
| L8 | **Latency/overhead claims rest on throw-away scripts** (PROGRESS_LOG Phase 2); no committed benchmark test. | Low | Confirmed | testing gap |

## 5. Alternative methodologies worth considering

1. **Policy/IFC-first, classifier-second.** Make the deterministic rule "EXTERNAL-derived value
   in an AUTHORITY_ARG of a tier-10 tool ⇒ review" the primary mechanism (this is CaMeL-strict's
   policy in monitor form), and use the WL-SVM only to *rank* review queue items. This matches
   what the literature shows works and keeps the project's "no LLM in the loop" identity.
2. **Flow graph instead of per-message graph.** Nodes = fields across the whole run; edges =
   parent/child *and* lineage links (EXTERNAL → DERIVED) *and* tool-call sequencing. WL over this
   graph has something to learn (attack flows have a characteristic UT-source→authority-sink
   motif); per-message graphs do not.
3. **Conformal / target-FPR thresholds per tool** (PROGRESS_LOG Phase 2 S3) in place of the
   fixed 1/5 cut-offs; report coverage (abstention/review rate) alongside FPR.
4. **Three-way verdict (CLEAN / SUSPICIOUS / UNKNOWN)** so unparseable ≠ malicious (Phase 2 S2),
   reducing the utility loss in L4.
5. **Compare against the strongest in-repo baselines**: the vendored fork already ports CaMeL,
   CaMeL-secpol(-strict), Progent, IsolateGPT, LlamaFirewall, Prompt Guard (root README lines
   492-505). Running them on the same tasks is cheap relative to building anything, and is the
   only way to show where a retrofit monitor sits on the security/utility frontier.
6. **Adaptive evaluation**: give a red-teamer the parser regexes and the lineage rules and
   measure ASR again; report both static and adaptive ASR (design-patterns paper's standard).

## 6. Research gaps the project could genuinely fill

- G1. Quantified security/utility/reviewer-load trade-off of a *retrofit* (no agent rewrite)
  provenance monitor on ADI attacks — not reported by CaMeL/FIDES, which assume control of the
  agent loop. (research opportunity, High value)
- G2. A frozen, documented **syntactic-ADI structural rule set with measured FPR on hard benign
  data** — useful regardless of the classifier's fate. (research opportunity)
- G3. Empirical answer to "does a graph kernel add anything over rules + lineage?" — a negative
  result here is publishable at FYP level if the experiment is clean (E1/E2 below).
- G4. Over-defense measurement for structural (non-lexical) detectors — complements InjecGuard,
  which covers lexical detectors.

## 7. Experiments needed to validate the claims (priority order)

| ID | Experiment | Validates | Prerequisite |
|---|---|---|---|
| E0 | Pin one AgentDojo copy + JSON formatter (D1/D2 of tagging-design §11.5); commit a reproducible environment; run `baseline` with `data_only_syntactic` on workspace to establish undefended ASR/utility | Everything downstream | API key; decision D2 |
| E1 | **Graph-separability test**: build graphs for paired benign vs attacked messages (NL injection) with current labels; verify feature vectors are identical (expected: yes). Then repeat with enriched labels (role, lineage status, length bucket). | A4 / L1 | Step-1.2 tagging wired to `graph.py` |
| E2 | **Ablation**: parser-only vs parser+lineage rule vs parser+lineage+WL-SVM, on a frozen held-out split (by seed/task, not by message) | M1, G3 | Training JSONL producer |
| E3 | End-to-end AgentDojo run in `passthrough` (parity) then `enforce`, reporting benign utility, utility under attack, targeted ASR, message-level FPR/FNR, **review rate** | RQ1, RQ3, L4 | E0, reviewer stub |
| E4 | Baseline comparison against in-repo CaMeL-strict, Progent, IsolateGPT, Prompt Guard on the same tasks | A1, novelty | E0 |
| E5 | Over-defense set (NotInject-style structural benign: JSON-in-prose, code, curl, markdown tables) with a stated FPR target | RQ4, M8 | Extend `hard_benign.jsonl` |
| E6 | Adaptive attacker: regex-aware delimiter mutation + lineage evasion (encoding, splitting, flooding RunState cap) | L7 | E3 |
| E7 | Human-review study: N reviewers × M escalated cases, blinded to label, with/without evidence panel; report accuracy and time | Human Approval Accuracy | Panel renderer, protocol |
| E8 | Latency budget test committed to CI (p95 per message, 10k-field payload) | NFR §7.2, L8 | — |

## 8. Consolidated finding list (severity-ordered)

| # | Finding | Severity | Confidence | Type | Where |
|---|---|---|---|---|---|
| F1 | Trust graph labels carry no content/flow information ⇒ WL-SVM cannot distinguish NL-attacked from benign messages; classifier is bounded by parser output | Critical | Confirmed | architectural issue | `src/trust_graph/graph.py:18-23`, `src/classifier/wl_svm.py:52-72` |
| F2 | Headline metrics (ASR, utility) never measured; no LLM-backed run; InjecAgent absent | Critical | Confirmed | testing gap | `src/pipeline/evaluation.py`, READMEs |
| F3 | Classifier has no training data, no artifact, 0-byte tests | Critical | Confirmed | testing gap | `src/classifier/train.py`, `tests/unit/test_classifier.py` |
| F4 | All TVM field classes `unclassified` ⇒ every field UT ⇒ provenance axis constant in the live path | High | Confirmed | implementation defect | `src/clone/tool_matrix.json`, `tagging.py:279` |
| F5 | Provenance lineage (the mechanism that would realize the thesis) unimplemented; `src/provenance/` empty | High | Confirmed | implementation gap | `docs/tagging-design.md` §4 |
| F6 | Contribution framing overstates the gap; CaMeL/FIDES already do field-level provenance; ADI paper shows CaMeL-strict stops ADI | High | Strongly supported | methodological concern | proposal §3, §5 |
| F7 | "Tag forgery" threat model does not match an architecture whose tags are never attacker-reachable | High | Strongly supported | methodological concern | proposal §6.4; `tagging-design.md` §2.4 |
| F8 | Two AgentDojo copies with different result formats; undecided D1–D3 block per-field tagging and reproducibility | High | Confirmed | unresolved design decision | `docs/tagging-design.md` §11 |
| F9 | Fail-closed defaults (NOT_JSON block, any-hit review, no-reviewer deny) risk large benign-utility loss; unmeasured | High | Strongly supported | architectural issue | `parser_analysis.py:24-34`, `risk_gate.py:55-68` |
| F10 | Label-leakage / contamination risk in any classifier evaluation on generator-derived data | High | Strongly supported | methodological concern | `src/parser/README.md:123-131` |
| F11 | Risk formula changed from proposal (`C×impact` vs `1-(1-S)(1-C)`) without updating proposal or re-deriving thresholds | Medium | Confirmed | unresolved design decision | `risk_gate.py:52-57`, `src/pipeline/README.md:61` |
| F12 | Lineage v1 = substring matching; documented evasions (encoding, paraphrase, split, flooding) | Medium | Confirmed | architectural issue | `tagging-design.md` §7 |
| F13 | No adaptive-attacker evaluation planned | Medium | Confirmed | research opportunity | proposal §6.8 |
| F14 | Human Approval Accuracy has no study protocol | Medium | Confirmed | methodological concern | proposal §6.8.2 |
| F15 | Reviewer load / coverage missing from metrics | Medium | Strongly supported | methodological concern | proposal §6.8.2 |
| F16 | Possible prior art for the parser contribution (tool-result parsing defense, 2026) uncited | Medium | Research-dependent | research opportunity | [arXiv:2601.04795](https://arxiv.org/abs/2601.04795) |
| F17 | WL kernel cited via a 2024 generalization paper rather than the canonical reference | Low | Confirmed | documentation | proposal ref [13] |
| F18 | Root README concatenates upstream ADI README incl. foreign citation block | Low | Confirmed | documentation | `README.md:339-573` |
| F19 | Known failing test ("E003 baseline") and a flagged legacy assertion left unreconciled | Low | Confirmed | testing gap | commit `66fec89`; `src/pipeline/README.md:178` |

---
*Observations are from the repository at HEAD `66fec89` and the linked papers' abstracts/HTML;
numbers quoted from third-party summaries (e.g. ADI-paper ASR figures, FIDES utility deltas) should
be re-verified against the primary PDFs before being cited in the thesis.*
