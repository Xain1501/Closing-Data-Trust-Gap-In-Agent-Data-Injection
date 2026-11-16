# Updated Scope and Build Plan

Status: proposal. Nothing in this document is built yet unless marked "exists".
Existing names were checked on commit `7f26cf2`. Names marked "new" are proposals.
Paper numbers come from a model summary of the arXiv pages and are **unverified** until checked against the PDFs.

## 1. Goal

A detector that catches Agent Data Injection (ADI) on tool calls and tool results, without lowering benign utility by blocking too much.

- It uses no extra LLM.
- It does not change what the agent sees.
- It checks both directions: the call (pre-hop) and the result (post-hop).

## 2. The core idea

The user's prompt is trusted. Content written by outsiders (an email body, a product review, a GitHub comment, a shared file) is untrusted.

Marking is not enough by itself. Three steps are needed:

1. **Mark** outsider-written content as untrusted.
2. **Keep the mark from being escaped.** ADI makes untrusted text look like a separate trusted field. So field boundaries must come from the tool's real result object, not from reading the text.
3. **Follow the value to the action.** At each tool call, check where every important argument came from. This is where blocking happens.

Example: the injected data says "send the money to CH93…". The agent calls `send_money(recipient="CH93…")`. The argument is a clean IBAN with no delimiters, so the parser sees nothing. The lineage check sees that the value exists only inside an untrusted text field and was never named by the user.

## 3. Scope

### In scope now (measured on AgentDojo)

| Content comes in from | Costly action it can reach |
|---|---|
| email, files, web page text, chat messages | `send_money`, `send_email`, `share_file`, `update_password` |

AgentDojo has 70 tools in four suites (workspace, slack, banking, travel). The ADI paper added 108 ADI attacks over 96 user tasks to these suites and changed the tool output from YAML to JSON. Our vendored `agentdojo/` appears to be that extended version. Open question: we counted 168 payloads, the paper says 108 attacks.

### In scope next (new suites, in our own code, not inside `agentdojo/`)

| Priority | Content comes in from | Costly action |
|---|---|---|
| 2 | GitHub issues, PRs, comments (`gh` / MCP output) | post comment, merge, run a command |
| 3 | browser `read_page` element list | `click(ref)`, `type(ref, text)` |

These are the paper's real-agent attacks (Claude Code, Codex, Gemini CLI, Claude in Chrome, Antigravity). Results on new suites are reported separately, because they are not comparable to the paper's table.

### Later (with the plugin)

- Shell output, memory, web search.
- Orchestration (sub-agents) is cut until the plugin is built.
- Tests on real agents.

### Not claimed

- Paraphrased values, or values the LLM itself transforms.
- Attacks that add no new value (for example, only changing which existing id is picked).
- Tools that return one big string with no structure.

## 4. Related work and our position

| Work | What it does | Gap we target |
|---|---|---|
| ADI paper (arXiv 2607.05120) | Shows the attack. Root cause: agents do not isolate trusted from untrusted data. | We do the isolation at the tool boundary. |
| DualView (arXiv 2607.03821) | Hides untrusted data from the agent as symbols; a second LLM reads it. 0% attack success, 48–93% extra tokens (unverified). | Untrusted data reaching sensitive arguments is listed as future work. Forged structure is not discussed (unverified). |
| LlamaFirewall AlignmentCheck | An LLM audits the whole trace against the user's goal. | Baseline to beat. 45.4% ADI attack success in the ADI paper. |
| CaMeL Strict | Blocks all untrusted data flow. | 0% attack success but 36.5% utility. |
| Agent receipts | Signed, hash-chained records of agent actions. | We reuse the hash-chain idea for the auditor. |

Numbers to beat on AgentDojo with GPT-5.2 (unverified):

| Defense | Attack success | Benign utility |
|---|---|---|
| No defense | 49.1% | 86.5% |
| AlignmentCheck | 45.4% | not stated |
| Randomization | 28.7% | 83.3% |
| Progent | 22.2% | 81.4% |
| CaMeL Strict | 0% | 36.5% |

A good result is attack success well below 22% with utility near 86%.

## 5. Three stores

| Store | Status | Purpose | Who reads it |
|---|---|---|---|
| `InterceptionLedger` | exists | What was captured, with its hash chain | the clone |
| `RunState` | new | The detector's memory for one run: user prompt, tags, value index | the detector |
| `AuditTrail` | new | One record per stage, for humans | humans only; the detector never reads it |

Taint tracking lives in `RunState`, because the detector must read it to decide. The auditor records the trail.

## 6. Tags

Keep the existing vocabulary in `src/trust_graph/tagging.py`: `Provenance`, `Role`, `LineageStatus`, `FieldTag`, `Evidence`, `ProfileEntry`.

| Meaning | Tag |
|---|---|
| Value appears in the user's prompt | `USER` |
| Skeleton: keys, nesting, numbers, booleans, server-generated ids | `SYSTEM` |
| Any string value an outsider could write (default for all strings) | `EXTERNAL` |
| Argument built from earlier values | `DERIVED` |

Tags are derived automatically. The tool matrix is only an optional per-tool override (for example, "this string field is server-generated").

## 7. Data flow

### Result (post-hop). Results are never blocked.

| # | Function | Status | Output |
|---|---|---|---|
| 1 | `runtime.run_function` then `output_formatter` in `TrustVerificationToolsExecutor.query` | exists | raw object and text |
| 2 | `InterceptionCore.check_result(..., raw_result=)` | add argument | `DetectorContext` with `run_id`, `raw_result` |
| 3 | `canonical_json(payload)` in `clone/canonical.py` | new | one frozen string that is hashed, stored and inspected |
| 4 | `analyze_clone_payload` → `parse`, `structural_flags` | exists | `ParserAnalysis` |
| 5 | `build_skeleton(raw_result)` in `parser/skeleton.py` | new | true fields from the object |
| 6 | `tag_fields("post", ...)` | exists | `FieldTag` list |
| 7 | `index_values(tags, fields, run_state)` in `provenance/lineage.py` | new | values added to `RunState` |
| 8 | `AuditTrail.record(stage, ...)` in `pipeline/audit.py` | new | one line per stage |

If a result cannot be inspected, `RunState.blind` is set and later high-impact calls go to review.

### Call (pre-hop). This is where blocking happens.

| # | Function | Status | Output |
|---|---|---|---|
| 1 | `_framework_args` then `InterceptionCore.check_call` | exists | args and `DetectorContext` |
| 2 | `canonical_json` then `ledger.capture` | new, then exists | record |
| 3 | `analyze_clone_payload` | exists | `ParserAnalysis` |
| 4 | `tag_fields("pre", ...)` | exists | roles such as `AUTHORITY_ARG` |
| 5 | `link_arguments(tags, fields, run_state)` in `provenance/lineage.py` | new | `LineageStatus` and `Evidence` per argument |
| 6 | `screen_call(tags, entry)` in `pipeline/call_screen.py` | new | cleared, or needs stage 2 |
| 7 | `extract_flow_features` then `FlowClassifier.predict` | new | flow score |
| 8 | `build_run_graph(run_state)` then `WLGraphSVM.predict` | new, then exists | graph score |
| 9 | `assess_risk` then `decide` | exist; `decide` extended | `DetectorDecision` |
| 10 | `AuditTrail.record` | new | one line per stage |

### Decision rules in simple terms

- **Stage 1** clears a call if the tool is low-impact, or if its authority arguments are grounded in the user's prompt.
- **Stage 2** runs only for calls stage 1 does not clear. Features include:
  - Did the user's prompt point at the source (file name, sender)?
  - Is the value a whole real field, or a fragment inside free text?
  - Did the parser flag forged structure in that same leaf, with a fake key name that matches the argument name?
- **Block only high-impact calls** whose argument came from a forged or untrusted leaf the user did not point to.

## 8. Names to fix now, so they do not change later

- **`DetectorContext`:** add `run_id`, `raw_result=None`, `result_format="json"`.
- **`DetectorDecision` and `InterceptionRecord`:** add `forgery_found`, `schema_ok`, `parse_health`, `decided_by`. `contains_adi` then means forgery only.
- **`RunState`:** `run_id`, `user_prompt`, `values`, `tags`, `blind`.
- **`adi_detector(payload, context)`:** one composed detector registered with the core. `parser_detector` becomes its first stage.

## 9. Classifiers

- **WL-SVM stays**, as the graph branch, on a run-level provenance graph (fields and arguments across the run; edges mean "this argument came from that field").
- **One flow-feature classifier is added.** XGBoost is the planned main model. Logistic regression is run next to it as a check.
- **Fair test:** cross-validation grouped by task, so the model cannot memorise the seeds. The seed set is small.
- The classifier does not do the tracking. The lineage step does. Either model writes its reasons to the auditor.

## 10. Bugs: fix now

| Item | Why now |
|---|---|
| B3, B4: split the logged evidence | Every reported number is read from the ledger. |
| B1: schema check on salvaged `repr` payloads | Small; the same payload is treated two ways today. |
| Different serialisations: canonical string | It changes what the detector receives. |
| A3, A4 | The detector run must match the baseline run. |
| A5, L2, L3 | Crashes break runs. |
| L1 | Long runs are unusable (quadratic rewrite). |
| C5 | The denial text tells the attacker which rule fired. |
| C4: `DetectorContext` fields | The one core interface change everything else needs. |

## 11. Bugs: note now, fix later

| Item | Fixed at |
|---|---|
| B2: text with no delimiters passes | step 4 (lineage) |
| P5: clean attacker-chosen argument | step 4 |
| Rule 4: one finding blocks alone | step 4, when findings become evidence |
| DOM and markdown routing | step 8 |
| `ToolSchemaRegistry` built per call | any time; speed only |
| Parser bug 2 (forged CSV row), bug 3 (other formats), rest of bug 5 (`'truest' :5`) | not fixed in the parser; lineage covers them |
| L4–L9, C1–C3, T2–T5, A1, A2, A6, A7 | plugin stage |

## 12. Build order

1. The "fix now" table.
2. `canonical_json` and the `DetectorContext` fields.
3. `build_skeleton` and automatic `SYSTEM` / `EXTERNAL` tagging.
4. `RunState`, `index_values`, `link_arguments`, `screen_call`. Rule 4 becomes evidence.
5. `AuditTrail`, hash-chained.
6. First experiment on stock AgentDojo: the ADI attacks plus benign tasks, compared with the paper's table.
7. `FlowClassifier`, `build_run_graph`, WL-SVM.
8. GitHub suite, then browser suite with the format router and the DOM detector on the live path.
9. Encoded values (base64, hex, URL, unicode), then the plugin for real agents.

The suites come after step 6, so a detector bug cannot be confused with a suite bug.

## 13. How utility is proven

Report four numbers:

1. Benign utility with and without the detector.
2. Utility under attack.
3. Attack success rate.
4. Count of benign calls blocked.

- **Cheap first measure:** run benign tasks once in monitor mode, save the traces, and replay them offline through each detector version.
- **Final numbers need live LLM runs.** The no-LLM rule must be lifted for that step.

## 14. Open questions

- How the adapter gets the user prompt. `ledger.set_run_metadata` exists and may be the place. Not checked.
- The current signature of `check_result`. Not re-read.
- 108 attacks in the paper versus 168 payloads counted in the vendored copy. Compare against `github.com/compsec-snu/adi`.
- "Paged attention": only found as the vLLM serving technique; no link to injection defense found.
- Steps 7 and 8 may still add fields. They should not rename any.

## Sources

- Agent Data Injection: https://arxiv.org/abs/2607.05120
- DualView: https://arxiv.org/abs/2607.03821
- LlamaFirewall: https://arxiv.org/abs/2505.03574
- ADI artifacts: https://github.com/compsec-snu/adi
