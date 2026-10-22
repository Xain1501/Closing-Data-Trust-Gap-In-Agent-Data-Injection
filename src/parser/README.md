# Parser (Stage 1) - Closing the Data Trust Gap in Agent Data Injection

Stage 1 of the Detector Agent (proposal 6.2, deterministic parsing). It opens a tool message,
splits it into addressable fields, and measures how much *fake structure* hides inside text values.
It makes **no trust decision and blocks nothing**. Tagging, the provenance graph, the classifier and
the risk gate are later stages (not built yet).

```
message (pre_hop call args or post_hop tool result)
   |
   +-- JSON ------> parse() -> ParseResult -> structural_flags() -> StructuralReport (S, hit_count)
   +-- web page --> dom_flags()   -> StructuralReport
   +-- markdown --> md_flags()    -> StructuralReport   (experimental)
   |
   stage1.analyze()  ->  verdict: clean | flagged | untrusted_default
```

Design rule: **structure only, never wording.** No trigger words ("ignore", "system:") are used.

## 1. Files

| File | Role |
|---|---|
| `models.py` | Shared data shapes (Pydantic): `ToolTraffic`, `ParseStatus`, `ParsedField`, `Finding`, `ParseResult`, `StructuralReport`, ... |
| `parser.py` | `parse()`: strict JSON -> addressed fields + status. No scoring. |
| `structural.py` | `structural_flags()`: counts forged-structure signs in JSON text values, computes S |
| `dom_flag.py` | `dom_flags()`: web page text. Layout A (tags) and layout B (accessibility tree `[ref_N]`) |
| `md_flags.py` | `md_flags()`: markdown records. **Experimental**, see section 4 |
| `stage1.py` | `analyze(traffic, fmt)`: one entry point + the verdict rule |
| `adi_eval.py` | Runs ADI benchmark files, reports by scope / attack type / category / delimiter / defense / route |
| `make_extra_cases.py` | Writes the hand-made `prehop_cases.jsonl` and `hard_benign.jsonl` |
| `eval.py`, `agentdojo_offline.py`, `demo.py` | Older runners / demo (see 3) |
| `test_*.py` | Unit tests (`test_dom_layout.py`, `test_dom_linenum.py`, `test_md_flags.py`, `test_stage1.py` are new) |
| `agentdojo_element.py` | Unfinished, unused |

## 2. Setup and commands (Windows PowerShell)

Parser work uses your normal Python (3.12 tested). Do **not** run it inside the `llm-benchmark` uv venv.
Run everything from `src\parser`.

```
python -m pytest                                  # all tests (89 passed before md_flags / stage1 were added)
python demo.py
python make_extra_cases.py --out-dir ..\..\tests\fixtures\cases
python adi_eval.py <cases file> --misses          # replace <cases file> with a real path
python adi_eval.py <cases file> --show <case id>  # findings + raw input of one case
python adi_eval.py <cases file> --diff <attack id># exactly what text an attack injected
python adi_eval.py <cases file> --split dev|heldout
```

Generating ADI cases (run from `llm-benchmark`, with `$env:PYTHONUTF8 = "1"` set on Windows):
```
uv run dib generate -C email -c configs/benchmark_syntactic.yaml -n 2 -f json -o out/generated/email.jsonl
uv run dib generate -C web_dom -c configs/benchmark_syntactic.yaml -n 3 -f web_dom -o out/generated/web_dom3.jsonl
```
`dib generate` only builds the dataset. **Do not use `dib run`**: it calls paid model APIs.

## 3. How each part works

**`parse()`** - strict JSON only (NaN/Infinity rejected, BOM tolerated), limits 1,000,000 bytes and depth 32.
Every field gets a path (`$.emails[0].body`) and a parent link; duplicate keys stay visible (`$.to`, `$.to#2`).
Status is one of `ok`, `invalid_json`, `too_large`, `too_deep`. On failure the whole payload is one untrusted blob.

**`structural_flags()`** - `S = min(1, counted signs / boundaries)`, boundaries = objects + arrays + keys.
Counted signs: `quote_close_structure`, `key_injection`, `object_reopen`, `array_close_object`, `kv_forgery`
(with `"`, `\"`, `'`, curly quotes, backtick, `$`, and `( )` variants), `embedded_json`, `duplicate_key`,
`unexpected_key` (only with a schema). Logged but never counted: `code_fence`, `chat_template_token`,
`schema_violation`. Text is normalised first (HTML entities, `%`-encoding, fullwidth, zero-width/bidi).

**`dom_flags()`**
- Layout A: a real element starts its own line. Allowed before a tag: `3->` line number, `|SCROLL|`, tabs, `*`,
  `[idx]`, `(x,y)` coordinates. A tag after anything else is a forged element.
- Layout B (accessibility tree): a real line has exactly one `[ref_N]`, and ids are unique. Two ids on one
  line, or a repeated id, is a forged element.

**`md_flags()`** (experimental) - numbered record out of sequence, the same top-level record id in two records,
or a field marker `- **key**:` in the middle of a line. The `stage1.analyze(..., fmt="markdown")` route
combines these checks with the JSON text rules over the whole document, because some markdown attacks
embed a fake issue as a Python-dict-like string. Keep this route experimental until it has broader benign
coverage.

**`stage1.analyze()`** - verdict rule:
- `untrusted_default`: JSON that does not parse (proposal 6.2: unparsed content is untrusted by default).
- `flagged`: parsed, and `hit_count >= min_hits` (default 1).
- `clean`: otherwise.

The rule uses `hit_count`, not S, because S shrinks as messages grow. S is passed on unchanged as a feature
for the classifier. **`min_hits = 1` is a design choice to confirm with the supervisor.**
A parse failure gives S = 0 by design: the **status** carries the "untrusted" signal, so the gate must read the status.

**Both directions.** The same parser accepts `pre_hop` (outgoing call arguments) and `post_hop` (tool result)
traffic (proposal 6.1). Real benchmark data exists only for post_hop; pre_hop has a small hand-made set only.

## 4. Results so far (read the cautions)

| Check | Result |
|---|---|
| Unit tests | Previous run reported 89 passed; current suite has not been re-run |
| Current generated JSON snapshot, 6 categories (email, calendar, cloud_drive, github_comments, github_issue, reference_json), with and without `random_key` | syntactic attacks caught **400 / 400**; benign false positives **0 / 82** |
| Current generated web_dom snapshot | attacks **20 / 20**, benign false positives **0 / 30** |
| ADI semantic attacks (`error`, `contextual`) | **0 caught, by design** (wording only; classifier stage) |
| AgentDojo replay, benign | 0 of 678 messages flagged (earlier run) |
| Current generated markdown snapshot (combined `md_flags` + text rules) | github_comments **71 / 71** syntactic attacks caught, **0 / 33** benign flagged; github_issue **130 / 130** syntactic attacks caught, but **6 / 30** benign cases flagged. This is a small, generator-derived snapshot, not a final benchmark result. |
| Pre-hop (22 hand-made cases) | attacks 10/10 caught, 0/12 benign flagged, flag on the right field 9/9 (one case has no field). Hand-made: sanity check only |
| Hard benign (33 hand-made harmless messages) | **9/33 flagged** (see section 5). The other 24 pass |
| github_issue JSON, larger earlier run | attacks 120/120, but **2 of 10 benign issues flagged**: inline code followed by a colon (`` `file.py`: ``) matches the backtick `kv_forgery` variant. The current generated snapshot is smaller and did not reproduce those false positives; investigate before claiming they are fixed. |

**Cautions - do not over-claim:**
1. The 400 come from 8 seeds and one attack generator; many cases are near-duplicates. Strong sign, not a final detection rate.
2. The DOM rules were fixed after seeing failures. Only the third pages of each layout are a true held-out check.
3. `md_flags` was designed from one example. Treat its numbers as a first measurement.
4. Pre-hop and hard-benign cases are hand-made by the author of the rules: a sanity check, not an independent benchmark.
5. No LLM agent ran: **no Attack Success Rate or utility** yet. The guard blocks nothing.
6. These cases were generated by the repo's generator; whether they equal the paper's frozen released set is not checked.
7. The `random_key` defense puts a sentence before the JSON. `adi_eval.py` strips it before parsing; this assumes
   the defense wrapper is added by the benchmark/pipeline, not by the tool.

## 5. Known limits (written down, not hidden)

- A forged element on a **real new line** (web page or markdown) looks like a real one. Needs provenance (tagging / graph).
- Wording-only attacks are not caught (by design).
- Benign text that contains a real key-value pair is flagged, because it looks identical to a forged field. Measured on
  `hard_benign.jsonl`: json_in_prose, json_code_fence, python_dict, curl_command, whole_body_is_json, code_block_braces,
  setting_in_prose, json_lines (8 of 33), plus `see [the "docs"], then retry`. Only provenance (tagging) can separate these.
- Unquoted `role: system` lines are not flagged.
- Attacks split across fields or messages; YAML (AgentDojo default) and other formats; lenient JSON the agent accepts but we reject.
- Plain-text tool output is `invalid_json` with S = 0; the gate must use the status.
- Pre-hop attacks have no real dataset yet.
- The benchmark seed data has an encoding quirk (arrows and stars appear as `â†’`, `â˜…`); the DOM rule accepts both forms.

## 6. Open work

1. Re-run the unit suite and record the current count; unit tests were not run for this status update.
2. Confirm `min_hits` / the verdict rule with the supervisor.
3. Extend independent benign data, increase seeds per category, and freeze a held-out JSON set. Investigate the markdown false positives and the earlier backtick false positive using held-out data.
4. Implement proposal 6.3 tagging, then the field trust-provenance graph, constrained classifier, risk scoring and review gate (sections 6.4–6.7). These do not belong to Stage 1 parsing and are not implemented here.
5. Integrate the detector with AgentDojo and run paired benign / attack agent tasks to measure ASR and utility; the current parser-only evaluation does not measure either.
6. Clarify the post-hop policy in the proposal: a post-hop response check can prevent untrusted content reaching the agent, but it cannot undo a side effect already performed by a tool. Side-effecting proposed calls need pre-hop authorization.
7. Add YAML or other formats only if they remain in the agreed project scope.

## 7. How to add a new check

1. Add the pattern to the right module (`_COUNTED` / `_WEAK` in `structural.py`, or the rules in `dom_flag.py` / `md_flags.py`).
2. Add a positive test (attack text) **and** a benign test.
3. Run `python -m pytest`, then `adi_eval.py` on the benign sets and confirm they still show 0 false positives.
4. Fix rules using only part of the data; keep some seeds untouched as a held-out check.
5. Avoid unbounded `\s*` or overlapping quantifiers (a speed test guards against regex slowdown).
