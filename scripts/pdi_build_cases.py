#probablistic delimeter injection custom build 
#!/usr/bin/env python3
"""Build detector test cases from llm-benchmark generated instances.

Scope of this first version: category "email", UNDEFENDED instances only
(instances with a defense_type such as random_key are skipped and counted).

Input : the JSON array written by `dib generate` / `dib run`
        (out/generated/instances_*.jsonl -- NOTE: despite the .jsonl name it is
        ONE JSON array, not one object per line).
Output: two true-JSONL files (one object per line, UTF-8):
  <prefix>_cases.jsonl       what the detector/parser team uses
  <prefix>_answer_key.jsonl  benchmark answers (groundtruth/targeted output),
                             kept SEPARATE so they never reach the detector;
                             only for end-to-end reports (ASR / utility).

Usage (from the repo root):
  python scripts/build_cases.py llm-benchmark/out/generated/email_study.jsonl
  python scripts/build_cases.py INSTANCES.json --variants curly_double
  python scripts/build_cases.py INSTANCES.json --variants curly_double --emit-instances llm-benchmark/out/generated/email_cases_instances.json

Read the results back with load_cases() below (always UTF-8).
"""
import argparse
import json
import sys
from pathlib import Path

# Extra delimiter variants made by us (NOT produced by llm-benchmark, which only
# has double/single quotes). Each maps a name -> (character to replace, replacement).
# UNVERIFIED against the ADI paper: confirm what counts as a probabilistic
# delimiter before using these in reports.
DELIMITER_VARIANTS = {
    "curly_double": ('"', "\u201d"),
}

# Delimiters present in llm-benchmark's own generator (attacks.yaml quote_style).
NATIVE_DELIMITERS = {"double": "double_quote", "single": "single_quote"}


def load_cases(path):
    """Load a *_cases.jsonl file: one JSON object per line, UTF-8."""
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def _no_duplicate_pairs(pairs):
    keys = [k for k, _ in pairs]
    dups = {k for k in keys if keys.count(k) > 1}
    if dups:
        raise ValueError("duplicate keys: " + ", ".join(sorted(dups)))
    return dict(pairs)


def expected_status(payload):
    """Compute (never assume) how a strict parser should see this payload."""
    try:
        json.loads(payload, object_pairs_hook=_no_duplicate_pairs)
        return "ok"
    except ValueError as e:
        return "duplicate_keys" if str(e).startswith("duplicate keys") else "invalid_json"


def split_for(delimiter):
    """Fixed rule, assigned here and never changed: native quotes (and benign
    twins) train; our extra delimiter variants are frozen for the final test."""
    return "test" if delimiter in DELIMITER_VARIANTS else "train"


def tool_name(tool_info):
    # llm-benchmark stores e.g. "gmail.users.messages.get(id='...')" as a string
    return str(tool_info).split("(")[0] if tool_info else None


def make_case(inst, payload, delimiter, untrusted, case_id):
    return {
        "id": case_id,
        "source": "llm-benchmark",
        "category": inst["category"],
        "suite": None,
        "tool": tool_name(inst.get("tool_info")),
        "direction": "post_hop",
        "payload": payload,  # RAW string, exactly as the tool returned it
        "label": inst["test_type"],
        "attack_type": inst.get("attack_type"),
        "delimiter": delimiter,
        "consistency": None,  # not derivable from llm-benchmark output
        "expected_status": expected_status(payload),
        "expected_untrusted": [untrusted] if untrusted else [],
        "expected_target": [inst["target_field"]],
        "split": split_for(delimiter),
    }


def make_key(inst, case_id):
    return {
        "id": case_id,
        "task_prompt": inst["task_prompt"],
        "target_field": inst["target_field"],
        "groundtruth_output": inst["groundtruth_output"],
        "targeted_output": inst["targeted_output"],
        "comparison_method": inst["comparison_method"],
    }


def build(instances, variants):
    cases, keys, inst_out = [], [], []
    skipped = {"defended": 0, "other_category": 0}

    # untrusted field per seed, read from the attacks (benign twins share it)
    untrusted_by_seed = {}
    for i in instances:
        field = (i.get("attack_params") or {}).get("injection_field")
        if field:
            untrusted_by_seed[i["seed_file"]] = field

    benign_body = {}  # seed_file -> benign body text, to find the injected span
    for i in instances:
        if i["test_type"] == "benign" and not i.get("defense_type"):
            try:
                benign_body[i["seed_file"]] = json.loads(i["input"]).get("body")
            except ValueError:
                pass

    for i in instances:
        if i["category"] != "email":
            skipped["other_category"] += 1
            continue
        if i.get("defense_type"):
            skipped["defended"] += 1
            continue

        untrusted = untrusted_by_seed.get(i["seed_file"])
        params = i.get("attack_params") or {}
        delimiter = NATIVE_DELIMITERS.get(params.get("quote_style")) if i["test_type"] == "attack" else None
        cases.append(make_case(i, i["input"], delimiter, untrusted, i["instance_id"]))
        keys.append(make_key(i, i["instance_id"]))
        inst_out.append(i)

        # extra delimiter variants: only for double-quote attacks whose body is
        # "benign body + injected span" (so the injected span can be located)
        if i["test_type"] == "attack" and delimiter == "double_quote" and untrusted:
            obj = json.loads(i["input"])
            base = benign_body.get(i["seed_file"])
            body = obj.get(untrusted)
            if base and isinstance(body, str) and body.startswith(base):
                span = body[len(base):]
                for name in variants:
                    old, new = DELIMITER_VARIANTS[name]
                    obj2 = dict(obj)
                    obj2[untrusted] = base + span.replace(old, new)
                    payload = json.dumps(obj2, ensure_ascii=False)
                    vid = f"{i['instance_id']}__{name}"
                    cases.append(make_case(i, payload, name, untrusted, vid))
                    keys.append(make_key(i, vid))
                    j = dict(i)  # same fields as the benchmark Instance, new input
                    j["input"], j["instance_id"] = payload, vid
                    inst_out.append(j)
    return cases, keys, skipped, inst_out


def validate(cases, keys):
    """Return a list of problems (empty list = all checks passed)."""
    problems = []
    key_by_id = {k["id"]: k for k in keys}
    for c in cases:
        cid = c["id"]
        try:
            parsed = json.loads(c["payload"])
            parse_ok = True
        except ValueError:
            parsed, parse_ok = None, False
        # 1. status vs actual parse
        if c["expected_status"] == "ok" and not parse_ok:
            problems.append(f"{cid}: expected_status=ok but json.loads failed")
        if c["expected_status"] == "invalid_json" and parse_ok:
            problems.append(f"{cid}: expected_status=invalid_json but it parses")
        if c["label"] != "attack" or not isinstance(parsed, dict):
            continue
        k = key_by_id[cid]
        field = c["expected_untrusted"][0] if c["expected_untrusted"] else None
        target = c["expected_target"][0]
        # 2. injected text must lie in the untrusted field, not in the target
        if field not in parsed:
            problems.append(f"{cid}: untrusted field {field!r} missing from payload")
            continue
        if k["targeted_output"] not in str(parsed[field]):
            problems.append(f"{cid}: attacker text not found inside {field!r}")
        if str(parsed.get(target)) == k["targeted_output"]:
            problems.append(f"{cid}: target field {target!r} was really overwritten")
        # 3. delimiter under test must actually be in the payload
        if c["delimiter"] in DELIMITER_VARIANTS and DELIMITER_VARIANTS[c["delimiter"]][1] not in c["payload"]:
            problems.append(f"{cid}: delimiter {c['delimiter']} not present in payload")
        # 4. benign twin must exist (same seed/task prefix)
        if c["id"].split("_ins_")[0].split("_ove_")[0] + "_benign" not in {x["id"] for x in cases}:
            problems.append(f"{cid}: no benign twin found")
    return problems


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("instances", help="JSON array from `dib generate`")
    ap.add_argument("--out-dir", default="tests/fixtures/cases")
    ap.add_argument("--prefix", default="email")
    ap.add_argument("--variants", nargs="*", default=[], choices=sorted(DELIMITER_VARIANTS),
                    help="extra delimiter variants to create (default: none)")
    ap.add_argument("--emit-instances", metavar="PATH",
                    help="also write a benchmark-format instances file (JSON array) that "
                         "`dib evaluate` can run on a model, incl. the variants")
    a = ap.parse_args()

    with open(a.instances, encoding="utf-8") as f:
        instances = json.load(f)
    cases, keys, skipped, inst_out = build(instances, a.variants)
    problems = validate(cases, keys)

    out = Path(a.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    for name, rows in ((f"{a.prefix}_cases.jsonl", cases), (f"{a.prefix}_answer_key.jsonl", keys)):
        with open(out / name, "w", encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")

    if a.emit_instances:
        Path(a.emit_instances).parent.mkdir(parents=True, exist_ok=True)
        with open(a.emit_instances, "w", encoding="utf-8") as f:
            json.dump(inst_out, f, ensure_ascii=False, indent=2)
        print(f"wrote {len(inst_out)} benchmark-format instances -> {a.emit_instances}")

    n_att = sum(c["label"] == "attack" for c in cases)
    print(f"read {len(instances)} instances; skipped {skipped}")
    print(f"wrote {len(cases)} cases ({n_att} attack, {len(cases) - n_att} benign) -> {out}")
    print(f"splits: " + ", ".join(f"{s}={sum(c['split'] == s for c in cases)}" for s in ("train", "test")))
    print("validation:", "ALL CHECKS PASSED" if not problems else f"{len(problems)} PROBLEM(S)")
    for p in problems:
        print("  -", p)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())