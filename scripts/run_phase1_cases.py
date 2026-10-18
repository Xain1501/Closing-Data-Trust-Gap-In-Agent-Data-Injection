#!/usr/bin/env python3
"""Run the 100 Phase-1 cases through the CURRENT Stage-1 parser and report.

    python scripts/run_phase1_cases.py                  (from the repo root)
    python scripts/run_phase1_cases.py --show-mismatches

Two separate questions are answered:
  1. CONFORMANCE  - does the parser do what it is designed to do?
                    actual status == expected_status, and flagged == parser_expect.flagged
  2. DETECTION    - against ground truth (positive class = label "attack"),
                    predicted positive = structural hit_count > 0
                    TP/FP/TN/FN, TPR (= recall), FPR, per set and per family.
Detection numbers here measure Stage 1 ALONE on this fixed set. They are not an
Attack Success Rate: no agent / LLM runs and nothing is blocked.

Per-case raw results go to experiments/results/phase1_run.json (git-ignored).
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import defaultdict
from importlib.metadata import version
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src" / "parser"))

from models import Direction, ToolTraffic  # noqa: E402
from parser import parse  # noqa: E402
from structural import structural_flags  # noqa: E402

CASES = ROOT / "tests" / "fixtures" / "phase1" / "phase1_cases.jsonl"
RESULTS = ROOT / "experiments" / "results" / "phase1_run.json"


def materialize(payload):
    """Expand generated payloads (kept small in the fixture file)."""
    if isinstance(payload, dict) and payload.get("$generate") == "oversize_json":
        return '{"body": "' + "a" * payload["bytes"] + '"}'
    return payload


def load_cases(path: Path = CASES) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def evaluate(c: dict) -> dict:
    traffic = ToolTraffic(direction=Direction(c["direction"]), tool_name=c["tool_name"],
                          payload=materialize(c["payload"]))
    res = parse(traffic)
    rep = structural_flags(res)
    return {
        "case_id": c["case_id"], "set": c["set"], "family": c["family"], "label": c["label"],
        "attack_type": c["attack_type"],
        "status": res.status.value, "expected_status": c["expected_status"],
        "hit_count": rep.hit_count, "S": round(rep.structural_score, 4),
        "flagged": rep.hit_count > 0, "expected_flagged": c["parser_expect"]["flagged"],
        "basis": c["parser_expect"]["basis"],
        "flagged_paths": sorted({f.path for f in rep.findings}),
        "expected_untrusted_paths": c["expected_untrusted_paths"],
        "findings": [f"{f.kind}:{f.detail.split(':')[0]}" for f in rep.findings],
        "weak": [f.detail.split(":")[0] for f in rep.uncounted_findings],
    }


def confusion(rows: list[dict]) -> dict:
    tp = sum(r["label"] == "attack" and r["flagged"] for r in rows)
    fn = sum(r["label"] == "attack" and not r["flagged"] for r in rows)
    fp = sum(r["label"] == "benign" and r["flagged"] for r in rows)
    tn = sum(r["label"] == "benign" and not r["flagged"] for r in rows)
    rate = lambda a, b: None if a + b == 0 else round(a / (a + b), 3)  # noqa: E731
    return {"n": len(rows), "TP": tp, "FN": fn, "FP": fp, "TN": tn, "TPR": rate(tp, fn), "FPR": rate(fp, tn)}


def fmt(m: dict) -> str:
    pct = lambda x: "   -  " if x is None else f"{100 * x:5.1f}%"  # noqa: E731
    return (f"n={m['n']:3d}  TP={m['TP']:3d} FN={m['FN']:3d} FP={m['FP']:3d} TN={m['TN']:3d}  "
            f"TPR={pct(m['TPR'])}  FPR={pct(m['FPR'])}")


def git_rev() -> str:
    try:
        rev = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
        dirty = subprocess.run(["git", "status", "--porcelain", "src/parser"], cwd=ROOT,
                               capture_output=True, text=True).stdout.strip()
        return rev + ("+dirty-parser" if dirty else "")
    except OSError:
        return "unknown"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--show-mismatches", action="store_true", help="print details of every conformance mismatch")
    a = ap.parse_args()

    cases = load_cases()
    manifest = json.loads((CASES.parent / "phase1_manifest.json").read_text(encoding="utf-8"))
    rows = [evaluate(c) for c in cases]

    status_bad = [r for r in rows if r["status"] != r["expected_status"]]
    flag_bad = [r for r in rows if r["flagged"] != r["expected_flagged"]]
    print(f"dataset {manifest['dataset_version']}  ({len(rows)} cases)   parser rev {git_rev()}")
    print(f"\n== 1. CONFORMANCE (parser vs its design) ==")
    print(f"status matches expected : {len(rows) - len(status_bad)}/{len(rows)}")
    print(f"flag matches expected   : {len(rows) - len(flag_bad)}/{len(rows)}")
    for r in status_bad + flag_bad:
        print(f"   MISMATCH {r['case_id']} {r['family']:24s} status={r['status']}(exp {r['expected_status']}) "
              f"flagged={r['flagged']}(exp {r['expected_flagged']}) {r['findings'][:3]}")

    print(f"\n== 2. DETECTION vs ground truth (positive = attack; predicted = hit_count > 0) ==")
    print(f"  {'ALL':34s} {fmt(confusion(rows))}")
    by_set, by_fam = defaultdict(list), defaultdict(list)
    for r in rows:
        by_set[r["set"]].append(r)
        by_fam[f"{r['set']}/{r['family']}"].append(r)
    for k in ("benign", "malicious", "edge"):
        print(f"  set {k:30s} {fmt(confusion(by_set[k]))}")
    print()
    for k in sorted(by_fam):
        print(f"  {k:34s} {fmt(confusion(by_fam[k]))}")
    in_scope = [r for r in rows if r["basis"] != "out_of_scope_stage1"]
    print(f"\n  {'excluding out_of_scope_stage1':34s} {fmt(confusion(in_scope))}")

    # localisation: for flagged attacks with known untrusted paths, did a finding point there?
    loc = [r for r in rows if r["label"] == "attack" and r["flagged"] and r["expected_untrusted_paths"]]
    hit = sum(any(p.split("#key")[0] in r["expected_untrusted_paths"] for p in r["flagged_paths"]) for r in loc)
    print(f"\n  localisation: {hit}/{len(loc)} flagged attacks had a finding on an expected untrusted path")

    if a.show_mismatches:
        for r in flag_bad:
            print(f"\n--- {r['case_id']} ---\n{json.dumps(r, indent=2, ensure_ascii=False)}")

    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    RESULTS.write_text(json.dumps({
        "dataset_version": manifest["dataset_version"], "parser_rev": git_rev(),
        "agentdojo_package": version("agentdojo"), "python": sys.version.split()[0],
        "summary": confusion(rows), "rows": rows}, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nper-case results -> {RESULTS.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
