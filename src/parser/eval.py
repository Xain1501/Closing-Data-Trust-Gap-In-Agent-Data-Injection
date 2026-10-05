"""Run the parser over a benchmark file (list of cases with "input" and "test_type").

    python -m detector.eval_dataset path/to/dataset.jsonl    (package layout)
    python eval_dataset.py path/to/dataset.jsonl             (flat layout)
Accepts .json (a list) or .jsonl (one case per line).

Routing per case:
  input parses as JSON      -> parse() + structural_flags()      (main parser)
  input is NOT JSON (text)  -> dom_flags()                       (text/DOM check)
Reports how many benign cases were flagged (false positives) and how many
attack cases were flagged (caught).
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict

try:
    from .dom_flag import dom_flags
    from .models import Direction, ParseStatus, ToolTraffic
    from .parser import parse
    from .structural import structural_flags
except ImportError:
    from dom_flag import dom_flags
    from models import Direction, ParseStatus, ToolTraffic
    from parser import parse
    from structural import structural_flags


def check(text: str):
    res = parse(ToolTraffic(direction=Direction.POST_HOP, tool_name="dataset", payload=text))
    if res.status is ParseStatus.OK:
        return "json", res.status.value, structural_flags(res)
    return "text", res.status.value, dom_flags(text)


def load_cases(path: str) -> list[dict]:
    """Accepts a JSON list ([...]) or JSONL (one JSON object per line)."""
    with open(path, encoding="utf-8-sig") as f:
        text = f.read()
    if text.lstrip().startswith("["):
        return json.loads(text)
    cases = []
    for n, line in enumerate(text.splitlines(), start=1):
        if line.strip():
            try:
                cases.append(json.loads(line))
            except ValueError as e:
                sys.exit(f"line {n} is not valid JSON: {e}")
    return cases


def main(path: str) -> None:
    cases = load_cases(path)
    missing = [i for i, c in enumerate(cases) if "input" not in c or "test_type" not in c]
    if missing:
        sys.exit(f"{len(missing)} cases lack 'input' or 'test_type' (first at index {missing[0]})")
    print(f"loaded {len(cases)} cases from {path}")

    rows = defaultdict(lambda: {"n": 0, "flagged": 0})
    uniq: dict[tuple[str, str], bool] = {}
    routes, shown = defaultdict(int), 0
    for c in cases:
        route, status, rep = check(c["input"])
        flagged = rep.hit_count > 0
        routes[(route, status)] += 1
        for key in (("ALL", c["test_type"]), (str(c.get("defense_type")), c["test_type"])):
            rows[key]["n"] += 1
            rows[key]["flagged"] += flagged
        uniq[(c["test_type"], c["input"])] = flagged
        if flagged and shown < 3:
            shown += 1
            print(f"\nexample flag ({c['instance_id']}, S={rep.structural_score:.2f}):")
            for f in rep.findings[:2]:
                print(f"   {f.path}: {f.detail}")

    print("\nrouting (how each input was read):", dict(routes))
    print("\nper case               n   flagged")
    for (group, tt), v in sorted(rows.items()):
        print(f"  {group:12s} {tt:7s} {v['n']:4d}  {v['flagged']:4d}  ({100*v['flagged']/v['n']:5.1f}%)")
    for tt in ("benign", "attack"):
        u = [fl for (t, _), fl in uniq.items() if t == tt]
        print(f"unique {tt} inputs: {len(u)}, flagged {sum(u)}")
    fp = rows[("ALL", "benign")]["flagged"]
    print(f"\nfalse positives on benign cases: {fp}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: eval.py path/to/dataset.jsonl")
    main(sys.argv[1])