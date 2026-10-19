"""adi_eval.py (v2) - run the Stage-1 parser on ADI cases.

Put in src/parser/ next to eval.py. Reads BOTH case schemas:
  * llm-benchmark raw:  input / test_type / format / instance_id
  * pdi_build_cases:    payload / label / tool / delimiter / split / expected_*

Usage:
  python adi_eval.py ..\\..\\tests\\fixtures\\cases\\email_cases.jsonl --misses
  python adi_eval.py <file> --split dev        # tune rules only on this
  python adi_eval.py <file> --split heldout    # look rarely
  python adi_eval.py <file> --show <case id>   # print the findings of one case
  python adi_eval.py <file> --diff <attack id> # show exactly what text the attack injected

Routing:
  web_dom               -> dom_flags(text)
  everything else       -> parse() + structural_flags()
  JSON after a preamble -> the preamble line (random_key defense) is cut off first
  if it is not JSON     -> the text is wrapped as one JSON text value and scanned
                           with the same rules (route "text_fallback")
Attack scope:
  syntactic (in scope)  : insert_complete, override_pre, override_post, cross
  semantic  (by design out of scope: wording only): error, contextual
"""
import argparse
import hashlib
import json
import re
import uuid
from collections import defaultdict

try:  # package layout
    from .models import StructuralReport, ToolTraffic
    from .parser import parse
    from .structural import structural_flags
    from .md_flags import md_flags
    try:
        from .dom_flags import dom_flags
    except ImportError:
        from .dom_flag import dom_flags
except ImportError:  # loose files
    from models import StructuralReport, ToolTraffic
    from parser import parse
    from structural import structural_flags
    from md_flags import md_flags
    try:
        from dom_flags import dom_flags
    except ImportError:
        from dom_flag import dom_flags

SYNTACTIC = {"insert_complete", "override_pre", "override_post", "cross"}
SEMANTIC = {"error", "contextual"}
_LOOKS_MD = re.compile(r"^\s*(?:\d+\.\s+)?-\s+\*\*[^*\n]+\*\*:", re.M)


def load(path):
    with open(path, encoding="utf-8") as f:
        text = f.read().strip()
    if text.startswith("["):
        return json.loads(text)
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def norm(case):
    """Map either schema to one common shape."""
    cid = case.get("id") or case.get("instance_id")
    m = re.match(r"(s\d+)", cid or "")
    params = case.get("attack_params") or {}
    atk = case.get("attack_type")
    return {
        "id": cid,
        "text": case.get("payload", case.get("input")),
        "label": case.get("label") or case.get("test_type"),
        "category": case.get("category"),
        "format": case.get("format"),
        "attack_type": atk or "-",
        "scope": ("syntactic" if atk in SYNTACTIC else
                  "semantic" if atk in SEMANTIC else "-"),
        "delimiter": case.get("delimiter") or "-",
        "escape_level": params.get("escape_level") or "-",
        "tricky": case.get("tricky") or "-",
        "defense": case.get("defense_type") or "-",
        "tool": case.get("tool") or case.get("category") or "tool",
        "direction": case.get("direction") or "post_hop",
        "expected_status": case.get("expected_status"),
        "expected_untrusted": case.get("expected_untrusted") or [],
        "split": case.get("split"),
        "seed": case.get("seed_file") or (m.group(1) if m else cid),
    }


def side(c):
    """dev or heldout. Uses the file's own split if present."""
    if c["split"] in ("train", "dev"):
        return "dev"
    if c["split"] in ("test", "heldout"):
        return "heldout"
    h = int(hashlib.sha256(str(c["seed"]).encode()).hexdigest(), 16)
    return "heldout" if h % 5 == 0 else "dev"


def strip_preamble(text):
    """The random_key defense puts a sentence before the JSON.
    Return the JSON part (as text), or None if there is none."""
    tried = 0
    for m in re.finditer(r"\n(?=[{\[])", text):
        cand = text[m.end():]
        try:
            json.loads(cand)
            return cand
        except ValueError:
            tried += 1
            if tried >= 3:
                break
    return None


def _md_combined(c, text):
    """markdown = record-consistency checks (md_flags) + the JSON text rules run over the whole text
    (catches a fake object dumped into a markdown field, e.g. a Python-dict style fake issue)."""
    a = md_flags(text)
    wrapped = parse(ToolTraffic(direction=c["direction"], tool_name=c["tool"],
                                payload=json.dumps({"text": text}),
                                internal_id=uuid.uuid5(uuid.NAMESPACE_URL, str(c["id"]))))
    b = structural_flags(wrapped)
    findings = list(a.findings) + list(b.findings)
    bounds = max(1, a.boundary_count + b.boundary_count)
    return StructuralReport(findings=findings, uncounted_findings=[], hit_count=len(findings),
                            boundary_count=bounds, structural_score=min(1.0, len(findings) / bounds))


def run(c):
    """Returns (report, parse_status, route)."""
    text = c["text"]
    if c["category"] == "web_dom" or c["format"] == "web_dom":
        return dom_flags(text), "text", "dom"
    if c["format"] == "markdown" and isinstance(text, str):
        return _md_combined(c, text), "text", "markdown"

    def traffic(payload):
        return ToolTraffic(direction=c["direction"], tool_name=c["tool"],
                           payload=payload,
                           internal_id=uuid.uuid5(uuid.NAMESPACE_URL, str(c["id"])))

    res = parse(traffic(text))
    status = getattr(res.status, "value", str(res.status))
    if status != "ok" and isinstance(text, str):
        inner = strip_preamble(text)
        if inner is not None:
            res2 = parse(traffic(inner))
            st2 = getattr(res2.status, "value", str(res2.status))
            return structural_flags(res2), st2, "json_after_preamble"
        if _LOOKS_MD.search(text):
            return _md_combined(c, text), status, "markdown"
        wrapped = parse(traffic(json.dumps({"text": text})))
        return structural_flags(wrapped), status, "text_fallback"
    return structural_flags(res), status, "json"


def localised(rep, keys):
    """True if a counted finding sits on one of the expected untrusted fields."""
    if not keys:
        return None
    for f in getattr(rep, "findings", []):
        tokens = re.split(r"[.\[\]#]", f.path)
        if any(t == k or t.startswith(k + "_") for t in tokens for k in keys):
            return True
    return False


def table(title, rows):
    print(f"--- {title} ---")
    print(f"{'':20}{'attacks':>8}{'caught':>8}{'at-field':>9}{'benign':>8}{'false+':>8}")
    for k, (a, ac, al, b, bf) in sorted(rows.items(), key=lambda kv: str(kv[0])):
        print(f"{str(k):20}{a:8}{ac:8}{al:9}{b:8}{bf:8}")
    print()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--split", choices=["all", "dev", "heldout"], default="all")
    ap.add_argument("--misses", action="store_true")
    ap.add_argument("--show", metavar="ID")
    ap.add_argument("--diff", metavar="ID", help="show the text an attack injected (vs its benign twin)")
    args = ap.parse_args()

    cases = [norm(c) for c in load(args.path)]
    if args.split != "all":
        cases = [c for c in cases if side(c) == args.split]

    if args.show:
        c = next(x for x in cases if x["id"] == args.show)
        rep, status, route = run(c)
        print(f"{c['id']} | status={status} route={route} hits={rep.hit_count} S={rep.structural_score:.2f}")
        for f in rep.findings:
            print(f"  {f.kind} at {f.path}: {f.detail}")
        print("--- raw input (first 3000 chars) ---")
        print(str(c["text"])[:3000].encode("ascii", "backslashreplace").decode())
        return

    if args.diff:
        import difflib
        a = next(x for x in cases if x["id"] == args.diff)
        twin = re.sub(r"_(?:ins|ove|err|con)_v\d+", "_benign", a["id"])
        b = next((x for x in cases if x["id"] == twin), None)
        if b is None:
            print("no matching benign case found:", twin)
            return
        ta, tb = str(a["text"]), str(b["text"])
        sm = difflib.SequenceMatcher(None, tb, ta, autojunk=False)
        print(f"attack={a['id']}  benign twin={b['id']}\nchanged parts (benign -> attack):")
        for tag, i1, i2, j1, j2 in sm.get_opcodes():
            if tag != "equal":
                out = f"  [{tag}] {tb[i1:i2][:300]!r} -> {ta[j1:j2][:900]!r}"
                print(out.encode("ascii", "backslashreplace").decode())
        return

    print(f"{len(cases)} cases (split={args.split})\n")
    keys = ["scope", "attack_type", "category", "delimiter", "defense", "escape_level", "route", "tricky"]
    stats = {k: defaultdict(lambda: [0, 0, 0, 0, 0]) for k in keys}
    routes, bad_status, misses, fps = defaultdict(int), [], [], []
    tot = defaultdict(lambda: [0, 0])  # (route, scope) -> [attacks, caught]
    ben = defaultdict(lambda: [0, 0])  # route -> [benign, false+]

    for c in cases:
        rep, status, route = run(c)
        c["route"] = route
        flagged = rep.hit_count > 0
        routes[(route, status)] += 1
        if c["expected_status"] and status != c["expected_status"]:
            bad_status.append((c["id"], c["expected_status"], status))
        is_attack = c["label"] == "attack"
        loc = bool(localised(rep, c["expected_untrusted"])) if flagged else False
        for k in keys:
            s = stats[k][c[k]]
            if is_attack:
                s[0] += 1; s[1] += flagged; s[2] += loc
            else:
                s[3] += 1; s[4] += flagged
        if is_attack:
            tot[(route, c["scope"])][0] += 1; tot[(route, c["scope"])][1] += flagged
            if not flagged:
                misses.append(f"{c['id']}  [{c['attack_type']}, {c['delimiter']}, {route}, {status}]")
        else:
            ben[route][0] += 1; ben[route][1] += flagged
            if flagged:
                fps.append(c["id"])

    print("how inputs were read (route, parse status):", dict(routes), "\n")
    for k in keys:
        if len(stats[k]) > 1 or "-" not in stats[k]:
            table(f"by {k}", stats[k])

    print("=== HEADLINE (per route) ===")
    for r in sorted(set(ben) | {k[0] for k in tot}):
        sy, se, b = tot[(r, "syntactic")], tot[(r, "semantic")], ben[r]
        print(f"[{r}] syntactic caught {sy[1]}/{sy[0]} | semantic (out of scope) caught {se[1]}/{se[0]} | benign false+ {b[1]}/{b[0]}")
        if b[0] and b[1] / b[0] > 0.2:
            print(f"      WARNING: [{r}] flags {b[1]}/{b[0]} benign cases, so its catch numbers mean little")
    if bad_status:
        print(f"\nstatus differs from expected_status in {len(bad_status)} cases, e.g. {bad_status[:3]}")
    if args.misses:
        print("\nMISSED ATTACKS:")
        for m_ in misses:
            print("  ", m_)
        print("FALSE POSITIVES:", fps or "none")


if __name__ == "__main__":
    main()