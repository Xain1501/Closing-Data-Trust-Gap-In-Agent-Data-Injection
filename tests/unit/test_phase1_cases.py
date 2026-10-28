"""Phase-1 dataset checks + Stage-1 parser conformance on all 100 cases.

    python -m pytest tests/unit/test_phase1_cases.py -q        (from the repo root)

Integrity tests guard the dataset itself (counts, ids, labels, schema).
Conformance tests check the parser against parser_expect (its DESIGN), so a
change to parser.py / structural.py that alters behaviour on any case fails here.
Detection metrics are reported by scripts/run_phase1_cases.py, not asserted.
"""
import json
import sys
from collections import Counter
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from run_phase1_cases import evaluate, load_cases, materialize  # noqa: E402

CASES = load_cases()
REQUIRED = {"case_id", "set", "family", "source", "direction", "tool_name", "payload", "label",
            "attack_type", "expected_status", "expected_untrusted_paths", "parser_expect", "tags"}


def test_exactly_100_cases_40_40_20():
    assert len(CASES) == 100
    assert Counter(c["set"] for c in CASES) == {"benign": 40, "malicious": 40, "edge": 20}


def test_ids_unique_and_payloads_not_duplicated():
    assert len({c["case_id"] for c in CASES}) == 100
    payloads = [json.dumps(c["payload"]) for c in CASES]
    assert len(set(payloads)) == len(payloads)


@pytest.mark.parametrize("c", CASES, ids=lambda c: c["case_id"])
def test_case_schema(c):
    assert REQUIRED <= c.keys()
    assert c["direction"] in {"pre_hop", "post_hop"}
    assert c["label"] in {"benign", "attack"}
    assert (c["label"] == "attack") == bool(c["attack_type"])
    assert c["set"] != "benign" or c["label"] == "benign"
    assert c["set"] != "malicious" or c["label"] == "attack"
    assert c["parser_expect"]["basis"] in {"spec", "known_limit", "out_of_scope_stage1"}


@pytest.mark.parametrize("c", [c for c in CASES if c["set"] == "malicious" and c["direction"] == "post_hop"],
                         ids=lambda c: c["case_id"])
def test_planted_attack_really_in_untrusted_field(c):
    assert c["expected_untrusted_paths"], "planted attack must be located in at least one field"


@pytest.mark.parametrize("c", CASES, ids=lambda c: c["case_id"])
def test_parser_conforms_to_design(c):
    r = evaluate(c)
    assert r["status"] == c["expected_status"]
    assert r["flagged"] == c["parser_expect"]["flagged"], c["parser_expect"]["rationale"]


def test_oversize_is_generated_not_stored():
    big = [c for c in CASES if isinstance(c["payload"], dict)]
    assert big and all(len(materialize(c["payload"])) > 1_000_000 for c in big)
