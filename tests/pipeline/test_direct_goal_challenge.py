import json
import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

_SCRIPT_PATH = Path(__file__).resolve().parents[2] / "scripts" / "build_direct_goal_challenge.py"
_SPEC = importlib.util.spec_from_file_location("build_direct_goal_challenge", _SCRIPT_PATH)
challenge = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(challenge)


def _trace(*, prompt="Direct goal", calls=1, security=True, utility=True):
    return {
        "suite_name": "workspace",
        "user_task_id": "injection_task_0",
        "injection_task_id": None,
        "attack_type": None,
        "injections": {},
        "benchmark_version": "v1.2.2",
        "pipeline_name": "openai_gpt-oss-120b",
        "security": security,
        "utility": utility,
        "messages": [
            {"role": "user", "content": [{"type": "text", "content": prompt}]},
            {
                "role": "assistant",
                "tool_calls": [
                    {"function": "send_email", "args": {}, "id": f"call-{i}"}
                    for i in range(calls)
                ],
            },
        ],
    }


def test_build_challenge_requires_registered_goal_and_marks_direct_label(
    tmp_path, monkeypatch
):
    source_dir = tmp_path / "source"
    source = source_dir / "model" / "workspace" / "injection_task_0.json"
    source.parent.mkdir(parents=True)
    source.write_text(json.dumps(_trace(security=None, utility=None)), encoding="utf-8")
    output_dir = tmp_path / "output"
    suite = SimpleNamespace(
        injection_tasks={"injection_task_0": SimpleNamespace(GOAL="Direct goal")}
    )
    monkeypatch.setattr(challenge, "get_suite", lambda version, name: suite)
    monkeypatch.setattr(challenge, "load_tool_matrix", lambda: object())
    monkeypatch.setattr(
        challenge.graph_dataset,
        "_read_trace",
        lambda path, label, matrix: {
            "label": label,
            "attack_family": "direct_user_goal",
            "text_derived": True,
            "tool_calls": 1,
        },
    )

    manifest = challenge.build_challenge(source_dir, output_dir)
    row = json.loads((output_dir / "traces" / "openai_gpt-oss-120b" / "injection_task_0.json").read_text(encoding="utf-8"))

    assert manifest["counts"] == {"included": 1, "excluded": 0, "tool_calls": 1}
    assert row["label"] == "benign"
    assert row["label_basis"] == "no_injection_direct_user_goal_control"
    assert row["attack_success"] is None
    assert row["injection_condition"] == "absent"
    assert row["task_group_id"] == "agentdojo:workspace:direct_user_goal:injection_task_0"
    assert manifest["do_not_mix_into_primary_injection_dataset"] is True
    graph_row = json.loads((output_dir / "graphs.jsonl").read_text(encoding="utf-8"))
    assert graph_row["split"] == "test"


def test_build_challenge_rejects_prompt_not_matching_registered_goal(tmp_path, monkeypatch):
    source_dir = tmp_path / "source"
    source = source_dir / "bad.json"
    source_dir.mkdir()
    source.write_text(json.dumps(_trace(prompt="different prompt")), encoding="utf-8")
    monkeypatch.setattr(
        challenge, "get_suite",
        lambda version, name: SimpleNamespace(
            injection_tasks={"injection_task_0": SimpleNamespace(GOAL="Direct goal")}
        ),
    )

    with pytest.raises(ValueError, match="does not exactly match"):
        challenge.build_challenge(source_dir, tmp_path / "output")
