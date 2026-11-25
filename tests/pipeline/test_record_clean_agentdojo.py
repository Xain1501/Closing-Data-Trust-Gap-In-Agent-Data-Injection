from scripts.record_clean_agentdojo import _clean_trace_row


def test_natural_clean_trace_is_unpaired_and_has_a_stable_call_hash():
    sequence = [{"tool_name": "read_file", "args": {"path": "report.txt"}}]

    row = _clean_trace_row(
        "workspace",
        "user_task_0",
        benchmark_version="v1.2.2",
        model_name="openai/gpt-oss-120b",
        run_id="clean-run-1",
        user_prompt="Read the report",
        events=[],
        sequence=sequence,
    )

    assert row["label"] == "benign"
    assert row["label_basis"] == "no_injection_natural_model_run"
    assert row["collection_mode"] == "natural_clean_agent_run"
    assert row["pipeline_name"] == "baseline_openai_gpt-oss-120b"
    assert row["task_group_id"] == "agentdojo:workspace:user_task_0"
    assert len(row["call_sequence_sha256"]) == 64
    assert "matched_pair_id" not in row
