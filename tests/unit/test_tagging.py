from __future__ import annotations

from parser.models import Direction, ToolTraffic, Trust
from parser.parser import parse
from provenance import RunState, RunStateStore
from trust_graph.tagging import (
    FieldTag,
    LineageStatus,
    ProfileEntry,
    Provenance,
    Role,
    tag_fields,
)
from trust_graph.graph import build_trace_graph, build_trust_graph


def parsed(payload, direction=Direction.POST_HOP):
    return parse(ToolTraffic(direction=direction, tool_name="demo", payload=payload))


def tag_post(payload, state, profile=None, interception_id="post-1"):
    result = parsed(payload)
    return tag_fields(
        "post", "demo", result.fields, profile, state,
        interception_id=interception_id,
    )


def test_default_result_tags_keep_structure_system_and_leaves_external():
    state = RunState("run-1")
    tags = tag_post({"id": "evt-1", "count": 4, "details": {"body": "untrusted text"}}, state)
    by_path = {tag.path: tag for tag in tags}

    assert by_path["$"].provenance is Provenance.SYSTEM
    assert by_path["$.details"].provenance is Provenance.SYSTEM
    for path in ("$.id", "$.count", "$.details.body"):
        assert by_path[path].provenance is Provenance.EXTERNAL
        assert by_path[path].trust is Trust.UT
    assert len(state.values) == 2  # only string leaves are kept for value lineage


def test_approved_profile_can_mark_a_result_path_system():
    state = RunState("run-1")
    profile = ProfileEntry(
        "demo", result_fields={"$.id": Provenance.SYSTEM},
        result_default=Provenance.EXTERNAL, review_status="approved",
    )
    tags = tag_post({"id": "evt-1", "body": "mail text"}, state, profile)
    by_path = {tag.path: tag for tag in tags}
    assert by_path["$.id"].provenance is Provenance.SYSTEM
    assert by_path["$.id"].trust is Trust.T
    assert by_path["$.body"].provenance is Provenance.EXTERNAL


def test_graph_preserves_source_provenance_for_lineage_edges():
    state = RunState("run-1")
    profile = ProfileEntry(
        "demo", result_fields={"$.id": Provenance.SYSTEM},
        review_status="approved",
    )
    result_tags = tag_post({"id": "event-123"}, state, profile)
    args = parsed({"id": "event-123"}, Direction.PRE_HOP)
    argument_tags = tag_fields(
        "pre", "demo", args.fields, run_state=state, interception_id="pre-1",
    )

    graph = build_trace_graph([result_tags, argument_tags])
    source_node = "event:0:$.id"
    target_node = "event:1:$.id"
    assert graph.node_labels[source_node].startswith("T:SYSTEM")
    assert (source_node, target_node) in graph.edges
    assert all("forgery=false" in label for label in graph.node_labels.values())


def test_text_result_stays_one_external_leaf_even_if_its_text_looks_like_json():
    state = RunState("run-text")
    result = parsed('{"id": "fake", "body": "untrusted"}')
    tags = tag_fields(
        "post", "text_tool", result.fields, run_state=state,
        interception_id="post-text", result_format="text",
    )
    assert len(tags) == 1
    assert tags[0].path == "$"
    assert tags[0].provenance is Provenance.EXTERNAL
    assert tags[0].role is Role.OTHER


def test_argument_value_links_to_prior_external_result_and_keeps_authority_role():
    state = RunState("run-1", user_prompt="Send the invoice to the finance contact")
    result_tags = tag_post({"body": "Please pay alice@example.com"}, state, interception_id="post-1")
    args = parsed({"recipient": "alice@example.com"}, Direction.PRE_HOP)
    tags = tag_fields(
        "pre", "send_mail", args.fields, run_state=state,
        interception_id="pre-2", authority_arguments=("recipient",),
    )
    recipient = next(tag for tag in tags if tag.path == "$.recipient")

    assert result_tags[1].provenance is Provenance.EXTERNAL
    assert recipient.role is Role.AUTHORITY_ARG
    assert recipient.provenance is Provenance.DERIVED
    assert recipient.trust is Trust.UT
    assert recipient.lineage_status is LineageStatus.EXTERNAL_LINK
    assert recipient.derived_from[0].source_tag_id == result_tags[1].tag_id
    assert recipient.derived_from[0].match_type == "substring"


def test_simultaneous_tool_calls_cannot_link_to_each_others_results():
    state = RunState("run-1")
    result_tags = tag_fields(
        "post", "read_mail", parsed({"body": "Use account acct-1234"}).fields,
        run_state=state, interception_id="post-1", batch_id=1,
    )
    args = parsed({"account": "acct-1234"}, Direction.PRE_HOP).fields
    same_batch = tag_fields(
        "pre", "pay", args, run_state=state, interception_id="pre-sibling", batch_id=1,
    )
    next_batch = tag_fields(
        "pre", "pay", args, run_state=state, interception_id="pre-next", batch_id=2,
    )

    assert result_tags[1].provenance is Provenance.EXTERNAL
    assert same_batch[1].lineage_status is LineageStatus.UNLINKED
    assert next_batch[1].lineage_status is LineageStatus.EXTERNAL_LINK
    assert next_batch[1].derived_from[0].source_tag_id == result_tags[1].tag_id


def test_prompt_match_is_user_lineage_evidence():
    state = RunState("run-1", user_prompt="Send the report to alice@example.com")
    tags = tag_fields(
        "pre", "send_mail", parsed({"recipient": "alice@example.com"}, Direction.PRE_HOP).fields,
        run_state=state, interception_id="pre-1", authority_arguments=("recipient",),
    )
    recipient = next(tag for tag in tags if tag.path == "$.recipient")
    assert recipient.provenance is Provenance.USER
    assert recipient.trust is Trust.T
    assert recipient.lineage_status is LineageStatus.USER_MATCH


def test_email_match_requires_identifier_boundaries():
    state = RunState("run-1")
    tag_post({"body": "evil.bob@x.com and bob@x.com.evil.org"}, state)
    tags = tag_fields(
        "pre", "send_mail", parsed({"recipient": "bob@x.com"}, Direction.PRE_HOP).fields,
        run_state=state, interception_id="pre-1",
    )
    recipient = next(tag for tag in tags if tag.path == "$.recipient")
    assert recipient.lineage_status is LineageStatus.UNLINKED
    assert recipient.derived_from == ()


def test_short_values_do_not_create_links_and_run_state_caps_are_visible():
    state = RunState("run-1", max_values=1, max_chars=10, min_length=4)
    tag_post({"a": "short", "b": "another"}, state)
    assert len(state.values) == 1
    assert state.overflowed and state.dropped_values == 1
    assert state.dropped_chars == len("another")
    tags = tag_fields(
        "pre", "demo", parsed({"value": "abc"}, Direction.PRE_HOP).fields,
        run_state=state, interception_id="pre-2",
    )
    value = next(tag for tag in tags if tag.path == "$.value")
    assert value.lineage_status is LineageStatus.BELOW_MIN
    assert value.trust is Trust.UT


def test_store_reuses_and_clears_each_runs_private_values():
    store = RunStateStore()
    first = store.get_or_create("run-1", "prompt")
    assert store.get_or_create("run-1", "prompt") is first
    assert store.end_run("run-1") is True
    assert store.get("run-1") is None
    assert first.user_prompt is None and first.values == []


def test_new_field_tags_are_side_records_without_raw_values():
    state = RunState("run-1")
    tags = tag_post({"body": "private raw value"}, state)
    tag = next(tag for tag in tags if tag.path == "$.body")
    assert isinstance(tag, FieldTag)
    assert not hasattr(tag, "value")
    assert tag.interception_id == "post-1"
