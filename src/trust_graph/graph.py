"""Convert tagged fields and cross-call lineage into graph snapshots."""
from __future__ import annotations

import re
from collections.abc import Sequence
from parser.models import Finding, TaggedField
from trust_graph.tagging import FieldTag
from classifier.wl_svm import GraphSnapshot

Tagged = FieldTag | TaggedField


def _label(field: Tagged) -> str:
    provenance = getattr(field, "provenance", None)
    role = getattr(field, "role", None)
    lineage = getattr(field, "lineage_status", None)
    direction = getattr(field, "direction", "unknown")
    return ":".join(
        part
        for part in (
            field.trust.value,
            getattr(provenance, "value", "legacy"),
            getattr(role, "value", "other"),
            getattr(lineage, "value", "unlinked"),
            field.value_type,
            f"depth={field.depth}",
            f"direction={getattr(direction, 'value', direction)}",
            f"forgery={_forgery_value(field)}",
            f"mimicry={str(bool(getattr(field, 'has_mimicry', False))).lower()}",
            f"anomaly={str(bool(getattr(field, 'has_anomaly', False))).lower()}",
        )
    )


_REAL_FIELD = re.compile(r"real field (\S+)")


def _forgery_value(field: object) -> str:
    """'true' (forgery on this node), 'leaf' (inside a forged leaf), or 'false'."""
    if getattr(field, "has_forgery", False):
        return "true"
    return "leaf" if getattr(field, "leaf_forged", False) else "false"


def build_trust_graph(
    fields: Sequence[Tagged],
    findings: Sequence[Finding] = (),
    mentions: Sequence[tuple[str, str]] = (),
) -> GraphSnapshot:
    """Build one field graph, including structural finding nodes."""
    return _build_graph((fields,), trace=False, finding_groups=(findings,), mentions=mentions)


def build_trace_graph(
    field_groups: Sequence[Sequence[Tagged]],
    findings: Sequence[Sequence[Finding]] = (),
    mentions: Sequence[tuple[str, str]] = (),
) -> GraphSnapshot:
    """Build a trace graph with one namespace per interception and real lineage edges.

    ``mentions`` are (untrusted leaf tag id, mentioned field tag id) pairs from run
    state. They and mimicry findings become typed relation nodes (``rel:mentions``,
    ``rel:mimics``) between the two fields, since graph edges carry no labels."""
    if findings and len(findings) != len(field_groups):
        raise ValueError("findings must have one group per field group")
    finding_groups = tuple(findings) if findings else tuple(() for _ in field_groups)
    return _build_graph(field_groups, trace=True, finding_groups=finding_groups, mentions=mentions)


def _build_graph(
    field_groups: Sequence[Sequence[Tagged]],
    *,
    trace: bool,
    finding_groups: Sequence[Sequence[Finding]],
    mentions: Sequence[tuple[str, str]] = (),
) -> GraphSnapshot:
    if not any(field_groups):
        raise ValueError("at least one tagged field is required to build a graph")

    node_labels: dict[str, str] = {}
    edges: list[tuple[str, str]] = []
    tag_nodes: dict[str, str] = {}
    group_nodes: list[dict[str, str]] = []
    for group_index, fields in enumerate(field_groups):
        prefix = f"event:{group_index}:" if trace else ""
        path_nodes = {field.path: f"{prefix}{field.path}" for field in fields}
        group_nodes.append(path_nodes)
        for field in fields:
            node_id = path_nodes[field.path]
            node_labels[node_id] = _label(field)
            tag_id = getattr(field, "tag_id", None)
            if isinstance(tag_id, str):
                tag_nodes[tag_id] = node_id
            if field.parent_path in path_nodes:
                edges.append((path_nodes[field.parent_path], node_id))

    source_aliases: dict[str, str] = {}
    for group_index, fields in enumerate(field_groups):
        path_nodes = group_nodes[group_index]
        prefix = f"event:{group_index}:" if trace else ""
        for field in fields:
            target = path_nodes[field.path]
            for evidence in getattr(field, "derived_from", ()):
                source_tag_id = evidence.source_tag_id
                if not source_tag_id:
                    continue
                source = tag_nodes.get(source_tag_id)
                if source is None:
                    source = source_aliases.setdefault(
                        source_tag_id, f"source:{len(source_aliases)}"
                    )
                    source_provenance = getattr(evidence, "source_provenance", "EXTERNAL")
                    source_provenance = getattr(source_provenance, "value", source_provenance)
                    source_forgery = ("true" if getattr(evidence, "source_has_forgery", False)
                                      else "leaf" if getattr(evidence, "source_leaf_forged", False)
                                      else "false")
                    node_labels.setdefault(
                        source,
                        f"source:{source_provenance}:string:forgery={source_forgery}",
                    )
                edges.append((source, target))

        for index, finding in enumerate(finding_groups[group_index]):
            finding_id = f"{prefix}finding:{index}:{finding.path}:{finding.kind}"
            node_labels[finding_id] = f"finding:{finding.kind}"
            target_path = finding.path.split("#", 1)[0]
            target = path_nodes.get(target_path)
            if target is None:
                # A schema/parser finding can point below a true field. Attach it
                # to the nearest true ancestor so the finding remains in-graph.
                candidates = [
                    (path, node) for path, node in path_nodes.items()
                    if target_path == path
                    or target_path.startswith(path + ".")
                    or target_path.startswith(path + "[")
                ]
                target = max(candidates, key=lambda item: len(item[0]))[1] if candidates else None
            if target is not None:
                edges.append((target, finding_id))
            # Mimicry: link the claim to the real field it copies.
            if finding.kind == "mimicry" and target is not None:
                ref = getattr(finding, "ref_path", None)
                if ref is None:                       # older findings: read it from the text
                    match = _REAL_FIELD.search(finding.detail or "")
                    ref = match.group(1) if match else None
                real_node = path_nodes.get(ref) if ref else None
                if real_node is not None:
                    rel = f"{prefix}rel:mimics:{finding.path}"
                    node_labels[rel] = "rel:mimics"
                    edges.append((target, rel))
                    edges.append((rel, real_node))

    for index, (leaf_tag, other_tag) in enumerate(mentions):
        leaf_node, other_node = tag_nodes.get(leaf_tag), tag_nodes.get(other_tag)
        if leaf_node is None or other_node is None:
            continue
        rel = f"rel:mentions:{index}"
        node_labels[rel] = "rel:mentions"
        edges.append((leaf_node, rel))
        edges.append((rel, other_node))

    return GraphSnapshot(node_labels=node_labels, edges=tuple(dict.fromkeys(edges)))
