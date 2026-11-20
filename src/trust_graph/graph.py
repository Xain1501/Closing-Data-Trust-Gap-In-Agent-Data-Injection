"""Convert tagged fields and cross-call lineage into graph snapshots."""
from __future__ import annotations

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
            f"forgery={str(bool(getattr(field, 'has_forgery', False))).lower()}",
        )
    )


def build_trust_graph(
    fields: Sequence[Tagged],
    findings: Sequence[Finding] = (),
) -> GraphSnapshot:
    """Build one field graph, including structural finding nodes."""
    return _build_graph((fields,), trace=False, finding_groups=(findings,))


def build_trace_graph(
    field_groups: Sequence[Sequence[Tagged]],
    findings: Sequence[Sequence[Finding]] = (),
) -> GraphSnapshot:
    """Build a trace graph with one namespace per interception and real lineage edges."""
    if findings and len(findings) != len(field_groups):
        raise ValueError("findings must have one group per field group")
    finding_groups = tuple(findings) if findings else tuple(() for _ in field_groups)
    return _build_graph(field_groups, trace=True, finding_groups=finding_groups)


def _build_graph(
    field_groups: Sequence[Sequence[Tagged]],
    *,
    trace: bool,
    finding_groups: Sequence[Sequence[Finding]],
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
                    source_forgery = str(bool(getattr(evidence, "source_has_forgery", False))).lower()
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

    return GraphSnapshot(node_labels=node_labels, edges=tuple(dict.fromkeys(edges)))
