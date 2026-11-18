"""Convert tagged parser output and structural findings into a graph snapshot."""
from __future__ import annotations

from parser.models import Finding, TaggedField
from classifier.wl_svm import GraphSnapshot


def build_trust_graph(
    fields: list[TaggedField], findings: list[Finding] | tuple[Finding, ...] = ()
) -> GraphSnapshot:
    """Build a deterministic field/provenance graph, retaining finding edges."""
    if not fields:
        raise ValueError("at least one tagged field is required to build a graph")
    node_labels: dict[str, str] = {}
    edges: list[tuple[str, str]] = []
    field_paths = {field.path for field in fields}
    for field in fields:
        provenance = getattr(field, "provenance", None)
        role = getattr(field, "role", None)
        lineage = getattr(field, "lineage_status", None)
        node_labels[field.path] = ":".join(
            part for part in (
                field.trust.value,
                getattr(provenance, "value", "legacy"),
                getattr(role, "value", "other"),
                getattr(lineage, "value", "unlinked"),
                field.value_type,
                f"depth={field.depth}",
                f"forgery={str(getattr(field, 'has_forgery', False)).lower()}",
            )
        )
        if field.parent_path in field_paths:
            edges.append((field.parent_path, field.path))
        for evidence in getattr(field, "derived_from", ()):
            if evidence.source_tag_id:
                source = f"source:{evidence.source_tag_id}"
                source_provenance = getattr(evidence, "source_provenance", "EXTERNAL")
                source_provenance = getattr(source_provenance, "value", source_provenance)
                source_forgery = str(getattr(evidence, "source_has_forgery", False)).lower()
                node_labels.setdefault(source, f"source:{source_provenance}:string:forgery={source_forgery}")
                edges.append((source, field.path))
    for index, finding in enumerate(findings):
        finding_id = f"finding:{index}:{finding.path}:{finding.kind}"
        node_labels[finding_id] = f"finding:{finding.kind}"
        target = finding.path.split("#", 1)[0]
        if target in field_paths:
            edges.append((target, finding_id))
    return GraphSnapshot(node_labels=node_labels, edges=tuple(edges))
