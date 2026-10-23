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
        node_labels[field.path] = f"{field.trust.value}:{field.value_type}:depth={field.depth}"
        if field.parent_path in field_paths:
            edges.append((field.parent_path, field.path))
    for index, finding in enumerate(findings):
        finding_id = f"finding:{index}:{finding.path}:{finding.kind}"
        node_labels[finding_id] = f"finding:{finding.kind}"
        target = finding.path.split("#", 1)[0]
        if target in field_paths:
            edges.append((target, finding_id))
    return GraphSnapshot(node_labels=node_labels, edges=tuple(edges))
