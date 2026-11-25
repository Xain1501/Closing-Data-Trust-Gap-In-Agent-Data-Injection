"""CPU-sized Weisfeiler-Lehman feature map and calibrated SVM.

The graph builder/tagger lives in ``src/trust_graph``. This module accepts a
small adapter-friendly graph snapshot: stable node IDs with categorical labels
and undirected edges. It does not infer trust labels from raw field values.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from hashlib import sha256
import json
import math
from pathlib import Path
from typing import Mapping, Sequence

import joblib
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction import DictVectorizer
from sklearn.model_selection import StratifiedGroupKFold, StratifiedKFold
from sklearn.svm import SVC


@dataclass(frozen=True)
class GraphSnapshot:
    """Minimal graph contract consumed by the WL classifier.

    Node labels should encode the provenance/trust class and any categorical
    features selected by the graph stage (for example field type or role).
    Edge pairs are treated as undirected and must reference known node IDs.
    """

    node_labels: Mapping[str, str]
    edges: tuple[tuple[str, str], ...]

    @classmethod
    def from_payload(cls, payload: Mapping[str, object]) -> "GraphSnapshot":
        """Normalize the supported graph JSON shapes into one classifier contract.

        The graph builder may serialize labels as ``node_labels`` or as a node
        list, and edges as pairs or ``source``/``target`` objects. Normalizing at
        this boundary keeps training and testing compatible with either form.
        """
        raw_labels = payload.get("node_labels")
        labels: dict[str, str] = {}
        if isinstance(raw_labels, Mapping):
            labels = {str(node): str(label) for node, label in raw_labels.items()}
        else:
            raw_nodes = payload.get("nodes", [])
            if isinstance(raw_nodes, Mapping):
                raw_nodes = [dict(value, id=node) if isinstance(value, Mapping) else {"id": node, "label": value}
                             for node, value in raw_nodes.items()]
            if isinstance(raw_nodes, Sequence) and not isinstance(raw_nodes, (str, bytes)):
                for node in raw_nodes:
                    if isinstance(node, Mapping) and node.get("id") is not None:
                        label = node.get("label", node.get("name"))
                        if label is not None:
                            labels[str(node["id"])] = str(label)
        raw_edges = payload.get("edges", payload.get("links", []))
        edges: list[tuple[str, str]] = []
        if isinstance(raw_edges, Sequence) and not isinstance(raw_edges, (str, bytes)):
            for edge in raw_edges:
                if isinstance(edge, Mapping):
                    left, right = edge.get("source"), edge.get("target")
                elif isinstance(edge, Sequence) and len(edge) == 2:
                    left, right = edge[0], edge[1]
                else:
                    continue
                if left is not None and right is not None:
                    edges.append((str(left), str(right)))
        return cls(node_labels=labels, edges=tuple(edges))

    def __post_init__(self) -> None:
        if not self.node_labels:
            raise ValueError("graph must contain at least one node")
        if any(not isinstance(node, str) or not node for node in self.node_labels):
            raise ValueError("node IDs must be non-empty strings")
        if any(not isinstance(label, str) or not label for label in self.node_labels.values()):
            raise ValueError("node labels must be non-empty strings")
        for left, right in self.edges:
            if left not in self.node_labels or right not in self.node_labels:
                raise ValueError(f"edge references unknown node: {(left, right)!r}")


def _digest(value: object) -> str:
    serialized = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return sha256(serialized.encode("utf-8")).hexdigest()


def wl_features(
    graph: GraphSnapshot,
    iterations: int = 2,
    *,
    normalize_counts: bool = True,
) -> dict[str, float]:
    """Return deterministic WL subtree label frequencies for iterations 0..h."""
    if iterations < 0:
        raise ValueError("iterations must be non-negative")
    neighbors: dict[str, list[str]] = {node: [] for node in graph.node_labels}
    for left, right in graph.edges:
        neighbors[left].append(right)
        if left != right:
            neighbors[right].append(left)

    labels = dict(graph.node_labels)
    features: Counter[str] = Counter()
    # Explicit, suite-independent provenance summaries make the classifier
    # robust when a new suite has different graph topology.  These are counts
    # of semantics already present in node labels, never raw tool names or
    # task IDs.
    node_count = len(labels)
    finding_count = sum(label.startswith("finding:") for label in labels.values())
    forgery_true = sum(":forgery=true" in label for label in labels.values())
    forgery_leaf = sum(":forgery=leaf" in label for label in labels.values())
    mimicry_true = sum(":mimicry=true" in label for label in labels.values())
    anomaly_true = sum(":anomaly=true" in label for label in labels.values())
    external_links = sum("EXTERNAL_LINK" in label for label in labels.values())
    system_links = sum("SYSTEM_LINK" in label for label in labels.values())
    user_matches = sum("USER_MATCH" in label for label in labels.values())
    authority_nodes = sum("AUTHORITY_ARG" in label for label in labels.values())
    rel_mimics = sum(label == "rel:mimics" for label in labels.values())
    rel_mentions = sum(label == "rel:mentions" for label in labels.values())
    # Log counts and normalized rates stop graph size from becoming a proxy for
    # the source (for example scripted benign traces versus LLM traces).
    features["summary:node_count_log1p"] = float(math.log1p(node_count))
    features["summary:finding_rate"] = finding_count / node_count
    features["summary:forgery_true_rate"] = forgery_true / node_count
    features["summary:forgery_leaf_rate"] = forgery_leaf / node_count
    features["summary:mimicry_true_rate"] = mimicry_true / node_count
    features["summary:anomaly_true_rate"] = anomaly_true / node_count
    features["summary:external_link_rate"] = external_links / node_count
    features["summary:system_link_rate"] = system_links / node_count
    features["summary:user_match_rate"] = user_matches / node_count
    features["summary:authority_rate"] = authority_nodes / node_count
    features["summary:rel_mimics_rate"] = rel_mimics / node_count
    features["summary:rel_mentions_rate"] = rel_mentions / node_count
    for depth in range(iterations + 1):
        depth_counts = Counter(labels.values())
        scale = node_count if normalize_counts else 1
        for label, count in depth_counts.items():
            features[f"wl:{depth}:{label}"] += count / scale
        if depth == iterations:
            break
        labels = {
            node: _digest([labels[node], sorted(labels[neighbor] for neighbor in neighbors[node])])
            for node in graph.node_labels
        }
    return {feature: float(count) for feature, count in features.items()}


@dataclass(frozen=True)
class ClassifierResult:
    attack_probability: float
    predicted_label: str
    novelty_score: float = 0.0
    out_of_distribution: bool = False


class WLGraphSVM:
    """WL explicit features + linear SVM with sigmoid probability calibration."""

    def __init__(self, iterations: int = 2, c: float = 1.0, random_state: int = 0) -> None:
        if iterations < 0 or c <= 0:
            raise ValueError("iterations must be >= 0 and C must be > 0")
        self.iterations = iterations
        self.c = c
        self.random_state = random_state
        self._vectorizer: DictVectorizer | None = None
        self._model: CalibratedClassifierCV | None = None
        self._training_group_ids: frozenset[str] | None = None
        self._training_unit = "run"
        self._normalize_wl_counts = True
        self._ood_threshold = 0.0

    @property
    def training_group_ids(self) -> frozenset[str] | None:
        return self._training_group_ids

    @property
    def training_unit(self) -> str:
        return self._training_unit

    @property
    def ood_threshold(self) -> float:
        return self._ood_threshold

    def fit(
        self,
        graphs: Sequence[GraphSnapshot],
        labels: Sequence[str],
        *,
        group_ids: Sequence[str] | None = None,
    ) -> "WLGraphSVM":
        if len(graphs) != len(labels) or not graphs:
            raise ValueError("graphs and labels must have the same non-zero length")
        if group_ids is not None and (
            len(group_ids) != len(graphs)
            or any(not isinstance(group, str) or not group for group in group_ids)
        ):
            raise ValueError("group_ids must contain one non-empty string per graph")
        counts = Counter(labels)
        if set(counts) != {"benign", "attack"}:
            raise ValueError("training labels must contain both 'benign' and 'attack'")
        folds = min(5, min(counts.values()))
        if folds < 2:
            raise ValueError("calibrated training needs at least two examples per class")

        feature_rows = [
            wl_features(graph, self.iterations, normalize_counts=True) for graph in graphs
        ]
        vectorizer = DictVectorizer(sparse=True, sort=True)
        matrix = vectorizer.fit_transform(feature_rows)
        # Newer SciPy versions may build int64 CSR indices for small matrices;
        # SVC requires int32 indices for sparse input.
        matrix.indices = matrix.indices.astype("int32", copy=False)
        matrix.indptr = matrix.indptr.astype("int32", copy=False)
        base = SVC(kernel="linear", C=self.c, class_weight="balanced")
        if group_ids is not None:
            if len(set(group_ids)) < folds:
                raise ValueError("group_ids must contain at least as many groups as calibration folds")
            splitter = StratifiedGroupKFold(
                n_splits=folds, shuffle=True, random_state=self.random_state
            )
            calibration_cv = list(splitter.split(matrix, list(labels), groups=list(group_ids)))
        else:
            calibration_cv = StratifiedKFold(
                n_splits=folds, shuffle=True, random_state=self.random_state
            )
        model = CalibratedClassifierCV(
            estimator=base,
            method="sigmoid",
            cv=calibration_cv,
        )
        model.fit(matrix, list(labels))
        self._vectorizer = vectorizer
        self._model = model
        self._training_group_ids = frozenset(group_ids) if group_ids is not None else None
        self._training_unit = "run"
        self._normalize_wl_counts = True
        self._ood_threshold = self._calibrate_ood_threshold(feature_rows, group_ids)
        return self

    @staticmethod
    def _calibrate_ood_threshold(
        feature_rows: Sequence[Mapping[str, float]],
        group_ids: Sequence[str] | None,
    ) -> float:
        """Calibrate novelty from features absent in other training groups."""
        feature_groups: dict[str, set[str]] = {}
        row_groups = (
            list(group_ids) if group_ids is not None
            else [f"row:{index}" for index in range(len(feature_rows))]
        )
        for features, group in zip(feature_rows, row_groups):
            for feature in features:
                feature_groups.setdefault(feature, set()).add(group)

        scores = []
        for features, group in zip(feature_rows, row_groups):
            total = sum(features.values())
            unseen = sum(
                value for feature, value in features.items()
                if not (feature_groups[feature] - {group})
            )
            scores.append(unseen / total if total else 0.0)

        # A nearest-rank 95th percentile uses only group-excluded training
        # examples; novel examples above the observed benign/attack variation
        # envelope abstain rather than receiving a potentially misleading label.
        ordered = sorted(scores)
        percentile_index = math.ceil(0.95 * len(ordered)) - 1
        return float(ordered[percentile_index])

    def predict(self, graph: GraphSnapshot) -> ClassifierResult:
        if self._model is None or self._vectorizer is None:
            raise RuntimeError("classifier must be fit before prediction")
        features = wl_features(
            graph, self.iterations, normalize_counts=self._normalize_wl_counts,
        )
        vocabulary = self._vectorizer.vocabulary_
        total_feature_mass = sum(features.values())
        novelty_score = (
            sum(value for name, value in features.items() if name not in vocabulary)
            / total_feature_mass
            if total_feature_mass else 0.0
        )
        vector = self._vectorizer.transform([features])
        vector.indices = vector.indices.astype("int32", copy=False)
        vector.indptr = vector.indptr.astype("int32", copy=False)
        probabilities = self._model.predict_proba(vector)[0]
        classes = list(self._model.classes_)
        attack_probability = float(probabilities[classes.index("attack")])
        predicted = str(self._model.predict(vector)[0])
        return ClassifierResult(
            attack_probability,
            predicted,
            novelty_score,
            novelty_score > self._ood_threshold,
        )

    def save(self, path: str | Path) -> None:
        if self._model is None or self._vectorizer is None:
            raise RuntimeError("cannot save an unfitted classifier")
        joblib.dump({
            "format_version": 4,
            "feature_schema_version": 2,
            "training_unit": self._training_unit,
            "ood_threshold": self._ood_threshold,
            "iterations": self.iterations,
            "c": self.c,
            "random_state": self.random_state,
            "vectorizer": self._vectorizer,
            "model": self._model,
            "training_group_ids": (
                sorted(self._training_group_ids)
                if self._training_group_ids is not None else None
            ),
        }, path)

    @classmethod
    def load(cls, path: str | Path) -> "WLGraphSVM":
        artifact = joblib.load(path)
        if not isinstance(artifact, dict):
            raise ValueError("unsupported classifier artifact")
        artifact_version = artifact.get("format_version")
        if artifact_version in (1, 2):
            normalize_wl_counts = False
            training_unit = "run"
        elif (
            artifact_version == 3
            and artifact.get("feature_schema_version") == 2
            and artifact.get("training_unit") == "run"
        ):
            normalize_wl_counts = True
            training_unit = "run"
            ood_threshold = 0.0
        elif (
            artifact_version == 4
            and artifact.get("feature_schema_version") == 2
            and artifact.get("training_unit") == "run"
            and not isinstance(artifact.get("ood_threshold"), bool)
            and isinstance(artifact.get("ood_threshold"), (int, float))
            and math.isfinite(artifact["ood_threshold"])
            and 0.0 <= artifact["ood_threshold"] <= 1.0
        ):
            normalize_wl_counts = True
            training_unit = "run"
            ood_threshold = float(artifact["ood_threshold"])
        else:
            raise ValueError("unsupported or incompatible classifier artifact")
        if artifact_version in (1, 2):
            ood_threshold = 0.0
        instance = cls(
            iterations=artifact["iterations"],
            c=artifact["c"],
            random_state=artifact["random_state"],
        )
        instance._vectorizer = artifact["vectorizer"]
        instance._model = artifact["model"]
        instance._training_unit = training_unit
        instance._normalize_wl_counts = normalize_wl_counts
        instance._ood_threshold = ood_threshold
        group_ids = artifact.get("training_group_ids")
        if group_ids is not None:
            if not isinstance(group_ids, list) or any(
                not isinstance(group, str) or not group for group in group_ids
            ):
                raise ValueError("invalid training group metadata in classifier artifact")
            instance._training_group_ids = frozenset(group_ids)
        return instance
