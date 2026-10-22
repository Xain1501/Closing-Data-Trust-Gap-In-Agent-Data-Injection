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
from pathlib import Path
from typing import Mapping, Sequence

import joblib
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction import DictVectorizer
from sklearn.model_selection import StratifiedKFold
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


def wl_features(graph: GraphSnapshot, iterations: int = 2) -> dict[str, float]:
    """Return deterministic WL subtree label counts for iterations 0..h."""
    if iterations < 0:
        raise ValueError("iterations must be non-negative")
    neighbors: dict[str, list[str]] = {node: [] for node in graph.node_labels}
    for left, right in graph.edges:
        neighbors[left].append(right)
        if left != right:
            neighbors[right].append(left)

    labels = dict(graph.node_labels)
    features: Counter[str] = Counter()
    for depth in range(iterations + 1):
        features.update(f"wl:{depth}:{label}" for label in labels.values())
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

    def fit(self, graphs: Sequence[GraphSnapshot], labels: Sequence[str]) -> "WLGraphSVM":
        if len(graphs) != len(labels) or not graphs:
            raise ValueError("graphs and labels must have the same non-zero length")
        counts = Counter(labels)
        if set(counts) != {"benign", "attack"}:
            raise ValueError("training labels must contain both 'benign' and 'attack'")
        folds = min(5, min(counts.values()))
        if folds < 2:
            raise ValueError("calibrated training needs at least two examples per class")

        vectorizer = DictVectorizer(sparse=True, sort=True)
        matrix = vectorizer.fit_transform([wl_features(graph, self.iterations) for graph in graphs])
        # Newer SciPy versions may build int64 CSR indices for small matrices;
        # SVC requires int32 indices for sparse input.
        matrix.indices = matrix.indices.astype("int32", copy=False)
        matrix.indptr = matrix.indptr.astype("int32", copy=False)
        base = SVC(kernel="linear", C=self.c, class_weight="balanced")
        model = CalibratedClassifierCV(
            estimator=base,
            method="sigmoid",
            cv=StratifiedKFold(n_splits=folds, shuffle=True, random_state=self.random_state),
        )
        model.fit(matrix, list(labels))
        self._vectorizer = vectorizer
        self._model = model
        return self

    def predict(self, graph: GraphSnapshot) -> ClassifierResult:
        if self._model is None or self._vectorizer is None:
            raise RuntimeError("classifier must be fit before prediction")
        vector = self._vectorizer.transform([wl_features(graph, self.iterations)])
        vector.indices = vector.indices.astype("int32", copy=False)
        vector.indptr = vector.indptr.astype("int32", copy=False)
        probabilities = self._model.predict_proba(vector)[0]
        classes = list(self._model.classes_)
        attack_probability = float(probabilities[classes.index("attack")])
        predicted = str(self._model.predict(vector)[0])
        return ClassifierResult(attack_probability, predicted)

    def save(self, path: str | Path) -> None:
        if self._model is None or self._vectorizer is None:
            raise RuntimeError("cannot save an unfitted classifier")
        joblib.dump({
            "format_version": 1,
            "iterations": self.iterations,
            "c": self.c,
            "random_state": self.random_state,
            "vectorizer": self._vectorizer,
            "model": self._model,
        }, path)

    @classmethod
    def load(cls, path: str | Path) -> "WLGraphSVM":
        artifact = joblib.load(path)
        if not isinstance(artifact, dict) or artifact.get("format_version") != 1:
            raise ValueError("unsupported classifier artifact")
        instance = cls(
            iterations=artifact["iterations"],
            c=artifact["c"],
            random_state=artifact["random_state"],
        )
        instance._vectorizer = artifact["vectorizer"]
        instance._model = artifact["model"]
        return instance
