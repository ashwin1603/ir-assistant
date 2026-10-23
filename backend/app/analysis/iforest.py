"""Isolation Forest anomaly detection for process-creation (4688) events, numpy only.

Idea (Liu et al., 2008): build random trees that split on a random feature at a
random value. Unusual points get isolated in few splits, so a SHORT average
path length across trees means "anomalous". This is separate from the rules:
it only says "this looks unusual compared to this host's normal activity", it
does not map anything to ATT&CK.
"""

import math
from collections import Counter

import numpy as np

N_TREES = 100
SAMPLE_SIZE = 256
SEED = 42
ANOMALY_THRESHOLD = 0.6  # standard IF cut-off: ~0.5 is normal, closer to 1 is anomalous

FEATURE_NAMES = [
    "cmdline_length",
    "token_count",
    "shannon_entropy",
    "special_char_ratio",
    "path_depth",
    "process_rarity",
    "parent_rarity",
    "hour_of_day",
]


def _basename(path: str | None) -> str:
    return (path or "").replace("/", "\\").rsplit("\\", 1)[-1].lower()


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    return -sum((c / len(text)) * math.log2(c / len(text)) for c in counts.values())


def _frequencies(events) -> tuple[Counter, Counter, int]:
    """How often each process / parent name appears in the training set."""
    procs = Counter(_basename(e.process) for e in events)
    parents = Counter(_basename(e.parent_process) for e in events)
    return procs, parents, max(len(events), 1)


def extract_features(events, training_events) -> np.ndarray:
    """One row per event, columns in FEATURE_NAMES order.

    Rarity = 1 - (frequency in the training set), so a never-seen process is 1.0.
    """
    procs, parents, n = _frequencies(training_events)
    rows = []
    for e in events:
        cmd = e.command_line or ""
        special = sum(1 for ch in cmd if not ch.isalnum() and not ch.isspace())
        rows.append([
            len(cmd),
            len(cmd.split()),
            _entropy(cmd),
            special / len(cmd) if cmd else 0.0,
            (e.process or "").replace("/", "\\").count("\\"),
            1.0 - procs[_basename(e.process)] / n,
            1.0 - parents[_basename(e.parent_process)] / n,
            e.timestamp.hour,
        ])
    return np.array(rows, dtype=float).reshape(-1, len(FEATURE_NAMES))


def _c(n: int) -> float:
    """Average path length of an unsuccessful BST search over n points.
    Used to normalise path lengths and to estimate the depth left at a leaf."""
    if n <= 1:
        return 0.0
    if n == 2:
        return 1.0
    return 2.0 * (math.log(n - 1) + 0.5772156649) - 2.0 * (n - 1) / n


class IsolationForest:
    def __init__(self, n_trees: int = N_TREES, sample_size: int = SAMPLE_SIZE, seed: int = SEED):
        self.n_trees = n_trees
        self.sample_size = sample_size
        self.seed = seed
        self.trees: list = []

    def fit(self, X: np.ndarray) -> "IsolationForest":
        rng = np.random.default_rng(self.seed)
        size = min(self.sample_size, len(X))
        self.psi = size
        height_limit = math.ceil(math.log2(max(size, 2)))
        self.trees = [
            self._build(X[rng.choice(len(X), size, replace=False)], 0, height_limit, rng)
            for _ in range(self.n_trees)
        ]
        return self

    def _build(self, X: np.ndarray, depth: int, limit: int, rng):
        # Leaf: depth limit reached, or nothing left to separate.
        if depth >= limit or len(X) <= 1:
            return ("leaf", len(X))
        lo, hi = X.min(axis=0), X.max(axis=0)
        splittable = np.flatnonzero(hi > lo)
        if len(splittable) == 0:
            return ("leaf", len(X))
        feature = rng.choice(splittable)
        split = rng.uniform(lo[feature], hi[feature])
        mask = X[:, feature] < split
        return ("node", feature, split,
                self._build(X[mask], depth + 1, limit, rng),
                self._build(X[~mask], depth + 1, limit, rng))

    def _path_lengths(self, tree, X: np.ndarray, idx: np.ndarray, depth: int, out: np.ndarray) -> None:
        """Send all rows in idx down the tree at once (vectorised per node)."""
        if tree[0] == "leaf":
            out[idx] += depth + _c(tree[1])
            return
        _, feature, split, left, right = tree
        mask = X[idx, feature] < split
        self._path_lengths(left, X, idx[mask], depth + 1, out)
        self._path_lengths(right, X, idx[~mask], depth + 1, out)

    def score(self, X: np.ndarray) -> np.ndarray:
        """Anomaly score in (0, 1]: s = 2 ** (-mean_path_length / c(psi))."""
        total = np.zeros(len(X))
        for tree in self.trees:
            self._path_lengths(tree, X, np.arange(len(X)), 0, total)
        mean_path = total / len(self.trees)
        return 2.0 ** (-mean_path / _c(self.psi))


def top_features(x: np.ndarray, X_train: np.ndarray, k: int = 3) -> list[dict]:
    """Explain one score: the features furthest from the training median,
    measured in robust units (median absolute deviation)."""
    median = np.median(X_train, axis=0)
    mad = np.median(np.abs(X_train - median), axis=0)
    std = X_train.std(axis=0)
    scale = np.where(mad > 0, mad, np.where(std > 0, std, 1.0))
    deviation = np.abs(x - median) / scale
    order = np.argsort(-deviation, kind="stable")[:k]
    return [
        {"name": FEATURE_NAMES[i], "value": round(float(x[i]), 3),
         "typical": round(float(median[i]), 3), "deviation": round(float(deviation[i]), 2)}
        for i in order
    ]
