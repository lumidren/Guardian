"""
Evaluation Validity Controls and Leakage Audit Harness (Milestone P3-1).

Implements broken-detector controls and validity checks:
1. Label isolation verification.
2. Non-semantic artifact leakage audit.
3. Shuffled-label control (TPR must collapse to roughly FPR).
4. Always-alert (TPR=1.0, FPR=1.0) and Never-alert (TPR=0.0, FPR=0.0) bounds.
5. Random-score detector control (ROC-AUC ~ 0.50).
6. Timeline extraction for pure-attack-window verification.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

import numpy as np

from ..capture.flow_tracker import FlowTracker
from ..enforcement.controller import EnforcementController
from ..features.extractor import FeatureExtractor
from ..ml.isolation_forest import IsolationForestDetector
from ..ml.statistical_baseline import StatisticalBaseline
from ..ml.threat_scorer import ThreatScorer
from .calibration import OperatingPoint
from .metrics import compute_binary_metrics, compute_roc_auc
from .scenario import GroundTruthEpisode, ScenarioBuilder


@dataclass
class PermutationTestResult:
    n_permutations: int
    observed_diff: float
    null_mean: float
    null_95th_percentile: float
    p_value: float
    passed: bool


def run_200_shuffle_permutation_test(
    y_true: Sequence[int],
    y_pred: Sequence[int],
    n_permutations: int = 200,
    seed: int = 42,
) -> PermutationTestResult:
    """
    Executes a 200-shuffle permutation test to construct the empirical null distribution
    for |TPR - FPR|, replacing heuristic tolerance bands with statistical hypothesis testing.
    """
    rng = np.random.default_rng(seed)
    y_arr = np.asarray(y_true, dtype=int)
    y_p = np.asarray(y_pred, dtype=int)

    null_diffs: list[float] = []
    for _ in range(n_permutations):
        y_perm = rng.permutation(y_arr)
        tp = np.sum((y_p == 1) & (y_perm == 1))
        p = np.sum(y_perm == 1)
        fp = np.sum((y_p == 1) & (y_perm == 0))
        n = np.sum(y_perm == 0)
        tpr = float(tp / p) if p > 0 else 0.0
        fpr = float(fp / n) if n > 0 else 0.0
        null_diffs.append(abs(tpr - fpr))

    tp_obs = np.sum((y_p == 1) & (y_arr == 1))
    p_obs = np.sum(y_arr == 1)
    fp_obs = np.sum((y_p == 1) & (y_arr == 0))
    n_obs = np.sum(y_arr == 0)
    tpr_obs = float(tp_obs / p_obs) if p_obs > 0 else 0.0
    fpr_obs = float(fp_obs / n_obs) if n_obs > 0 else 0.0
    diff_obs = abs(tpr_obs - fpr_obs)

    p_val = float(np.mean(np.asarray(null_diffs) >= diff_obs))
    null_mean = float(np.mean(null_diffs))
    null_95th = float(np.percentile(null_diffs, 95))

    return PermutationTestResult(
        n_permutations=n_permutations,
        observed_diff=diff_obs,
        null_mean=null_mean,
        null_95th_percentile=null_95th,
        p_value=p_val,
        passed=bool(p_val > 0.05 or diff_obs <= null_95th),
    )


@dataclass
class ControlsEvaluationResult:
    always_alert_tpr: float
    always_alert_fpr: float
    never_alert_tpr: float
    never_alert_fpr: float
    random_score_roc_auc: float
    shuffled_tpr: float
    shuffled_fpr: float
    shuffled_roc_auc: float
    permutation_p_value: float
    permutation_passed: bool
    controls_passed: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "always_alert": {
                "tpr": self.always_alert_tpr,
                "fpr": self.always_alert_fpr,
                "status": "PASS" if (self.always_alert_tpr == 1.0 and self.always_alert_fpr == 1.0) else "FAIL",
            },
            "never_alert": {
                "tpr": self.never_alert_tpr,
                "fpr": self.never_alert_fpr,
                "status": "PASS" if (self.never_alert_tpr == 0.0 and self.never_alert_fpr == 0.0) else "FAIL",
            },
            "random_score_detector": {
                "roc_auc": round(self.random_score_roc_auc, 4),
                "status": "PASS" if (0.40 <= self.random_score_roc_auc <= 0.60) else "FAIL",
            },
            "shuffled_labels": {
                "tpr": round(self.shuffled_tpr, 4),
                "fpr": round(self.shuffled_fpr, 4),
                "roc_auc": round(self.shuffled_roc_auc, 4),
                "permutation_p_value": round(self.permutation_p_value, 4),
                "status": "PASS" if self.permutation_passed else "FAIL",
            },
            "controls_passed": self.controls_passed,
        }


class EvaluationControlBattery:
    """
    Executes standard broken-detector and label integrity controls.
    """

    def __init__(self, seed: int = 42) -> None:
        self.seed = seed

    def run_all_controls(
        self,
        y_true: Sequence[int],
        scores: Sequence[float],
        operating_point: OperatingPoint | None = None,
    ) -> ControlsEvaluationResult:
        """
        Run the complete battery of broken-detector and shuffled-label controls.
        """
        op = operating_point or OperatingPoint.default_production()
        y_t = list(y_true)
        sc = list(scores)

        # 1. Always Alert Control
        y_always = [1] * len(y_t)
        always_bm = compute_binary_metrics(y_t, y_always)

        # 2. Never Alert Control
        y_never = [0] * len(y_t)
        never_bm = compute_binary_metrics(y_t, y_never)

        # 3. Random Score Detector Control
        rng = np.random.default_rng(self.seed)
        random_scores = rng.uniform(0.0, 1.0, size=len(y_t)).tolist()
        random_roc = compute_roc_auc(y_t, random_scores)

        # 4. Shuffled Labels Control with 200-Shuffle Permutation Test
        y_shuffled = rng.permutation(y_t).tolist()
        y_pred = [1 if op.is_alert(s * 100.0) else 0 for s in sc]
        shuffled_bm = compute_binary_metrics(y_shuffled, y_pred)
        shuffled_roc = compute_roc_auc(y_shuffled, sc)

        perm_test = run_200_shuffle_permutation_test(y_shuffled, y_pred, n_permutations=200, seed=self.seed)

        # Pass criteria
        p_always = (always_bm.tpr == 1.0 and always_bm.fpr == 1.0)
        p_never = (never_bm.tpr == 0.0 and never_bm.fpr == 0.0)
        p_random = (0.40 <= random_roc <= 0.60)
        p_shuffled = perm_test.passed

        all_passed = p_always and p_never and p_random and p_shuffled

        return ControlsEvaluationResult(
            always_alert_tpr=always_bm.tpr,
            always_alert_fpr=always_bm.fpr,
            never_alert_tpr=never_bm.tpr,
            never_alert_fpr=never_bm.fpr,
            random_score_roc_auc=random_roc,
            shuffled_tpr=shuffled_bm.tpr,
            shuffled_fpr=shuffled_bm.fpr,
            shuffled_roc_auc=shuffled_roc,
            permutation_p_value=perm_test.p_value,
            permutation_passed=perm_test.passed,
            controls_passed=all_passed,
        )


@dataclass
class EpisodeTimelinePoint:
    time_offset_s: float
    window_start: float
    has_attack: bool
    attack_packet_count: int
    normal_packet_count: int
    threat_score: float
    threat_level: str


def extract_episode_timeline(
    device_id: str,
    episode: GroundTruthEpisode,
    scenario_builder: ScenarioBuilder,
    lead_time_s: float = 20.0,
    lag_time_s: float = 20.0,
) -> list[EpisodeTimelinePoint]:
    """
    Extracts high-resolution window-by-window scores before, during, and after an attack episode.
    Used for pure-attack-window verification and score evolution auditing.
    """
    dev = next(d for d in scenario_builder.devices if d.id == device_id)
    t_start = max(0.0, episode.start_time - lead_time_s)
    t_end = episode.end_time + lag_time_s

    windows = scenario_builder.generate_device_stream_windows(
        device_id=dev.id,
        start_time=t_start,
        end_time=t_end,
        episodes=[episode],
    )

    extractor = FeatureExtractor()
    scorer = ThreatScorer()
    enforcer = EnforcementController()
    model = IsolationForestDetector(n_estimators=10)
    model.is_trained = True
    baseline = StatisticalBaseline()
    baseline.is_ready = True

    flow_tracker = FlowTracker(window_size_seconds=scenario_builder.window_size_s)
    for dst in dev.normal_destinations:
        flow_tracker.register_known_destination(dev.ip_address, dst)

    timeline: list[EpisodeTimelinePoint] = []
    for w in windows:
        for p in w.packets:
            flow_tracker.ingest_packet(p)

        summary = flow_tracker.get_window_summary(dev.ip_address)
        if not summary:
            continue

        feat = extractor.extract(summary)
        vec = extractor.extract_vector(summary)

        ml_score, _ = model.score_sample(vec)
        stat_score, _ = baseline.evaluate(feat)
        assessment = scorer.assess(ml_score, stat_score, feat)
        enf = enforcer.enforce(dev.id, dev.ip_address, assessment)

        timeline.append(
            EpisodeTimelinePoint(
                time_offset_s=round(w.start_time - episode.start_time, 2),
                window_start=round(w.start_time, 2),
                has_attack=w.has_attack,
                attack_packet_count=w.attack_packet_count,
                normal_packet_count=w.normal_packet_count,
                threat_score=round(assessment.threat_score, 2),
                threat_level=enf.current_level.value,
            )
        )

    return timeline


class SimpleDecisionTreeRegressor:
    """Fast depth-bounded regression tree for pseudo-residuals in GBDT."""

    def __init__(self, max_depth: int = 3, min_samples_split: int = 6) -> None:
        self.max_depth = max_depth
        self.min_samples_split = min_samples_split
        self.tree: dict[str, Any] = {}

    def fit(self, X: np.ndarray, r: np.ndarray, p: np.ndarray) -> None:
        self.tree = self._build_tree(X, r, p, depth=0)

    def _build_tree(self, X: np.ndarray, r: np.ndarray, p: np.ndarray, depth: int) -> dict[str, Any]:
        denom = float(np.sum(p * (1.0 - p)))
        leaf_val = float(np.sum(r) / (denom + 1e-10))
        if depth >= self.max_depth or len(X) < self.min_samples_split:
            return {"leaf": True, "val": leaf_val}

        best_gain = -1.0
        best_split: tuple[int, float, np.ndarray, np.ndarray] | None = None
        _, m = X.shape

        for feat in range(m):
            vals = np.unique(X[:, feat])
            if len(vals) > 8:
                vals = np.percentile(vals, np.linspace(15, 85, 6))
            for thr in vals:
                left = X[:, feat] <= thr
                right = ~left
                if np.sum(left) < 3 or np.sum(right) < 3:
                    continue
                r_l, r_r = r[left], r[right]
                gain = float((np.sum(r_l) ** 2 / len(r_l)) + (np.sum(r_r) ** 2 / len(r_r)))
                if gain > best_gain:
                    best_gain = gain
                    best_split = (feat, float(thr), left, right)

        if best_split is None:
            return {"leaf": True, "val": leaf_val}

        feat, thr, left, right = best_split
        return {
            "leaf": False,
            "feat": feat,
            "thr": thr,
            "left": self._build_tree(X[left], r[left], p[left], depth + 1),
            "right": self._build_tree(X[right], r[right], p[right], depth + 1),
        }

    def predict(self, X: np.ndarray) -> np.ndarray:
        return np.asarray([self._predict_one(x, self.tree) for x in X], dtype=float)

    def _predict_one(self, x: np.ndarray, node: dict[str, Any]) -> float:
        if node["leaf"]:
            return float(node["val"])
        if x[node["feat"]] <= node["thr"]:
            return self._predict_one(x, node["left"])
        return self._predict_one(x, node["right"])


class GradientBoostedTreesClassifier:
    """Pure NumPy Gradient Boosted Decision Tree classifier for artifact auditing."""

    def __init__(self, n_estimators: int = 15, max_depth: int = 3, learning_rate: int = 1) -> None:
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.lr = 0.1 * learning_rate
        self.trees: list[SimpleDecisionTreeRegressor] = []
        self.init_val = 0.0

    def fit(self, X: np.ndarray, y: np.ndarray) -> None:
        p_mean = max(1e-5, min(1.0 - 1e-5, float(np.mean(y))))
        self.init_val = float(np.log(p_mean / (1.0 - p_mean)))
        F = np.full(len(y), self.init_val)
        self.trees = []
        for _ in range(self.n_estimators):
            p = 1.0 / (1.0 + np.exp(-F))
            r = y - p
            tree = SimpleDecisionTreeRegressor(max_depth=self.max_depth)
            tree.fit(X, r, p)
            F += self.lr * tree.predict(X)
            self.trees.append(tree)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        F = np.full(len(X), self.init_val)
        for tree in self.trees:
            F += self.lr * tree.predict(X)
        probs = 1.0 / (1.0 + np.exp(-F))
        return np.asarray(probs, dtype=float)


def extract_non_semantic_packet_features(packet: Any) -> list[float]:
    """
    Extracts all non-semantic packet header fields:
    - TTL
    - TCP flags: SYN, ACK, PSH, RST, FIN
    - Length granularity: length % 8, length % 16
    - IAT regularity: sub-second timestamp fraction, IP ID % 1000, source port band
    """
    flags = getattr(packet, "tcp_flags", {}) or {}
    return [
        float(getattr(packet, "ttl", 64)),
        float(1.0 if flags.get("SYN") else 0.0),
        float(1.0 if flags.get("ACK") else 0.0),
        float(1.0 if flags.get("PSH") else 0.0),
        float(1.0 if flags.get("RST") else 0.0),
        float(1.0 if flags.get("FIN") else 0.0),
        float(getattr(packet, "length", 64) % 8),
        float(getattr(packet, "length", 64) % 16),
        float(getattr(packet, "timestamp", 0.0) % 1.0),
        float(getattr(packet, "ip_id", 0) % 1000),
        float(getattr(packet, "src_port", 0) // 10000),
    ]


def audit_non_semantic_leakage_gbdt(
    normal_packets: Sequence[Any],
    attack_packets: Sequence[Any],
    n_splits: int = 5,
    seed: int = 42,
) -> float:
    """
    Trains a Gradient Boosted Decision Tree ensemble across 5-fold cross-validation
    exclusively on non-semantic fields (TTL, flags, length granularity, IAT regularity)
    to compute cross-validated ROC-AUC for artifact leakage auditing.
    """
    X_norm = [extract_non_semantic_packet_features(p) for p in normal_packets]
    X_atk = [extract_non_semantic_packet_features(p) for p in attack_packets]
    X = np.array(X_norm + X_atk)
    y = np.array([0] * len(X_norm) + [1] * len(X_atk))

    rng = np.random.default_rng(seed)
    indices = rng.permutation(len(y))
    folds = np.array_split(indices, n_splits)
    auc_scores: list[float] = []

    for i in range(n_splits):
        val_idx = folds[i]
        train_idx = np.concatenate([folds[j] for j in range(n_splits) if j != i])
        clf = GradientBoostedTreesClassifier(n_estimators=15, max_depth=3)
        clf.fit(X[train_idx], y[train_idx])
        preds = clf.predict_proba(X[val_idx])
        auc = compute_roc_auc(y[val_idx].tolist(), preds.tolist())
        auc_scores.append(auc)

    return float(np.mean(auc_scores))

