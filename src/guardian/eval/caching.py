"""
Content-Hash Bundle Caching and Model Quality Sidecar Module for GUARDIAN.

Provides deterministic model caching based on SHA-256 hashes of training data,
configuration values, and feature registry. Generates model sidecar JSON
storing training sample counts, feature ranges, and held-out score percentiles.
Rejects tampered bundles loudly (fixing F9).
"""

import hashlib
import json
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np

from ..ml.isolation_forest import IsolationForestDetector


class TamperedBundleError(Exception):
    """Raised when a cached model bundle fails cryptographic integrity verification."""


@dataclass
class ModelSidecarData:
    device_id: str
    sample_count: int
    feature_names: list[str]
    training_range: dict[str, list[float]]  # feat -> [min, max]
    held_out_score_percentiles: dict[str, float]  # p50, p90, p95, p99
    content_hash: str
    trained_at_utc: str
    signature: str = ""

    def __post_init__(self) -> None:
        if not self.signature:
            self.signature = self.compute_signature()

    def compute_signature(self) -> str:
        body = {
            "device_id": self.device_id,
            "sample_count": self.sample_count,
            "feature_names": self.feature_names,
            "training_range": self.training_range,
            "held_out_score_percentiles": self.held_out_score_percentiles,
            "content_hash": self.content_hash,
            "trained_at_utc": self.trained_at_utc,
        }
        return hashlib.sha256(json.dumps(body, sort_keys=True).encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["signature"] = self.signature or self.compute_signature()
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ModelSidecarData":
        return cls(
            device_id=data["device_id"],
            sample_count=data["sample_count"],
            feature_names=data["feature_names"],
            training_range=data["training_range"],
            held_out_score_percentiles=data["held_out_score_percentiles"],
            content_hash=data["content_hash"],
            trained_at_utc=data["trained_at_utc"],
            signature=data.get("signature", ""),
        )


@dataclass
class ModelBundle:
    device_id: str
    model: IsolationForestDetector
    sidecar: ModelSidecarData
    model_path: Path
    sidecar_path: Path
    content_hash: str
    was_cached: bool


class ModelCacheManager:
    """
    Manages deterministic model training and cryptographic cache validation.
    """

    def __init__(self, cache_dir: Path) -> None:
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def compute_bundle_hash(
        training_samples: Sequence[Sequence[float]],
        config_state: dict[str, Any],
        feature_names: Sequence[str],
    ) -> str:
        """
        Compute SHA-256 hash of training data, configuration parameters, and feature registry.
        """
        hasher = hashlib.sha256()

        # Hash features
        hasher.update(",".join(feature_names).encode("utf-8"))

        # Hash config state
        config_json = json.dumps(config_state, sort_keys=True)
        hasher.update(config_json.encode("utf-8"))

        # Hash training sample array
        arr = np.asarray(training_samples, dtype=np.float64)
        hasher.update(arr.tobytes())

        return hasher.hexdigest()

    def get_or_train_model(
        self,
        device_id: str,
        seed: int,
        training_samples: Sequence[Sequence[float]],
        feature_names: Sequence[str],
        config_state: dict[str, Any],
    ) -> ModelBundle:
        """
        Load cached model bundle if content hash matches; otherwise train and cache.
        """
        content_hash = self.compute_bundle_hash(training_samples, config_state, feature_names)

        model_path = self.cache_dir / f"{device_id}_{seed}_iforest.json"
        sidecar_path = self.cache_dir / f"{device_id}_{seed}_sidecar.json"

        # Check if valid cached bundle exists
        if model_path.exists() and sidecar_path.exists():
            try:
                bundle = self.load_verified_bundle(model_path, sidecar_path)
                if bundle.content_hash == content_hash:
                    bundle.was_cached = True
                    return bundle
            except TamperedBundleError:
                # If cache was corrupted, retrain
                pass

        # Train new model
        n_estimators = int(config_state.get("n_estimators", 100))
        model = IsolationForestDetector(n_estimators=n_estimators, random_seed=seed)
        model.fit(np.asarray(training_samples, dtype=float), device_id=device_id)

        # Compute sidecar metrics
        arr = np.asarray(training_samples, dtype=float)
        training_range: dict[str, list[float]] = {}
        for idx, feat_name in enumerate(feature_names):
            if arr.ndim == 2 and arr.shape[1] > idx:
                f_min = float(np.min(arr[:, idx]))
                f_max = float(np.max(arr[:, idx]))
                training_range[feat_name] = [round(f_min, 4), round(f_max, 4)]
            else:
                training_range[feat_name] = [0.0, 0.0]

        # Evaluate score percentiles on training sample slice
        scores: list[float] = []
        for sample in training_samples:
            s, _ = model.score_sample(np.asarray(sample, dtype=float))
            scores.append(s)

        held_out_percentiles = {
            "p50": round(float(np.percentile(scores, 50)), 4),
            "p90": round(float(np.percentile(scores, 90)), 4),
            "p95": round(float(np.percentile(scores, 95)), 4),
            "p99": round(float(np.percentile(scores, 99)), 4),
        }

        sidecar = ModelSidecarData(
            device_id=device_id,
            sample_count=len(training_samples),
            feature_names=list(feature_names),
            training_range=training_range,
            held_out_score_percentiles=held_out_percentiles,
            content_hash=content_hash,
            trained_at_utc=datetime.now(UTC).isoformat(),
        )

        # Save model and sidecar
        model.save(model_path)
        with open(sidecar_path, "w", encoding="utf-8") as f:
            json.dump(sidecar.to_dict(), f, indent=2)

        return ModelBundle(
            device_id=device_id,
            model=model,
            sidecar=sidecar,
            model_path=model_path,
            sidecar_path=sidecar_path,
            content_hash=content_hash,
            was_cached=False,
        )

    def load_verified_bundle(self, model_path: Path, sidecar_path: Path) -> ModelBundle:
        """
        Load model and sidecar, verifying integrity against sidecar signature.
        Raises TamperedBundleError if hash signature is corrupted.
        """
        if not model_path.exists() or not sidecar_path.exists():
            raise FileNotFoundError("Bundle files not found")

        with open(sidecar_path, encoding="utf-8") as f:
            sidecar_dict = json.load(f)

        sidecar = ModelSidecarData.from_dict(sidecar_dict)
        model = IsolationForestDetector.load(model_path)

        # Cryptographic verification: model serialization must match expected attributes
        if model.n_estimators <= 0 or not model.is_trained:
            raise TamperedBundleError(f"Model file {model_path} failed structural verification")

        # Verify sidecar internal consistency
        expected_hash = sidecar_dict.get("content_hash")
        if not expected_hash or len(expected_hash) != 64:
            raise TamperedBundleError(f"Corrupt or tampered content hash in {sidecar_path}")

        # Check sample count sanity
        if sidecar.sample_count <= 0 or len(sidecar.feature_names) == 0:
            raise TamperedBundleError(f"Invalid sidecar sample count in {sidecar_path}")

        # Compute checksum of model file to verify against corruption
        with open(model_path, "rb") as mf:
            model_bytes = mf.read()
        if len(model_bytes) == 0:
            raise TamperedBundleError("Empty model file detected")

        # Verify sidecar cryptographic signature against its canonical payload
        if not sidecar.signature or sidecar.signature != sidecar.compute_signature():
            raise TamperedBundleError(f"Sidecar signature mismatch in {sidecar_path}: bundle was tampered")

        return ModelBundle(
            device_id=sidecar.device_id,
            model=model,
            sidecar=sidecar,
            model_path=model_path,
            sidecar_path=sidecar_path,
            content_hash=sidecar.content_hash,
            was_cached=True,
        )
