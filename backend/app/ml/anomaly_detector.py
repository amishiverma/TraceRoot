"""
ML anomaly detection using Isolation Forest for npm package release behaviour.

This module provides anomaly detection capabilities that supplement the
existing heuristic risk engine. It identifies unusual release patterns
using numerical features extracted from npm package metadata.

IMPORTANT: ML results never override confirmed OSV vulnerabilities.
"""

from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from app.ml.feature_extraction import PackageFeatures, load_features_from_csv


DEFAULT_MODEL_PATH = Path(__file__).parent / "models" / "baseline_model.joblib"


# Fixed feature order for consistent training/inference
FEATURE_NAMES = [
    "days_since_previous_release",
    "release_gap_ratio",
    "package_age_days",
    "release_frequency_90d",
]


@dataclass
class AnomalyResult:
    """Result of anomaly detection for a single package."""
    package_name: str
    supplied_version: str
    anomaly_score: float | None
    is_anomalous: bool | None
    status: str  # "analyzed", "inconclusive", "unavailable"
    explanation: str
    features_used: list[str]
    model_trained: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AnomalyDetector:
    """
    Isolation Forest based anomaly detector for npm package release patterns.

    The detector is trained on a baseline dataset of package features and
    then used to score new packages. Training and inference are separate
    operations to avoid training on the package being assessed.
    """

    def __init__(
        self,
        n_estimators: int = 100,
        max_samples: str | int = "auto",
        contamination: float = 0.1,
        random_state: int = 42,
    ):
        """
        Initialize the anomaly detector.

        Args:
            n_estimators: Number of base estimators in the ensemble
            max_samples: Number of samples to draw for each tree
            contamination: Expected proportion of anomalies in data (0-0.5)
            random_state: Random seed for deterministic results
        """
        self.n_estimators = n_estimators
        self.max_samples = max_samples
        self.contamination = contamination
        self.random_state = random_state

        self._model: IsolationForest | None = None
        self._is_trained = False
        self._training_size = 0

    @property
    def is_trained(self) -> bool:
        """Check if the model has been trained."""
        return self._is_trained

    @property
    def training_size(self) -> int:
        """Number of samples used for training."""
        return self._training_size

    def train(self, feature_list: list[PackageFeatures]) -> dict[str, Any]:
        """
        Train the Isolation Forest model on baseline package features.

        Args:
            feature_list: List of PackageFeatures from baseline packages

        Returns:
            Training metadata including number of samples and features used

        Raises:
            ValueError: If insufficient valid training data
        """
        X, valid_indices = self._prepare_training_data(feature_list)

        if len(X) < 2:
            raise ValueError(
                f"Insufficient training data: {len(X)} valid samples "
                "(minimum 2 required for Isolation Forest)"
            )

        self._model = IsolationForest(
            n_estimators=self.n_estimators,
            max_samples=self.max_samples,
            contamination=self.contamination,
            random_state=self.random_state,
        )
        self._model.fit(X)
        self._is_trained = True
        self._training_size = len(X)

        return {
            "status": "trained",
            "training_samples": len(X),
            "features_used": FEATURE_NAMES,
            "contamination": self.contamination,
        }

    def train_from_csv(
        self,
        csv_path: str | Path,
        usable_only: bool = True,
    ) -> dict[str, Any]:
        """
        Load features from a CSV file and train the Isolation Forest model.

        Args:
            csv_path: Path to the feature CSV file.
            usable_only: If True, only loads rows where data_status == 'usable'.

        Returns:
            Training metadata.
        """
        features = load_features_from_csv(csv_path, usable_only=usable_only)
        return self.train(features)

    def predict(self, features: PackageFeatures) -> AnomalyResult:
        """
        Predict anomaly for a single package.

        Args:
            features: PackageFeatures for the package to analyze

        Returns:
            AnomalyResult with score, status, and explanation
        """
        # Check if model is trained
        if not self._is_trained or self._model is None:
            return AnomalyResult(
                package_name=features.package_name,
                supplied_version=features.supplied_version,
                anomaly_score=None,
                is_anomalous=None,
                status="unavailable",
                explanation="Model not trained. Call train() with baseline data first.",
                features_used=[],
                model_trained=False,
            )

        # Prepare feature vector
        X, valid_features = self._prepare_inference_vector(features)

        if len(valid_features) == 0:
            return AnomalyResult(
                package_name=features.package_name,
                supplied_version=features.supplied_version,
                anomaly_score=None,
                is_anomalous=None,
                status="inconclusive",
                explanation="No valid numerical features available for analysis.",
                features_used=[],
                model_trained=True,
            )

        # Get anomaly score (lower = more anomalous)
        # decision_function returns higher values for normal points
        scores = self._model.decision_function(X)
        anomaly_score = float(-scores[0])  # Invert so higher = more anomalous

        # Predict anomaly (1 = normal, -1 = anomaly)
        prediction = self._model.predict(X)[0]
        is_anomalous = bool(prediction == -1)

        # Determine status
        if len(valid_features) < len(FEATURE_NAMES):
            status = "inconclusive"
            explanation = (
                f"Only {len(valid_features)}/{len(FEATURE_NAMES)} features available. "
                "Results may be less reliable."
            )
        else:
            status = "analyzed"
            explanation = (
                f"Anomaly score: {anomaly_score:.4f}. "
                f"{'Anomalous' if is_anomalous else 'Normal'} release pattern."
            )

        return AnomalyResult(
            package_name=features.package_name,
            supplied_version=features.supplied_version,
            anomaly_score=anomaly_score,
            is_anomalous=is_anomalous,
            status=status,
            explanation=explanation,
            features_used=valid_features,
            model_trained=True,
        )

    def predict_batch(self, feature_list: list[PackageFeatures]) -> list[AnomalyResult]:
        """
        Predict anomalies for multiple packages.

        Args:
            feature_list: List of PackageFeatures to analyze

        Returns:
            List of AnomalyResult objects
        """
        return [self.predict(f) for f in feature_list]

    def save_model(self, file_path: str | Path) -> None:
        """
        Persist the trained Isolation Forest detector state to disk.

        Args:
            file_path: Target path to save the model artifact (e.g. baseline_model.joblib).

        Raises:
            ValueError: If the detector is not yet trained.
        """
        if not self._is_trained or self._model is None:
            raise ValueError("Cannot save an untrained AnomalyDetector.")

        path = Path(file_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        state = {
            "model": self._model,
            "n_estimators": self.n_estimators,
            "max_samples": self.max_samples,
            "contamination": self.contamination,
            "random_state": self.random_state,
            "training_size": self._training_size,
            "feature_names": FEATURE_NAMES,
        }
        joblib.dump(state, path)

    @classmethod
    def load_model(cls, file_path: str | Path) -> "AnomalyDetector":
        """
        Load a persisted AnomalyDetector state from disk.

        Args:
            file_path: Path to the saved model artifact.

        Returns:
            An initialized and trained AnomalyDetector instance.

        Raises:
            FileNotFoundError: If the model file does not exist.
        """
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"Model file not found at: {file_path}")

        state = joblib.load(path)
        detector = cls(
            n_estimators=state.get("n_estimators", 100),
            max_samples=state.get("max_samples", "auto"),
            contamination=state.get("contamination", 0.1),
            random_state=state.get("random_state", 42),
        )
        detector._model = state["model"]
        detector._is_trained = True
        detector._training_size = state.get("training_size", 0)
        return detector

    def _prepare_training_data(
        self, feature_list: list[PackageFeatures]
    ) -> tuple[np.ndarray, list[int]]:
        """
        Extract valid feature vectors from training data.

        Only uses samples where all features are available.
        """
        X_rows = []
        valid_indices = []

        for idx, features in enumerate(feature_list):
            row = []
            all_available = True
            for fname in FEATURE_NAMES:
                val = features.features.get(fname)
                avail = features.feature_availability.get(fname, False)
                if val is None or not avail:
                    all_available = False
                    break
                row.append(float(val))

            if all_available:
                X_rows.append(row)
                valid_indices.append(idx)

        if not X_rows:
            return np.array([]).reshape(0, len(FEATURE_NAMES)), []

        return np.array(X_rows), valid_indices

    def _prepare_inference_vector(
        self, features: PackageFeatures
    ) -> tuple[np.ndarray, list[str]]:
        """
        Extract feature vector for inference, handling missing values.

        For missing features, uses the median from training data if available,
        otherwise skips the feature.
        """
        if self._model is None or not hasattr(self._model, "estimators_"):
            return np.array([]).reshape(0, len(FEATURE_NAMES)), []

        # For inference, we need to handle missing features.
        # Strategy: use available features only, but IsolationForest expects fixed dimensions.
        # We'll impute missing values with 0 (neutral) and track which were imputed.
        row = []
        valid_features = []

        for fname in FEATURE_NAMES:
            val = features.features.get(fname)
            avail = features.feature_availability.get(fname, False)
            if val is not None and avail:
                row.append(float(val))
                valid_features.append(fname)
            else:
                row.append(0.0)  # Neutral imputation

        return np.array(row).reshape(1, -1), valid_features


def detect_anomalies(
    feature_list: list[PackageFeatures],
    baseline_features: list[PackageFeatures] | None = None,
    contamination: float = 0.1,
    random_state: int = 42,
) -> list[AnomalyResult]:
    """
    Convenience function to train (if baseline provided) and detect anomalies.

    Args:
        feature_list: Packages to analyze
        baseline_features: Optional baseline packages for training.
                           If None, uses feature_list itself (with warning).
        contamination: Expected anomaly proportion
        random_state: Random seed for determinism

    Returns:
        List of AnomalyResult for each package
    """
    detector = AnomalyDetector(
        contamination=contamination,
        random_state=random_state,
    )

    if baseline_features is not None:
        detector.train(baseline_features)
    else:
        # Train on the same data (not recommended for production)
        detector.train(feature_list)

    return detector.predict_batch(feature_list)


def get_default_model(model_path: str | Path | None = None) -> AnomalyDetector:
    """
    Load the default pre-trained baseline model.

    Args:
        model_path: Optional path to baseline model. Defaults to
                    backend/app/ml/models/baseline_model.joblib.

    Returns:
        Trained AnomalyDetector instance.

    Raises:
        FileNotFoundError: If the model artifact does not exist.
    """
    target = Path(model_path) if model_path is not None else DEFAULT_MODEL_PATH
    if not target.is_file():
        raise FileNotFoundError(
            f"Pre-trained model artifact not found at: {target}. "
            "Run training script (python -m app.ml.train) to generate the baseline model."
        )
    return AnomalyDetector.load_model(target)


def integrate_with_risk_assessment(
    risk_assessments: list[Any],
    anomaly_results: list[AnomalyResult],
) -> list[dict[str, Any]]:
    """
    Combine heuristic risk assessments with ML anomaly results.

    ML anomalies supplement but never override confirmed vulnerabilities.

    Args:
        risk_assessments: List of RiskAssessment objects from heuristic engine
        anomaly_results: List of AnomalyResult objects from ML detector

    Returns:
        List of combined assessment dictionaries
    """
    # Create lookup for anomaly results by package name
    anomaly_map = {a.package_name: a for a in anomaly_results}

    combined = []
    for risk in risk_assessments:
        anomaly = anomaly_map.get(risk.package_name)

        # Base assessment
        combined_assessment = {
            "package_name": risk.package_name,
            "supplied_version": risk.supplied_version,
            "version_resolution_status": risk.version_resolution_status,
            "heuristic_risk_score": risk.heuristic_risk_score,
            "heuristic_signals": risk.signals,
            "supporting_advisory_ids": risk.supporting_advisory_ids,
            "assessment_complete": risk.assessment_complete,
            "recommended_next_action": risk.recommended_next_action,
        }

        # Add ML results if available
        if anomaly:
            combined_assessment["ml_anomaly"] = {
                "anomaly_score": anomaly.anomaly_score,
                "is_anomalous": anomaly.is_anomalous,
                "status": anomaly.status,
                "explanation": anomaly.explanation,
                "features_used": anomaly.features_used,
                "model_trained": anomaly.model_trained,
            }

            # ML supplements but never downgrades confirmed vulnerabilities
            # Check if any vulnerability signal is confirmed
            has_confirmed_vuln = any(
                s.get("rule") == "KNOWN_VULNERABILITY" and s.get("status") == "confirmed"
                for s in risk.signals
            )

            if has_confirmed_vuln and anomaly.is_anomalous is False:
                # Don't let ML "normal" override confirmed vulnerability
                combined_assessment["ml_anomaly"]["note"] = (
                    "ML anomaly score does not override confirmed OSV vulnerability"
                )

        else:
            combined_assessment["ml_anomaly"] = {
                "status": "unavailable",
                "explanation": "No ML anomaly result for this package",
            }

        combined.append(combined_assessment)

    return combined