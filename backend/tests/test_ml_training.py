"""
Unit and integration tests for ML CSV feature loading, training, and model persistence.
"""

from pathlib import Path
import pytest

from app.ml.anomaly_detector import (
    AnomalyDetector,
    FEATURE_NAMES,
    get_default_model,
)
from app.ml.feature_extraction import (
    PackageFeatures,
    load_features_from_csv,
)

CSV_PATH = Path(__file__).resolve().parent.parent.parent / "traceroot_real_features.csv"


class TestCSVFeatureLoading:
    def test_load_features_from_csv_all(self):
        features = load_features_from_csv(CSV_PATH, usable_only=False)
        assert len(features) == 1000

        # Verify structure
        first = features[0]
        assert isinstance(first, PackageFeatures)
        assert first.package_name != ""
        assert first.supplied_version != ""
        assert set(first.features.keys()) == set(FEATURE_NAMES)

        # Count complete vs incomplete
        complete = [
            f for f in features
            if all(f.feature_availability.get(k, False) for k in FEATURE_NAMES)
        ]
        incomplete = [
            f for f in features
            if not all(f.feature_availability.get(k, False) for k in FEATURE_NAMES)
        ]
        assert len(complete) == 763
        assert len(incomplete) == 237

    def test_load_features_from_csv_usable_only(self):
        features = load_features_from_csv(CSV_PATH, usable_only=True)
        assert len(features) == 763

        for f in features:
            for fname in FEATURE_NAMES:
                assert f.feature_availability[fname] is True
                assert f.features[fname] is not None

    def test_load_features_from_csv_nonexistent_raises(self):
        with pytest.raises(FileNotFoundError, match="Feature CSV not found"):
            load_features_from_csv("non_existent_file.csv")


class TestCSVTraining:
    def test_train_from_csv(self):
        detector = AnomalyDetector(contamination=0.1, random_state=42)
        meta = detector.train_from_csv(CSV_PATH, usable_only=True)

        assert detector.is_trained is True
        assert detector.training_size == 763
        assert meta["status"] == "trained"
        assert meta["training_samples"] == 763
        assert meta["features_used"] == FEATURE_NAMES

    def test_train_from_csv_predict(self):
        detector = AnomalyDetector(contamination=0.1, random_state=42)
        detector.train_from_csv(CSV_PATH, usable_only=True)

        features = load_features_from_csv(CSV_PATH, usable_only=True)
        sample = features[0]

        result = detector.predict(sample)
        assert result.status in ("analyzed", "inconclusive")
        assert result.anomaly_score is not None
        assert isinstance(result.is_anomalous, bool)
        assert result.model_trained is True


class TestModelPersistence:
    def test_save_and_load_round_trip(self, tmp_path):
        detector = AnomalyDetector(contamination=0.08, random_state=123)
        detector.train_from_csv(CSV_PATH, usable_only=True)

        model_file = tmp_path / "test_model.joblib"
        detector.save_model(model_file)
        assert model_file.is_file()

        # Load back
        loaded = AnomalyDetector.load_model(model_file)
        assert loaded.is_trained is True
        assert loaded.training_size == 763
        assert loaded.contamination == 0.08
        assert loaded.random_state == 123

        # Compare predictions
        features = load_features_from_csv(CSV_PATH, usable_only=True)
        for sample in features[:10]:
            orig_res = detector.predict(sample)
            loaded_res = loaded.predict(sample)
            assert orig_res.anomaly_score == loaded_res.anomaly_score
            assert orig_res.is_anomalous == loaded_res.is_anomalous

    def test_save_untrained_raises(self, tmp_path):
        detector = AnomalyDetector()
        with pytest.raises(ValueError, match="Cannot save an untrained AnomalyDetector"):
            detector.save_model(tmp_path / "dummy.joblib")

    def test_load_nonexistent_raises(self):
        with pytest.raises(FileNotFoundError, match="Model file not found"):
            AnomalyDetector.load_model("nonexistent_model.joblib")


class TestDefaultBaselineModel:
    def test_get_default_model(self):
        model = get_default_model()
        assert model.is_trained is True
        assert model.training_size == 763

        # Inference with baseline model
        sample = PackageFeatures(
            package_name="express",
            supplied_version="4.18.2",
            version_precision="resolved",
            features={
                "days_since_previous_release": 30.0,
                "release_gap_ratio": 1.2,
                "package_age_days": 3500.0,
                "release_frequency_90d": 1.0,
            },
            feature_availability={
                "days_since_previous_release": True,
                "release_gap_ratio": True,
                "package_age_days": True,
                "release_frequency_90d": True,
            },
            reference_timestamp="2026-01-01T00:00:00Z",
        )
        res = model.predict(sample)
        assert res.status == "analyzed"
        assert res.anomaly_score is not None
        assert res.model_trained is True
