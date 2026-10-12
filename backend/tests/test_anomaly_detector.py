"""
Tests for ML anomaly detection using Isolation Forest.
"""

import pytest
from datetime import datetime, timezone
import numpy as np

from app.ml.feature_extraction import PackageFeatures, extract_features
from app.ml.anomaly_detector import (
    AnomalyDetector,
    AnomalyResult,
    detect_anomalies,
    integrate_with_risk_assessment,
    FEATURE_NAMES,
)

# Fixed reference time for deterministic tests
REFERENCE_TIME = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)


def _make_features(
    name: str,
    version: str,
    features: dict[str, float | None],
    availability: dict[str, bool] | None = None,
) -> PackageFeatures:
    """Create a PackageFeatures object with specified feature values."""
    if availability is None:
        availability = {k: v is not None for k, v in features.items()}

    return PackageFeatures(
        package_name=name,
        supplied_version=version,
        version_precision="resolved",
        features=features,
        feature_availability=availability,
        reference_timestamp=REFERENCE_TIME.isoformat(),
    )


class TestAnomalyDetectorInit:
    def test_default_initialization(self):
        detector = AnomalyDetector()
        assert detector.n_estimators == 100
        assert detector.contamination == 0.1
        assert detector.random_state == 42
        assert detector.is_trained is False
        assert detector.training_size == 0

    def test_custom_parameters(self):
        detector = AnomalyDetector(
            n_estimators=50,
            contamination=0.05,
            random_state=123,
        )
        assert detector.n_estimators == 50
        assert detector.contamination == 0.05
        assert detector.random_state == 123


class TestTraining:
    def test_train_requires_minimum_samples(self):
        detector = AnomalyDetector()

        # Only 1 valid sample
        features = [
            _make_features("pkg1", "1.0.0", {k: 1.0 for k in FEATURE_NAMES}),
        ]

        with pytest.raises(ValueError, match="Insufficient training data"):
            detector.train(features)

    def test_train_with_valid_data(self):
        detector = AnomalyDetector(random_state=42)

        # 10 valid samples with varying features
        features = []
        for i in range(10):
            f = {
                "days_since_previous_release": float(10 * i),
                "release_gap_ratio": float(1.0 + 0.1 * i),
                "package_age_days": float(100 * i),
                "release_frequency_90d": float(i % 3),
            }
            features.append(_make_features(f"pkg{i}", "1.0.0", f))

        result = detector.train(features)

        assert detector.is_trained is True
        assert detector.training_size == 10
        assert result["status"] == "trained"
        assert result["training_samples"] == 10
        assert result["features_used"] == FEATURE_NAMES

    def test_train_skips_incomplete_samples(self):
        detector = AnomalyDetector(random_state=42)

        features = [
            # Complete sample
            _make_features("pkg1", "1.0.0", {k: 1.0 for k in FEATURE_NAMES}),
            # Missing one feature
            _make_features(
                "pkg2", "1.0.0",
                {**{k: 1.0 for k in FEATURE_NAMES}, "release_gap_ratio": None},
                {**{k: True for k in FEATURE_NAMES}, "release_gap_ratio": False},
            ),
            # Complete sample
            _make_features("pkg3", "1.0.0", {k: 2.0 for k in FEATURE_NAMES}),
        ]

        result = detector.train(features)

        assert detector.training_size == 2  # Only 2 complete samples


class TestPrediction:
    def test_predict_before_training_returns_unavailable(self):
        detector = AnomalyDetector(random_state=42)

        features = _make_features("test", "1.0.0", {k: 1.0 for k in FEATURE_NAMES})
        result = detector.predict(features)

        assert result.status == "unavailable"
        assert result.anomaly_score is None
        assert result.is_anomalous is None
        assert result.model_trained is False
        assert "not trained" in result.explanation.lower()

    def test_predict_after_training(self):
        detector = AnomalyDetector(random_state=42)

        # Train with diverse baseline
        baseline = []
        for i in range(20):
            f = {
                "days_since_previous_release": float(30 * i),
                "release_gap_ratio": float(1.0 + 0.05 * i),
                "package_age_days": float(100 * i),
                "release_frequency_90d": float(i % 5),
            }
            baseline.append(_make_features(f"base{i}", "1.0.0", f))

        detector.train(baseline)

        # Test with a normal sample
        test_features = _make_features("test", "1.0.0", {
            "days_since_previous_release": 150.0,
            "release_gap_ratio": 1.5,
            "package_age_days": 1500.0,
            "release_frequency_90d": 2.0,
        })

        result = detector.predict(test_features)

        assert result.status in ("analyzed", "inconclusive")
        assert result.anomaly_score is not None
        assert result.is_anomalous is not None
        assert result.model_trained is True
        assert len(result.features_used) == 4

    def test_predict_with_missing_features_returns_inconclusive(self):
        detector = AnomalyDetector(random_state=42)

        # Train with full features
        baseline = []
        for i in range(20):
            f = {k: float(i * 10 + idx) for idx, k in enumerate(FEATURE_NAMES)}
            baseline.append(_make_features(f"base{i}", "1.0.0", f))

        detector.train(baseline)

        # Test with only 2 features available
        test_features = _make_features("test", "1.0.0", {
            "days_since_previous_release": 100.0,
            "release_gap_ratio": 1.5,
            "package_age_days": None,
            "release_frequency_90d": None,
        }, {
            "days_since_previous_release": True,
            "release_gap_ratio": True,
            "package_age_days": False,
            "release_frequency_90d": False,
        })

        result = detector.predict(test_features)

        assert result.status == "inconclusive"
        assert len(result.features_used) == 2
        assert result.model_trained is True

    def test_predict_with_all_missing_features(self):
        detector = AnomalyDetector(random_state=42)

        baseline = [
            _make_features(f"base{i}", "1.0.0", {k: float(i) for k in FEATURE_NAMES})
            for i in range(10)
        ]
        detector.train(baseline)

        # No features available
        test_features = _make_features("test", "1.0.0", {
            k: None for k in FEATURE_NAMES
        }, {k: False for k in FEATURE_NAMES})

        result = detector.predict(test_features)

        assert result.status == "inconclusive"
        assert result.anomaly_score is None
        assert len(result.features_used) == 0

    def test_deterministic_with_fixed_seed(self):
        """Same training data + same seed = same results."""
        baseline = [
            _make_features(f"base{i}", "1.0.0", {k: float(i * 10 + idx) for idx, k in enumerate(FEATURE_NAMES)})
            for i in range(20)
        ]

        detector1 = AnomalyDetector(random_state=42)
        detector1.train(baseline)

        detector2 = AnomalyDetector(random_state=42)
        detector2.train(baseline)

        test_features = _make_features("test", "1.0.0", {k: 50.0 for k in FEATURE_NAMES})

        result1 = detector1.predict(test_features)
        result2 = detector2.predict(test_features)

        assert result1.anomaly_score == result2.anomaly_score
        assert result1.is_anomalous == result2.is_anomalous


class TestConvenienceFunction:
    def test_detect_anomalies_with_baseline(self):
        baseline = [
            _make_features(f"base{i}", "1.0.0", {k: float(i * 10 + idx) for idx, k in enumerate(FEATURE_NAMES)})
            for i in range(20)
        ]

        test_features = [
            _make_features("test1", "1.0.0", {k: 50.0 for k in FEATURE_NAMES}),
            _make_features("test2", "1.0.0", {k: 500.0 for k in FEATURE_NAMES}),  # outlier
        ]

        results = detect_anomalies(test_features, baseline_features=baseline, random_state=42)

        assert len(results) == 2
        for r in results:
            assert r.status in ("analyzed", "inconclusive")
            assert r.model_trained is True

    def test_detect_anomalies_without_baseline(self):
        """Training on test data itself (not recommended but supported)."""
        test_features = [
            _make_features(f"pkg{i}", "1.0.0", {k: float(i * 10 + idx) for idx, k in enumerate(FEATURE_NAMES)})
            for i in range(20)
        ]

        results = detect_anomalies(test_features, baseline_features=None, random_state=42)

        assert len(results) == 20
        for r in results:
            assert r.model_trained is True


class TestIntegrationWithRiskAssessment:
    def test_integration_preserves_vulnerability_override(self):
        """ML 'normal' result must not override confirmed vulnerability."""
        # Mock risk assessment with confirmed vulnerability
        class MockRisk:
            def __init__(self):
                self.package_name = "vulnerable-pkg"
                self.supplied_version = "1.0.0"
                self.version_resolution_status = "resolved"
                self.heuristic_risk_score = 50
                self.signals = [
                    {"rule": "KNOWN_VULNERABILITY", "status": "confirmed", "points": 50},
                    {"rule": "EXTENDED_DORMANCY", "status": "not_detected", "points": 0},
                ]
                self.supporting_advisory_ids = ["GHSA-123"]
                self.assessment_complete = True
                self.recommended_next_action = "High risk detected."

        # Mock anomaly result showing normal
        class MockAnomaly:
            def __init__(self):
                self.package_name = "vulnerable-pkg"
                self.anomaly_score = -0.5  # normal
                self.is_anomalous = False
                self.status = "analyzed"
                self.explanation = "Normal pattern"
                self.features_used = FEATURE_NAMES
                self.model_trained = True

        risks = [MockRisk()]
        anomalies = [MockAnomaly()]

        combined = integrate_with_risk_assessment(risks, anomalies)

        assert len(combined) == 1
        c = combined[0]
        assert c["ml_anomaly"]["is_anomalous"] is False
        assert "does not override" in c["ml_anomaly"]["note"]

    def test_integration_without_vulnerability(self):
        """ML anomaly adds information when no confirmed vulnerability."""
        class MockRisk:
            def __init__(self):
                self.package_name = "normal-pkg"
                self.supplied_version = "1.0.0"
                self.version_resolution_status = "resolved"
                self.heuristic_risk_score = 10
                self.signals = [
                    {"rule": "KNOWN_VULNERABILITY", "status": "not_detected", "points": 0},
                ]
                self.supporting_advisory_ids = []
                self.assessment_complete = True
                self.recommended_next_action = "Low risk."

        class MockAnomaly:
            def __init__(self):
                self.package_name = "normal-pkg"
                self.anomaly_score = 0.8  # anomalous
                self.is_anomalous = True
                self.status = "analyzed"
                self.explanation = "Anomalous pattern"
                self.features_used = FEATURE_NAMES
                self.model_trained = True

        risks = [MockRisk()]
        anomalies = [MockAnomaly()]

        combined = integrate_with_risk_assessment(risks, anomalies)

        c = combined[0]
        assert c["ml_anomaly"]["is_anomalous"] is True
        assert "note" not in c["ml_anomaly"]

    def test_integration_missing_anomaly(self):
        """Package with no anomaly result gets unavailable status."""
        class MockRisk:
            def __init__(self):
                self.package_name = "no-ml-pkg"
                self.supplied_version = "1.0.0"
                self.version_resolution_status = "resolved"
                self.heuristic_risk_score = 0
                self.signals = []
                self.supporting_advisory_ids = []
                self.assessment_complete = True
                self.recommended_next_action = "Continue monitoring."

        risks = [MockRisk()]
        anomalies = []  # Empty

        combined = integrate_with_risk_assessment(risks, anomalies)

        c = combined[0]
        assert c["ml_anomaly"]["status"] == "unavailable"


class TestIntegrationWithFeatureExtractor:
    def test_end_to_end_with_real_feature_extractor(self):
        """Test full pipeline: feature extraction -> anomaly detection."""
        from app.graph.builder import build_graph_from_api_response
        from app.ml.feature_extraction import extract_features_batch

        # Minimal API response with known release patterns
        # Both packages need >=3 releases to have all 4 features available
        response = {
            "transaction_hash": "test",
            "dependencies": [
                {
                    "package": "normal-pkg",
                    "version": "1.0.0",
                    "vulnerabilities": [],
                    "npm_metadata": {
                        "maintainers": [],
                        "times": {
                            "1.0.0": "2020-01-01T00:00:00Z",
                            "1.1.0": "2020-02-01T00:00:00Z",
                            "1.2.0": "2020-03-01T00:00:00Z",
                            "2.0.0": "2020-04-01T00:00:00Z",
                        },
                    },
                },
                {
                    "package": "dormant-pkg",
                    "version": "1.0.0",
                    "vulnerabilities": [],
                    "npm_metadata": {
                        "maintainers": [],
                        "times": {
                            "1.0.0": "2018-01-01T00:00:00Z",
                            "1.1.0": "2018-06-01T00:00:00Z",
                            "2.0.0": "2024-01-01T00:00:00Z",  # 6 year gap after 1.1.0
                        },
                    },
                },
            ],
        }

        # Extract features
        features_list = extract_features_batch(response, REFERENCE_TIME)

        # Run anomaly detection (train on the same data for this test)
        results = detect_anomalies(features_list, baseline_features=features_list, random_state=42)

        assert len(results) == 2
        names = {r.package_name for r in results}
        assert names == {"normal-pkg", "dormant-pkg"}

        # Both should have model trained
        for r in results:
            assert r.model_trained is True


class TestEdgeCases:
    def test_empty_feature_list(self):
        detector = AnomalyDetector(random_state=42)

        with pytest.raises(ValueError, match="Insufficient training data"):
            detector.train([])

    def test_single_complete_feature(self):
        detector = AnomalyDetector(random_state=42)

        features = [
            _make_features("pkg1", "1.0.0", {k: 1.0 for k in FEATURE_NAMES}),
        ]

        with pytest.raises(ValueError, match="Insufficient training data"):
            detector.train(features)

    def test_feature_order_consistency(self):
        """Ensure feature order is consistent between training and inference."""
        detector = AnomalyDetector(random_state=42)

        baseline = [
            _make_features(f"base{i}", "1.0.0", {k: float(i * 10 + idx) for idx, k in enumerate(FEATURE_NAMES)})
            for i in range(10)
        ]
        detector.train(baseline)

        # The model should expect features in FEATURE_NAMES order
        assert hasattr(detector._model, "n_features_in_")
        assert detector._model.n_features_in_ == len(FEATURE_NAMES)