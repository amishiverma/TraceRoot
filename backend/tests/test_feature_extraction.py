"""
Tests for ML feature extraction from npm release history.

Uses deterministic fixtures with a fixed reference timestamp.
"""

import pytest
from datetime import datetime, timezone
from app.ml.feature_extraction import (
    PackageFeatures,
    extract_features,
    extract_features_batch,
    _extract_release_timestamps,
    _parse_iso_timestamp,
)
from app.graph.builder import build_graph_from_api_response


# Fixed reference time for deterministic tests
REFERENCE_TIME = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)


def _make_node(
    name="testpkg",
    version="1.0.0",
    version_precision="resolved",
    npm_times=None,
    npm_maintainers=None,
):
    """Build a node_data dict as produced by build_graph_from_api_response."""
    return {
        "name": name,
        "version": version,
        "version_precision": version_precision,
        "npm_maintainers": npm_maintainers or [],
        "npm_times": npm_times or {},
        "incomplete": True,
    }


class TestTimestampParsing:
    def test_valid_iso_timestamp(self):
        ts = "2024-01-15T10:30:00Z"
        result = _parse_iso_timestamp(ts)
        assert result is not None
        assert result.year == 2024
        assert result.month == 1
        assert result.day == 15

    def test_invalid_timestamp(self):
        assert _parse_iso_timestamp("not-a-timestamp") is None
        assert _parse_iso_timestamp("") is None
        assert _parse_iso_timestamp(None) is None


class TestReleaseTimestampExtraction:
    def test_excludes_created_and_modified(self):
        npm_times = {
            "created": "2020-01-01T00:00:00Z",
            "modified": "2026-01-01T00:00:00Z",
            "1.0.0": "2020-01-01T00:00:00Z",
            "2.0.0": "2022-01-01T00:00:00Z",
        }
        releases = _extract_release_timestamps(npm_times)
        assert len(releases) == 2
        assert releases[0][0] == "1.0.0"
        assert releases[1][0] == "2.0.0"

    def test_chronological_sorting(self):
        npm_times = {
            "2.0.0": "2022-01-01T00:00:00Z",
            "1.0.0": "2020-01-01T00:00:00Z",
            "1.5.0": "2021-06-01T00:00:00Z",
        }
        releases = _extract_release_timestamps(npm_times)
        assert len(releases) == 3
        assert releases[0][0] == "1.0.0"
        assert releases[1][0] == "1.5.0"
        assert releases[2][0] == "2.0.0"

    def test_invalid_timestamps_ignored(self):
        npm_times = {
            "1.0.0": "invalid-timestamp",
            "2.0.0": "2022-01-01T00:00:00Z",
        }
        releases = _extract_release_timestamps(npm_times)
        assert len(releases) == 1
        assert releases[0][0] == "2.0.0"

    def test_empty_npm_times(self):
        releases = _extract_release_timestamps({})
        assert releases == []


class TestFeatureExtraction:
    def test_valid_release_history(self):
        npm_times = {
            "1.0.0": "2020-01-01T00:00:00Z",
            "1.1.0": "2021-01-01T00:00:00Z",
            "2.0.0": "2023-01-01T00:00:00Z",
            "2.1.0": "2025-01-01T00:00:00Z",
        }
        node = _make_node(name="testpkg", version="2.1.0", npm_times=npm_times)
        features = extract_features(node, REFERENCE_TIME)

        assert isinstance(features, PackageFeatures)
        assert features.package_name == "testpkg"
        assert features.supplied_version == "2.1.0"
        assert features.reference_timestamp == REFERENCE_TIME.isoformat()

        # package_age_days: from 2020-01-01 to 2026-01-15 = ~2207 days
        assert features.feature_availability["package_age_days"] is True
        assert features.features["package_age_days"] is not None
        assert features.features["package_age_days"] > 2000

        # days_since_previous_release: from 2025-01-01 to 2026-01-15 = ~380 days
        assert features.feature_availability["days_since_previous_release"] is True
        assert features.features["days_since_previous_release"] is not None
        assert features.features["days_since_previous_release"] > 300

        # release_gap_ratio: available (>=3 releases)
        assert features.feature_availability["release_gap_ratio"] is True
        assert features.features["release_gap_ratio"] is not None

        # release_frequency_90d: from 2025-01-01 to 2026-01-15 is ~380 days, NOT within 90 days
        assert features.feature_availability["release_frequency_90d"] is True
        assert features.features["release_frequency_90d"] == 0.0

    def test_chronological_sorting_in_features(self):
        """Ensure releases are sorted chronologically before feature calculation."""
        npm_times = {
            "2.0.0": "2022-01-01T00:00:00Z",
            "1.0.0": "2020-01-01T00:00:00Z",
        }
        node = _make_node(npm_times=npm_times)
        features = extract_features(node, REFERENCE_TIME)

        # First release should be 1.0.0 (2020), not 2.0.0
        assert features.feature_availability["package_age_days"] is True
        assert features.features["package_age_days"] > 2000

    def test_long_release_gap_detected(self):
        """Package with a long gap between releases."""
        npm_times = {
            "1.0.0": "2018-01-01T00:00:00Z",
            "1.1.0": "2019-01-01T00:00:00Z",
            "2.0.0": "2024-01-01T00:00:00Z",  # 5-year gap after 1.1.0
        }
        node = _make_node(npm_times=npm_times)
        features = extract_features(node, REFERENCE_TIME)

        assert features.feature_availability["release_gap_ratio"] is True
        # Max gap is ~1826 days, mean gap is ~(365 + 1826)/2 = 1095, ratio ~1.66
        assert features.features["release_gap_ratio"] > 1.0

    def test_empty_release_history(self):
        """No npm_times -> all features unavailable."""
        node = _make_node(npm_times={})
        features = extract_features(node, REFERENCE_TIME)

        for key in features.features:
            assert features.features[key] is None
            assert features.feature_availability[key] is False

    def test_invalid_timestamps_handled(self):
        """Invalid timestamps should be skipped, not crash."""
        npm_times = {
            "1.0.0": "invalid",
            "2.0.0": "2024-01-01T00:00:00Z",
        }
        node = _make_node(npm_times=npm_times)
        features = extract_features(node, REFERENCE_TIME)

        # Only one valid release
        assert features.feature_availability["package_age_days"] is True
        assert features.feature_availability["days_since_previous_release"] is True
        assert features.feature_availability["release_gap_ratio"] is False  # < 3 releases

    def test_one_release_package(self):
        """Package with only one release."""
        npm_times = {
            "1.0.0": "2024-01-01T00:00:00Z",
        }
        node = _make_node(npm_times=npm_times)
        features = extract_features(node, REFERENCE_TIME)

        assert features.feature_availability["package_age_days"] is True
        assert features.feature_availability["days_since_previous_release"] is True
        assert features.feature_availability["release_gap_ratio"] is False
        assert features.feature_availability["release_frequency_90d"] is True
        # 2024-01-01 to 2026-01-15 is ~745 days, NOT within 90 days
        assert features.features["release_frequency_90d"] == 0.0

    def test_missing_npm_metadata(self):
        """Node without npm_times field."""
        node = _make_node()
        node.pop("npm_times", None)
        features = extract_features(node, REFERENCE_TIME)

        for key in features.features:
            assert features.features[key] is None
            assert features.feature_availability[key] is False

    def test_deterministic_results(self):
        """Same input + same reference time = same output."""
        npm_times = {
            "1.0.0": "2020-01-01T00:00:00Z",
            "2.0.0": "2022-01-01T00:00:00Z",
        }
        node = _make_node(npm_times=npm_times)

        f1 = extract_features(node, REFERENCE_TIME)
        f2 = extract_features(node, REFERENCE_TIME)

        assert f1.features == f2.features
        assert f1.feature_availability == f2.feature_availability

    def test_feature_availability_structure(self):
        """Feature availability dict has correct keys."""
        node = _make_node()
        features = extract_features(node, REFERENCE_TIME)

        expected_keys = {
            "days_since_previous_release",
            "release_gap_ratio",
            "package_age_days",
            "release_frequency_90d",
        }
        assert set(features.features.keys()) == expected_keys
        assert set(features.feature_availability.keys()) == expected_keys


class TestBatchFeatureExtraction:
    def test_extracts_all_packages(self):
        """Batch extraction processes all packages in response."""
        response = {
            "transaction_hash": "tx123",
            "dependencies": [
                {
                    "package": "pkg-a",
                    "version": "1.0.0",
                    "vulnerabilities": [],
                    "npm_metadata": {
                        "maintainers": [],
                        "times": {
                            "1.0.0": "2020-01-01T00:00:00Z",
                            "2.0.0": "2022-01-01T00:00:00Z",
                        },
                    },
                },
                {
                    "package": "pkg-b",
                    "version": "2.0.0",
                    "vulnerabilities": [],
                    "npm_metadata": {
                        "maintainers": [],
                        "times": {
                            "1.0.0": "2021-01-01T00:00:00Z",
                        },
                    },
                },
            ],
        }

        results = extract_features_batch(response, REFERENCE_TIME)

        assert len(results) == 2
        names = {f.package_name for f in results}
        assert names == {"pkg-a", "pkg-b"}

    def test_malformed_record_raises(self):
        """Malformed dependency record raises appropriate error."""
        response = {
            "transaction_hash": "tx123",
            "dependencies": [{"version": "1.0.0"}],  # missing "package"
        }
        with pytest.raises(ValueError, match="missing required field 'package'"):
            extract_features_batch(response, REFERENCE_TIME)