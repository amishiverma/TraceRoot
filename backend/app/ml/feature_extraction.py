"""
ML feature extraction from npm package release history.

Converts npm_metadata.times into numerical features for anomaly detection.
"""

import csv
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class PackageFeatures:
    """Feature vector for a single npm package."""
    package_name: str
    supplied_version: str
    version_precision: str
    features: dict[str, float | None]
    feature_availability: dict[str, bool]
    reference_timestamp: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _parse_iso_timestamp(ts: str) -> datetime | None:
    """Parse ISO 8601 timestamp, return None if invalid."""
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def _extract_release_timestamps(npm_times: dict[str, str]) -> list[tuple[str, datetime]]:
    """
    Extract version release timestamps from npm times dict.

    Excludes 'created' and 'modified' metadata keys.
    Returns list of (version, datetime) tuples sorted chronologically.
    """
    releases = []
    for version, ts in npm_times.items():
        if version in ("created", "modified"):
            continue
        dt = _parse_iso_timestamp(ts)
        if dt is not None:
            releases.append((version, dt))

    releases.sort(key=lambda x: x[1])
    return releases


def _calculate_days_between(dt1: datetime, dt2: datetime) -> float:
    """Calculate days between two datetimes."""
    return (dt2 - dt1).total_seconds() / 86400.0


def extract_features(
    node_data: dict[str, Any],
    reference_time: datetime | None = None,
) -> PackageFeatures:
    """
    Extract ML features from package node data.

    Args:
        node_data: Node attributes from graph (name, version, version_precision,
                   npm_maintainers, npm_times, etc.)
        reference_time: Reference timestamp for calculations (defaults to now UTC).
                        Use a fixed timestamp in tests for determinism.

    Returns:
        PackageFeatures with computed features and availability flags.
    """
    if reference_time is None:
        reference_time = datetime.now(timezone.utc)

    name = node_data.get("name", "")
    version = node_data.get("version", "")
    version_precision = node_data.get("version_precision", "range")
    npm_times = node_data.get("npm_times", {})

    # Initialize features and availability
    features = {
        "days_since_previous_release": None,
        "release_gap_ratio": None,
        "package_age_days": None,
        "release_frequency_90d": None,
    }
    availability = {k: False for k in features}

    if not npm_times:
        return PackageFeatures(
            package_name=name,
            supplied_version=version,
            version_precision=version_precision,
            features=features,
            feature_availability=availability,
            reference_timestamp=reference_time.isoformat(),
        )

    releases = _extract_release_timestamps(npm_times)

    if not releases:
        return PackageFeatures(
            package_name=name,
            supplied_version=version,
            version_precision=version_precision,
            features=features,
            feature_availability=availability,
            reference_timestamp=reference_time.isoformat(),
        )

    # Package age: days from first release to reference time
    first_release_dt = releases[0][1]
    features["package_age_days"] = _calculate_days_between(first_release_dt, reference_time)
    availability["package_age_days"] = True

    # Days since previous release: gap from latest release to reference time
    latest_release_dt = releases[-1][1]
    features["days_since_previous_release"] = _calculate_days_between(latest_release_dt, reference_time)
    availability["days_since_previous_release"] = True

    # Release gap ratio: max gap / mean gap (for packages with >=3 releases)
    if len(releases) >= 3:
        gaps = []
        for i in range(1, len(releases)):
            prev_dt = releases[i - 1][1]
            curr_dt = releases[i][1]
            gap = _calculate_days_between(prev_dt, curr_dt)
            gaps.append(gap)

        max_gap = max(gaps)
        mean_gap = sum(gaps) / len(gaps)
        if mean_gap > 0:
            features["release_gap_ratio"] = max_gap / mean_gap
            availability["release_gap_ratio"] = True

    # Release frequency in last 90 days
    if len(releases) >= 1:
        cutoff = reference_time.timestamp() - (90 * 86400)
        recent_releases = sum(1 for _, dt in releases if dt.timestamp() > cutoff)
        features["release_frequency_90d"] = float(recent_releases)
        availability["release_frequency_90d"] = True

    return PackageFeatures(
        package_name=name,
        supplied_version=version,
        version_precision=version_precision,
        features=features,
        feature_availability=availability,
        reference_timestamp=reference_time.isoformat(),
    )


def extract_features_batch(
    api_response: dict[str, Any],
    reference_time: datetime | None = None,
) -> list[PackageFeatures]:
    """
    Extract features for all packages in an API response.

    Args:
        api_response: Raw API response with transaction_hash and dependencies.
        reference_time: Reference timestamp for calculations (defaults to now UTC).

    Returns:
        List of PackageFeatures for each package.
    """
    from app.graph.builder import build_graph_from_api_response

    graph = build_graph_from_api_response(api_response)
    feature_list = []

    for node_id in graph.nodes():
        node_data = graph.nodes[node_id]
        features = extract_features(node_data, reference_time)
        feature_list.append(features)

    return feature_list


def load_features_from_csv(
    csv_path: str | Path,
    usable_only: bool = False,
) -> list[PackageFeatures]:
    """
    Load package features from a CSV file (e.g. traceroot_real_features.csv).

    Args:
        csv_path: Path to the CSV file.
        usable_only: If True, only returns rows where data_status == 'usable'.
                     If False, returns all rows with appropriate feature_availability flags.

    Returns:
        List of PackageFeatures objects parsed from the CSV.
    """
    path = Path(csv_path)
    if not path.is_file():
        raise FileNotFoundError(f"Feature CSV not found at: {csv_path}")

    feature_cols = [
        "days_since_previous_release",
        "release_gap_ratio",
        "package_age_days",
        "release_frequency_90d",
    ]

    results: list[PackageFeatures] = []
    with open(path, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            data_status = row.get("data_status", "").strip()
            if usable_only and data_status != "usable":
                continue

            pkg_name = row.get("package_name", "").strip()
            version = row.get("resolved_version", "").strip()

            features: dict[str, float | None] = {}
            availability: dict[str, bool] = {}

            for col in feature_cols:
                raw_val = row.get(col, "")
                if raw_val is not None and str(raw_val).strip() != "":
                    try:
                        features[col] = float(raw_val)
                        availability[col] = True
                    except (ValueError, TypeError):
                        features[col] = None
                        availability[col] = False
                else:
                    features[col] = None
                    availability[col] = False

            results.append(
                PackageFeatures(
                    package_name=pkg_name,
                    supplied_version=version,
                    version_precision="resolved",
                    features=features,
                    feature_availability=availability,
                    reference_timestamp="",
                )
            )

    return results