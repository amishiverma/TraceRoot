"""
Heuristic risk rules for dependency security assessment.

Each rule evaluates a specific risk signal and returns:
- status: "confirmed", "not_detected", or "unknown"
- points: integer score (0-50 per rule)
- explanation: human-readable description
- evidence: structured data supporting the finding
"""

from datetime import datetime
from typing import Any

from app.graph.builder import _is_version_range


class SignalResult:
    """Container for a single heuristic signal evaluation."""

    def __init__(
        self,
        rule_name: str,
        status: str,
        points: int,
        explanation: str,
        evidence: dict[str, Any],
    ):
        self.rule_name = rule_name
        self.status = status  # "confirmed", "not_detected", "unknown"
        self.points = points
        self.explanation = explanation
        self.evidence = evidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule_name,
            "status": self.status,
            "points": self.points,
            "explanation": self.explanation,
            "evidence": self.evidence,
        }


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


def _find_dormancy_gaps(releases: list[tuple[str, datetime]], min_gap_days: int = 730) -> list[dict[str, Any]]:
    """
    Find gaps between consecutive releases exceeding min_gap_days.

    Returns list of gap evidence dicts with from_version, to_version, gap_days.
    """
    gaps = []
    for i in range(1, len(releases)):
        prev_version, prev_dt = releases[i - 1]
        curr_version, curr_dt = releases[i]
        gap_days = (curr_dt - prev_dt).days

        if gap_days >= min_gap_days:
            gaps.append({
                "from_version": prev_version,
                "to_version": curr_version,
                "gap_days": gap_days,
                "from_date": prev_dt.isoformat(),
                "to_date": curr_dt.isoformat(),
            })
    return gaps


def _version_in_range(version: str, introduced: str, fixed: str | None) -> bool:
    """
    Check if a resolved version falls within a vulnerable range.

    Args:
        version: Resolved version string (e.g., "1.20.1")
        introduced: Version where vulnerability was introduced (e.g., "0" or "1.0.0")
        fixed: Version where vulnerability was fixed (e.g., "1.20.3"), or None if unfixed

    Returns:
        True if version is >= introduced and < fixed (if fixed exists)
    """
    try:
        from packaging import version as pkg_version

        v = pkg_version.parse(version)
        introduced_v = pkg_version.parse(introduced) if introduced != "0" else pkg_version.parse("0.0.0")

        if v < introduced_v:
            return False

        if fixed is not None:
            fixed_v = pkg_version.parse(fixed)
            if v >= fixed_v:
                return False

        return True
    except Exception:
        return False


def evaluate_vulnerability_signal(
    node_data: dict[str, Any],
    vulnerabilities: list[dict[str, Any]],
) -> SignalResult:
    """
    RULE 1: KNOWN VULNERABILITY (+50)

    Award 50 points only when an OSV advisory is confirmed to affect
    the exact resolved package version.

    - If version is a range (not resolved), status = "unknown"
    - If no vulnerabilities, status = "not_detected"
    - If advisory affects resolved version, status = "confirmed"
    - If advisory exists but doesn't affect this version, status = "not_detected"
    """
    version = node_data.get("version", "")
    version_precision = node_data.get("version_precision", "range")

    # Cannot confirm applicability without a resolved version
    if version_precision == "range" or _is_version_range(version):
        return SignalResult(
            rule_name="KNOWN_VULNERABILITY",
            status="unknown",
            points=0,
            explanation=(
                f"Package version '{version}' is a range, not a resolved version. "
                "Cannot confirm vulnerability applicability without lockfile resolution."
            ),
            evidence={
                "supplied_version": version,
                "version_precision": version_precision,
                "advisory_ids": node_data.get("vulnerability_advisory_ids", []),
                "note": "Requires package-lock.json resolution to confirm",
            },
        )

    # No vulnerabilities reported
    if not vulnerabilities:
        return SignalResult(
            rule_name="KNOWN_VULNERABILITY",
            status="not_detected",
            points=0,
            explanation="No OSV advisories reported for this package.",
            evidence={"advisory_ids": []},
        )

    # Check each vulnerability for applicability to resolved version
    confirmed_advisories = []
    for vuln in vulnerabilities:
        vuln_id = vuln.get("id", "")
        affected_list = vuln.get("affected", [])

        for affected in affected_list:
            pkg_info = affected.get("package", {})
            if pkg_info.get("name") != node_data.get("name"):
                continue

            ranges = affected.get("ranges", [])
            for r in ranges:
                if r.get("type") != "SEMVER":
                    continue

                events = r.get("events", [])
                introduced = "0"
                fixed = None

                for event in events:
                    if "introduced" in event:
                        introduced = event["introduced"]
                    if "fixed" in event:
                        fixed = event["fixed"]

                if _version_in_range(version, introduced, fixed):
                    confirmed_advisories.append({
                        "advisory_id": vuln_id,
                        "introduced": introduced,
                        "fixed": fixed,
                        "matched_version": version,
                    })
                    break

    if confirmed_advisories:
        return SignalResult(
            rule_name="KNOWN_VULNERABILITY",
            status="confirmed",
            points=50,
            explanation=(
                f"Confirmed {len(confirmed_advisories)} OSV advisory(ies) affect "
                f"resolved version {version}"
            ),
            evidence={
                "resolved_version": version,
                "confirmed_advisories": confirmed_advisories,
            },
        )

    # Vulnerabilities exist but don't affect this version
    return SignalResult(
        rule_name="KNOWN_VULNERABILITY",
        status="not_detected",
        points=0,
        explanation=(
            f"OSV advisories found but none affect resolved version {version}"
        ),
        evidence={
            "resolved_version": version,
            "advisory_ids": node_data.get("vulnerability_advisory_ids", []),
        },
    )


def evaluate_dormancy_signal(node_data: dict[str, Any]) -> SignalResult:
    """
    RULE 2: RELEASE AFTER EXTENDED DORMANCY (+30)

    Award 30 points when release history establishes that a package
    received a new release after at least two years without a release.

    - Parse npm_metadata.times safely
    - Extract release timestamps from version keys
    - Sort chronologically, compare consecutive releases
    - Ignore 'created' and 'modified' timestamps
    """
    npm_times = node_data.get("npm_times", {})
    if not npm_times:
        return SignalResult(
            rule_name="EXTENDED_DORMANCY",
            status="unknown",
            points=0,
            explanation="No npm release timestamp data available.",
            evidence={},
        )

    releases = _extract_release_timestamps(npm_times)

    if len(releases) < 2:
        return SignalResult(
            rule_name="EXTENDED_DORMANCY",
            status="not_detected",
            points=0,
            explanation="Insufficient release history to detect dormancy (need ≥2 releases).",
            evidence={
                "release_count": len(releases),
                "releases": [{"version": v, "date": dt.isoformat()} for v, dt in releases],
            },
        )

    gaps = _find_dormancy_gaps(releases, min_gap_days=730)

    if gaps:
        # Use the largest gap as primary evidence
        max_gap = max(gaps, key=lambda g: g["gap_days"])
        return SignalResult(
            rule_name="EXTENDED_DORMANCY",
            status="confirmed",
            points=30,
            explanation=(
                f"Package had a release gap of {max_gap['gap_days']} days "
                f"between {max_gap['from_version']} and {max_gap['to_version']}"
            ),
            evidence={
                "max_gap_days": max_gap["gap_days"],
                "gap_from_version": max_gap["from_version"],
                "gap_to_version": max_gap["to_version"],
                "gap_from_date": max_gap["from_date"],
                "gap_to_date": max_gap["to_date"],
                "all_gaps": gaps,
                "total_releases": len(releases),
            },
        )

    return SignalResult(
        rule_name="EXTENDED_DORMANCY",
        status="not_detected",
        points=0,
        explanation="No release gap of 2+ years found in version history.",
        evidence={
            "total_releases": len(releases),
            "releases": [{"version": v, "date": dt.isoformat()} for v, dt in releases],
        },
    )


def evaluate_maintainer_change_signal(
    node_data: dict[str, Any],
    historical_maintainers: list[dict[str, Any]] | None = None,
) -> SignalResult:
    """
    RULE 3: VERIFIED MAINTAINER CHANGE (+20)

    Award 20 points only when historical evidence establishes an
    unexpected maintainer change under an explicit policy.

    - Current maintainer list alone is insufficient
    - Requires historical snapshots for comparison
    - If historical data unavailable, status = "unknown"
    """
    current_maintainers = node_data.get("npm_maintainers", [])

    if historical_maintainers is None:
        return SignalResult(
            rule_name="MAINTAINER_CHANGE",
            status="unknown",
            points=0,
            explanation=(
                "Historical maintainer data not available. "
                "Cannot verify maintainer changes without registry snapshots."
            ),
            evidence={
                "current_maintainers": [
                    {"name": m.get("name"), "email": m.get("email")}
                    for m in current_maintainers
                ],
                "note": "Requires historical npm registry snapshots",
            },
        )

    if not historical_maintainers:
        return SignalResult(
            rule_name="MAINTAINER_CHANGE",
            status="not_detected",
            points=0,
            explanation="No historical maintainer records to compare against.",
            evidence={
                "current_maintainers": [
                    {"name": m.get("name"), "email": m.get("email")}
                    for m in current_maintainers
                ],
            },
        )

    # Compare current vs historical (simple set comparison by email)
    current_emails = {m.get("email") for m in current_maintainers if m.get("email")}
    historical_emails = {m.get("email") for m in historical_maintainers if m.get("email")}

    added = current_emails - historical_emails
    removed = historical_emails - current_emails

    if added or removed:
        return SignalResult(
            rule_name="MAINTAINER_CHANGE",
            status="confirmed",
            points=20,
            explanation=(
                f"Maintainer change detected: {len(added)} added, {len(removed)} removed"
            ),
            evidence={
                "added_maintainers": list(added),
                "removed_maintainers": list(removed),
                "current_maintainers": [
                    {"name": m.get("name"), "email": m.get("email")}
                    for m in current_maintainers
                ],
                "historical_maintainers": [
                    {"name": m.get("name"), "email": m.get("email")}
                    for m in historical_maintainers
                ],
            },
        )

    return SignalResult(
        rule_name="MAINTAINER_CHANGE",
        status="not_detected",
        points=0,
        explanation="No maintainer changes detected in historical comparison.",
        evidence={
            "current_maintainers": [
                {"name": m.get("name"), "email": m.get("email")}
                for m in current_maintainers
            ],
        },
    )