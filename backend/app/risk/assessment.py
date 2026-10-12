"""
Risk assessment orchestration layer.

Combines all heuristic signal evaluators (from heuristic_rules.py) into a
single per-package RiskAssessment object and a batch assess_all_packages helper.

Key design decisions:
- RiskAssessment is a value object (no mutation after construction).
- Score is capped at 100; each signal contributes its own points.
- assess_package_risk accepts raw node_data dicts so it works both on
  graph node data and on deserialized API response dicts.
- assess_all_packages validates input and raises ValueError on malformed
  records so callers get a clear failure signal early.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.risk.heuristic_rules import (
    SignalResult,
    evaluate_vulnerability_signal,
    evaluate_dormancy_signal,
    evaluate_maintainer_change_signal,
)


# ---------------------------------------------------------------------------
# RiskAssessment value object
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RiskAssessment:
    """Immutable result of a full heuristic risk assessment for one package."""

    package_name: str
    supplied_version: str
    resolved_version: str | None
    version_resolution_status: str  # "resolved" | "range" | "unknown"
    heuristic_risk_score: int  # 0-100
    signals: tuple[dict, ...]  # always 3 signal dicts (serialised for direct subscript access)
    supporting_advisory_ids: tuple[str, ...]
    assessment_complete: bool  # False if any signal is "unknown"

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a plain dict for JSON output."""
        # signals are already dicts; build evidence index from them
        all_evidence: dict[str, Any] = {}
        for sig in self.signals:
            all_evidence[sig["rule"].lower()] = sig.get("evidence", {})

        # Aggregate recommended next action
        unknowns = [s["rule"] for s in self.signals if s["status"] == "unknown"]
        if unknowns:
            action = (
                f"Resolve version to a pinned release and gather historical "
                f"data for: {', '.join(unknowns)}"
            )
        elif self.heuristic_risk_score >= 50:
            action = "Review package urgently; confirmed risk signals detected."
        elif self.heuristic_risk_score > 0:
            action = "Monitor package; low-level risk signals present."
        else:
            action = "No action required at this time."

        return {
            "package_name": self.package_name,
            "supplied_version": self.supplied_version,
            "resolved_version": self.resolved_version,
            "version_resolution_status": self.version_resolution_status,
            "heuristic_risk_score": self.heuristic_risk_score,
            "signals": list(self.signals),  # already dicts
            "supporting_advisory_ids": list(self.supporting_advisory_ids),
            "assessment_complete": self.assessment_complete,
            "evidence": all_evidence,
            "recommended_next_action": action,
        }


# ---------------------------------------------------------------------------
# Per-package assessment
# ---------------------------------------------------------------------------


def assess_package_risk(
    node_data: dict[str, Any],
    vulnerabilities: list[dict[str, Any]] | None = None,
    historical_maintainers: list[dict[str, Any]] | None = None,
) -> RiskAssessment:
    """
    Run all three heuristic signals against a single package node and return
    a RiskAssessment.

    Args:
        node_data: Node attribute dict from the dependency graph (or an
                   equivalent dict with the same keys).
        vulnerabilities: Full OSV advisory objects fetched for this package.
                         Pass an empty list when there are none, or None to
                         let the evaluator use advisory_ids embedded in
                         node_data (which treats it as "no full advisory data").
        historical_maintainers: Snapshotted maintainer list for comparison.
                                Pass None when unavailable (yields "unknown").

    Returns:
        A frozen RiskAssessment instance.
    """
    if vulnerabilities is None:
        vulnerabilities = []

    # --- Signal 1: Known vulnerability ---
    vuln_signal = evaluate_vulnerability_signal(node_data, vulnerabilities)

    # --- Signal 2: Extended dormancy ---
    dormancy_signal = evaluate_dormancy_signal(node_data)

    # --- Signal 3: Maintainer change ---
    maintainer_signal = evaluate_maintainer_change_signal(node_data, historical_maintainers)

    # Serialise signals to dicts immediately so callers can subscript them directly
    signal_dicts = tuple(s.to_dict() for s in (vuln_signal, dormancy_signal, maintainer_signal))

    # --- Score aggregation (cap at 100) ---
    raw_score = sum(s.points for s in (vuln_signal, dormancy_signal, maintainer_signal))
    final_score = min(raw_score, 100)

    # --- Version metadata ---
    version_precision = node_data.get("version_precision", "unknown")
    supplied_version = node_data.get("version", "")
    resolved_version = supplied_version if version_precision == "resolved" else None

    # --- Completeness flag: all signals must be non-unknown ---
    assessment_complete = all(s["status"] != "unknown" for s in signal_dicts)

    # --- Advisory IDs from confirmed vuln signal evidence ---
    advisory_ids: list[str] = []
    if vuln_signal.status == "confirmed":
        for adv in vuln_signal.evidence.get("confirmed_advisories", []):
            aid = adv.get("advisory_id")
            if aid:
                advisory_ids.append(aid)

    return RiskAssessment(
        package_name=node_data.get("name", ""),
        supplied_version=supplied_version,
        resolved_version=resolved_version,
        version_resolution_status=version_precision,
        heuristic_risk_score=final_score,
        signals=signal_dicts,
        supporting_advisory_ids=tuple(advisory_ids),
        assessment_complete=assessment_complete,
    )


# ---------------------------------------------------------------------------
# Batch assessment
# ---------------------------------------------------------------------------


def assess_all_packages(
    api_response: dict[str, Any],
    vulnerabilities_map: dict[str, list[dict[str, Any]]] | None = None,
    historical_maintainers_map: dict[str, list[dict[str, Any]]] | None = None,
) -> list[RiskAssessment]:
    """
    Assess risk for all packages in a /scan API response.

    Args:
        api_response: The dict returned by /scan, expected to contain a
                      ``dependencies`` key with a list of package dicts.
        vulnerabilities_map: Mapping of package_name -> OSV advisory list.
                             Pass None to assess with no advisory data.
        historical_maintainers_map: Mapping of package_name -> historical
                                    maintainer list. Pass None when unavailable.

    Returns:
        List of RiskAssessment objects, one per dependency record.

    Raises:
        ValueError: If a dependency record is missing the required 'package' field.
    """
    dependencies = api_response.get("dependencies", [])
    assessments: list[RiskAssessment] = []

    for record in dependencies:
        if "package" not in record:
            raise ValueError(
                f"Dependency record is missing required field 'package': {record!r}"
            )

        pkg_name = record["package"]

        # Build a node_data dict from the API response record
        node_data = _api_record_to_node_data(record)

        vulns = (vulnerabilities_map or {}).get(pkg_name, [])
        historical = (historical_maintainers_map or {}).get(pkg_name, None)

        assessments.append(assess_package_risk(node_data, vulns, historical))

    return assessments


# ---------------------------------------------------------------------------
# Internal adapter
# ---------------------------------------------------------------------------


def _api_record_to_node_data(record: dict[str, Any]) -> dict[str, Any]:
    """
    Convert an API response dependency record into the node_data shape
    expected by the heuristic evaluators.

    API record keys:      node_data keys:
      package           -> name
      version           -> version
      vulnerabilities   -> vulnerability_advisory_ids (extracted ids),
                           vulnerability_count
      npm_metadata      -> npm_maintainers, npm_times
    """
    npm_meta = record.get("npm_metadata") or {}

    # Extract vulnerability advisory IDs from raw vulnerability list
    raw_vulns = record.get("vulnerabilities") or []
    advisory_ids = [v.get("id") for v in raw_vulns if v.get("id")]

    version = record.get("version", "")
    # Determine version precision: if it starts with ^, ~, >=, <=, or
    # contains a space or *, treat it as a range
    from app.graph.builder import _is_version_range
    precision = "range" if _is_version_range(version) else "resolved"

    return {
        "name": record.get("package", ""),
        "version": version,
        "version_precision": precision,
        "vulnerability_count": len(raw_vulns),
        "vulnerability_advisory_ids": advisory_ids,
        "npm_maintainers": npm_meta.get("maintainers") or [],
        "npm_times": npm_meta.get("times") or {},
        "incomplete": precision == "range",
    }