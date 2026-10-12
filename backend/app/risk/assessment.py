"""
Risk assessment orchestration layer.

Provides both:
1. Production pipeline risk scoring functions used by main.py:
   - assess_all_risks(graph, manifest)
   - calculate_impact(graph, node_name)
   - calculate_heuristics(pkg_data)
   - predict_ml_risk(pkg_data)

2. Comprehensive heuristic risk evaluation classes/functions for unit & integration testing:
   - RiskAssessment
   - assess_package_risk(node_data, vulnerabilities, historical_maintainers)
   - assess_all_packages(api_response, vulnerabilities_map, historical_maintainers_map)
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import networkx as nx

from app.risk.heuristic_rules import (
    SignalResult,
    evaluate_vulnerability_signal,
    evaluate_dormancy_signal,
    evaluate_maintainer_change_signal,
)


# ===========================================================================
# 1. Pipeline Risk Scoring (used by main.py)
# ===========================================================================


def calculate_impact(graph: nx.DiGraph, node_name: str) -> int:
    """Calculate graph centrality impact score."""
    try:
        centrality = nx.betweenness_centrality(graph, normalized=True)
        cent = centrality.get(node_name, 0)
        return min(int(cent * 10000), 100)
    except Exception:
        return 0


def calculate_heuristics(pkg_data: dict[str, Any]) -> tuple[int, list[str]]:
    """Calculate heuristic score and flags from package data."""
    score = 0
    flags = []
    if pkg_data.get("vulnerabilities"):
        score += 100
        flags.append("Known CVEs found")

    npm_meta = pkg_data.get("npm_metadata") or {}
    try:
        times = npm_meta.get("times", {})
        if "modified" in times:
            mod_date_str = times["modified"].split("T")[0]
            mod_date = datetime.strptime(mod_date_str, "%Y-%m-%d")
            if (datetime.now() - mod_date).days > 365:
                score += 50
                flags.append("Package dormant for > 1 year")
    except Exception:
        pass

    maintainers = npm_meta.get("maintainers", [])
    if isinstance(maintainers, list) and len(maintainers) < 2:
        score += 20
        flags.append("Low maintainer count")

    return min(score, 100), flags


def predict_ml_risk(pkg_data: dict[str, Any]) -> int:
    """Predict risk using ML model (stub / random baseline)."""
    return random.randint(10, 40)


def assess_all_risks(graph: nx.DiGraph, manifest: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Score risks across all packages in the manifest using ensemble formula.
    Injected directly into each package dict for API response and blockchain anchoring.
    """
    for pkg in manifest:
        impact = calculate_impact(graph, pkg.get("package"))
        heuristics, flags = calculate_heuristics(pkg)
        ml_score = predict_ml_risk(pkg)
        final_score = int((0.50 * heuristics) + (0.30 * impact) + (0.20 * ml_score))
        pkg["final_risk_score"] = min(final_score, 100)
        pkg["risk_flags"] = flags
    return manifest


# ===========================================================================
# 2. Detailed Heuristic Risk Assessment (for verification and testing)
# ===========================================================================


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
        all_evidence: dict[str, Any] = {}
        for sig in self.signals:
            all_evidence[sig["rule"].lower()] = sig.get("evidence", {})

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
            "signals": list(self.signals),
            "supporting_advisory_ids": list(self.supporting_advisory_ids),
            "assessment_complete": self.assessment_complete,
            "evidence": all_evidence,
            "recommended_next_action": action,
        }


def assess_package_risk(
    node_data: dict[str, Any],
    vulnerabilities: list[dict[str, Any]] | None = None,
    historical_maintainers: list[dict[str, Any]] | None = None,
) -> RiskAssessment:
    """Run all three heuristic signals against a package node."""
    if vulnerabilities is None:
        vulnerabilities = []

    vuln_signal = evaluate_vulnerability_signal(node_data, vulnerabilities)
    dormancy_signal = evaluate_dormancy_signal(node_data)
    maintainer_signal = evaluate_maintainer_change_signal(node_data, historical_maintainers)

    signal_dicts = tuple(s.to_dict() for s in (vuln_signal, dormancy_signal, maintainer_signal))

    raw_score = sum(s.points for s in (vuln_signal, dormancy_signal, maintainer_signal))
    final_score = min(raw_score, 100)

    version_precision = node_data.get("version_precision", "unknown")
    supplied_version = node_data.get("version", "")
    resolved_version = supplied_version if version_precision == "resolved" else None

    assessment_complete = all(s["status"] != "unknown" for s in signal_dicts)

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


def assess_all_packages(
    api_response: dict[str, Any],
    vulnerabilities_map: dict[str, list[dict[str, Any]]] | None = None,
    historical_maintainers_map: dict[str, list[dict[str, Any]]] | None = None,
) -> list[RiskAssessment]:
    """Assess risk for all packages in a /scan API response."""
    dependencies = api_response.get("dependencies", [])
    assessments: list[RiskAssessment] = []

    for record in dependencies:
        if "package" not in record:
            raise ValueError(
                f"Dependency record is missing required field 'package': {record!r}"
            )

        pkg_name = record["package"]
        node_data = _api_record_to_node_data(record)
        vulns = (vulnerabilities_map or {}).get(pkg_name, [])
        historical = (historical_maintainers_map or {}).get(pkg_name, None)
        assessments.append(assess_package_risk(node_data, vulns, historical))

    return assessments


def _api_record_to_node_data(record: dict[str, Any]) -> dict[str, Any]:
    """Convert an API response dependency record into node_data shape."""
    npm_meta = record.get("npm_metadata") or {}
    raw_vulns = record.get("vulnerabilities") or []
    advisory_ids = [v.get("id") for v in raw_vulns if v.get("id")]

    version = record.get("version", "")
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