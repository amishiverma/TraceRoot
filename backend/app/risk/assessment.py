"""
Heuristic risk assessment engine.

Orchestrates individual risk rules and produces a consolidated
risk assessment for a package node.
"""

from dataclasses import dataclass, asdict
from typing import Any

from app.graph.builder import build_graph_from_api_response
from app.risk.heuristic_rules import (
    SignalResult,
    evaluate_vulnerability_signal,
    evaluate_dormancy_signal,
    evaluate_maintainer_change_signal,
)


@dataclass
class RiskAssessment:
    """Complete risk assessment for a single package."""
    package_name: str
    supplied_version: str
    resolved_version: str | None
    version_resolution_status: str  # "resolved" or "range"
    heuristic_risk_score: int  # 0-100
    signals: list[dict[str, Any]]
    supporting_advisory_ids: list[str]
    assessment_complete: bool
    evidence: dict[str, Any]
    recommended_next_action: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def assess_package_risk(
    node_data: dict[str, Any],
    vulnerabilities: list[dict[str, Any]] | None = None,
    historical_maintainers: list[dict[str, Any]] | None = None,
) -> RiskAssessment:
    """
    Assess heuristic risk for a single package node.

    Args:
        node_data: Node attributes from graph (name, version, version_precision,
                   vulnerability_count, vulnerability_advisory_ids, npm_maintainers,
                   npm_times, incomplete)
        vulnerabilities: Full vulnerability objects from API response (for rule 1)
        historical_maintainers: Optional historical maintainer data (for rule 3)

    Returns:
        RiskAssessment with score, signal statuses, and evidence
    """
    name = node_data.get("name", "")
    version = node_data.get("version", "")
    version_precision = node_data.get("version_precision", "range")

    # Use vulnerabilities from node_data if not provided
    if vulnerabilities is None:
        # Reconstruct minimal vulnerability objects from advisory IDs
        # (Full objects needed for version range matching)
        vuln_count = node_data.get("vulnerability_count", 0)
        advisory_ids = node_data.get("vulnerability_advisory_ids", [])
        # We can't do full matching without full objects - will return unknown
        vulnerabilities = [{"id": aid} for aid in advisory_ids] if advisory_ids else []

    # Evaluate all three rules
    vuln_signal = evaluate_vulnerability_signal(node_data, vulnerabilities)
    dormancy_signal = evaluate_dormancy_signal(node_data)
    maintainer_signal = evaluate_maintainer_change_signal(node_data, historical_maintainers)

    signals = [vuln_signal, dormancy_signal, maintainer_signal]

    # Calculate score: sum of confirmed points, capped at 100
    confirmed_points = sum(s.points for s in signals if s.status == "confirmed")
    heuristic_score = min(100, confirmed_points)

    # Determine if assessment is complete (no unknown signals)
    has_unknown = any(s.status == "unknown" for s in signals)
    assessment_complete = not has_unknown

    # Collect all supporting advisory IDs
    all_advisory_ids = node_data.get("vulnerability_advisory_ids", [])

    # Determine recommended action
    if not assessment_complete:
        recommended_action = (
            "Assessment incomplete. Resolve package version via lockfile "
            "and obtain historical maintainer data for full evaluation."
        )
    elif heuristic_score >= 50:
        recommended_action = "High risk detected. Prioritize remediation and investigation."
    elif heuristic_score >= 30:
        recommended_action = "Moderate risk. Review findings and monitor."
    elif heuristic_score > 0:
        recommended_action = "Low risk signals detected. Monitor for changes."
    else:
        recommended_action = "No heuristic risk signals confirmed. Continue monitoring."

    return RiskAssessment(
        package_name=name,
        supplied_version=version,
        resolved_version=version if version_precision == "resolved" else None,
        version_resolution_status=version_precision,
        heuristic_risk_score=heuristic_score,
        signals=[s.to_dict() for s in signals],
        supporting_advisory_ids=all_advisory_ids,
        assessment_complete=assessment_complete,
        evidence={
            "version_precision": version_precision,
            "incomplete_graph": node_data.get("incomplete", True),
            "npm_metadata_available": bool(node_data.get("npm_times") or node_data.get("npm_maintainers")),
        },
        recommended_next_action=recommended_action,
    )


def assess_all_packages(
    api_response: dict[str, Any],
    vulnerability_details: dict[str, list[dict[str, Any]]] | None = None,
    historical_maintainers_map: dict[str, list[dict[str, Any]]] | None = None,
) -> list[RiskAssessment]:
    """
    Assess risk for all packages in an API response.

    Args:
        api_response: Raw API response with transaction_hash and dependencies
        vulnerability_details: Optional map of package@version -> full vulnerability objects
        historical_maintainers_map: Optional map of package name -> historical maintainers

    Returns:
        List of RiskAssessment objects
    """
    graph = build_graph_from_api_response(api_response)
    assessments = []

    for node_id in graph.nodes():
        node_data = graph.nodes[node_id]
        name = node_data.get("name", "")

        # Get full vulnerability objects if available
        vulns = None
        if vulnerability_details:
            vulns = vulnerability_details.get(node_id, [])

        # Get historical maintainers if available
        hist_maintainers = None
        if historical_maintainers_map:
            hist_maintainers = historical_maintainers_map.get(name)

        assessment = assess_package_risk(node_data, vulns, hist_maintainers)
        assessments.append(assessment)

    return assessments


def assess_all_risks(
    arg1: Any,
    arg2: Any = None,
) -> list[dict[str, Any]]:
    """
    Assess risk for all packages in the manifest using graph metrics and heuristic rules.
    Supports both assess_all_risks(graph, manifest) and assess_all_risks(manifest, graph).
    Mutates manifest packages in-place adding final_risk_score, risk_flags, and recommendations.
    """
    import networkx as nx
    from app.graph.builder import _is_version_range

    if isinstance(arg1, list):
        manifest = arg1
        graph = arg2
    else:
        graph = arg1
        manifest = arg2 if isinstance(arg2, list) else []

    if not manifest:
        return manifest

    # Calculate betweenness centrality if graph is provided
    impact_scores: dict[str, int] = {}
    if graph and hasattr(graph, "nodes"):
        try:
            centrality = nx.betweenness_centrality(graph, normalized=True)
            for node, cent in centrality.items():
                impact_scores[node] = min(int(cent * 10000), 100)
        except Exception:
            pass

    for pkg in manifest:
        pkg_name = pkg.get("package") or pkg.get("name", "")
        version = pkg.get("version", "")
        node_id = f"{pkg_name}@{version}"

        node_data = {
            "name": pkg_name,
            "version": version,
            "version_precision": "resolved" if not _is_version_range(version) else "range",
            "vulnerability_count": len(pkg.get("vulnerabilities", [])),
            "vulnerability_advisory_ids": [v.get("id", "") for v in pkg.get("vulnerabilities", []) if v.get("id")],
            "npm_maintainers": (pkg.get("npm_metadata", {}) or {}).get("maintainers", []),
            "npm_times": (pkg.get("npm_metadata", {}) or {}).get("times", {}),
            "incomplete": False,
        }

        vulns = pkg.get("vulnerabilities", [])
        assessment = assess_package_risk(node_data, vulns)

        impact = impact_scores.get(node_id, impact_scores.get(pkg_name, 0))
        h_score = assessment.heuristic_risk_score

        final_score = int(round(0.70 * h_score + 0.30 * impact))
        final_score = max(0, min(final_score, 100))

        flags = [s["description"] for s in assessment.signals if s.get("status") == "confirmed"]
        if impact > 50:
            flags.append(f"High graph centrality impact ({impact}/100)")

        pkg["final_risk_score"] = final_score
        pkg["risk_flags"] = flags
        pkg["heuristic_risk_score"] = h_score
        pkg["impact_score"] = impact
        pkg["recommended_action"] = assessment.recommended_next_action

    return manifest