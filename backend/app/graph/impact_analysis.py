"""
Impact analysis for vulnerable packages.

Analyzes the structural impact of a vulnerable package on the dependency graph.
"""

import networkx as nx
from typing import Any

from app.graph.traversal import (
    get_direct_dependents,
    get_transitive_dependents,
    get_upstream_paths_to_vulnerable,
    get_downstream_impact_set,
)
from app.graph.metrics import calculate_package_metrics


class ImpactAnalysis:
    """Container for impact analysis results."""

    def __init__(
        self,
        target_package: dict[str, Any],
        direct_upstream_dependents: list[str],
        transitive_upstream_dependents: list[str],
        total_affected_upstream: int,
        dependency_paths: dict[str, list[list[str]]],
        structural_impact_score: float,
        affected_package_metrics: dict[str, Any],
    ):
        self.target_package = target_package
        self.direct_upstream_dependents = direct_upstream_dependents
        self.transitive_upstream_dependents = transitive_upstream_dependents
        self.total_affected_upstream = total_affected_upstream
        self.dependency_paths = dependency_paths
        self.structural_impact_score = structural_impact_score
        self.affected_package_metrics = affected_package_metrics

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_package": self.target_package,
            "direct_upstream_dependents": self.direct_upstream_dependents,
            "transitive_upstream_dependents": self.transitive_upstream_dependents,
            "total_affected_upstream": self.total_affected_upstream,
            "dependency_paths": self.dependency_paths,
            "structural_impact_score": self.structural_impact_score,
            "affected_package_metrics": self.affected_package_metrics,
        }


def _calculate_structural_impact_score(
    graph: nx.DiGraph,
    target_node: str,
    direct_dependents: list[str],
    transitive_dependents: list[str],
) -> float:
    """
    Calculate a structural impact score for a vulnerable package.

    Formula (heuristic, 0-1 scale):
    - Base score from fraction of graph affected: affected_upstream / total_packages
    - Weighted by betweenness centrality of target (how central it is)
    - Weighted by average betweenness of affected packages

    This is a PRIORITIZATION HEURISTIC only, not a probability of failure.

    Args:
        graph: Dependency graph
        target_node: Vulnerable package node ID
        direct_dependents: Direct upstream dependents
        transitive_dependents: Transitive upstream dependents

    Returns:
        Score between 0.0 and 1.0
    """
    total_packages = graph.number_of_nodes()
    if total_packages == 0:
        return 0.0

    all_affected = set(direct_dependents) | set(transitive_dependents)
    affected_count = len(all_affected)

    # Fraction of graph affected (excluding the vulnerable package itself)
    affected_fraction = affected_count / total_packages

    # Betweenness centrality of target
    betweenness = nx.betweenness_centrality(graph, normalized=True)
    target_betweenness = betweenness.get(target_node, 0.0)

    # Average betweenness of affected packages
    if all_affected:
        avg_affected_betweenness = sum(
            betweenness.get(n, 0.0) for n in all_affected
        ) / len(all_affected)
    else:
        avg_affected_betweenness = 0.0

    # Weighted combination (heuristic weights)
    score = (
        0.5 * affected_fraction +
        0.3 * target_betweenness +
        0.2 * avg_affected_betweenness
    )

    return min(1.0, max(0.0, score))


def analyze_impact(graph: nx.DiGraph, target_node_id: str) -> ImpactAnalysis:
    """
    Analyze the structural impact of a vulnerable package.

    Args:
        graph: Directed dependency graph (parent -> dependency)
        target_node_id: Node ID of the vulnerable package (e.g., "lodash@4.17.15")

    Returns:
        ImpactAnalysis object with impact details

    Raises:
        ValueError: If target_node_id is not in the graph
    """
    if not graph.has_node(target_node_id):
        raise ValueError(f"Target package '{target_node_id}' not found in graph")

    # Get target package info
    target_data = graph.nodes[target_node_id]
    target_package = {
        "node_id": target_node_id,
        "name": target_data.get("name", ""),
        "version": target_data.get("version", ""),
        "incomplete": target_data.get("incomplete", False),
    }

    # Get upstream dependents
    direct_dependents = get_direct_dependents(graph, target_node_id)
    transitive_dependents = get_transitive_dependents(graph, target_node_id)

    # Get dependency paths from each dependent to the vulnerable package
    dependency_paths = get_upstream_paths_to_vulnerable(graph, target_node_id)

    # Calculate structural impact score
    structural_impact_score = _calculate_structural_impact_score(
        graph,
        target_node_id,
        direct_dependents,
        transitive_dependents,
    )

    # Get metrics for affected packages
    all_package_metrics = calculate_package_metrics(graph)
    affected_package_metrics = {}
    all_affected = set(direct_dependents) | set(transitive_dependents)
    for node_id in all_affected:
        if node_id in all_package_metrics:
            affected_package_metrics[node_id] = all_package_metrics[node_id].to_dict()

    return ImpactAnalysis(
        target_package=target_package,
        direct_upstream_dependents=direct_dependents,
        transitive_upstream_dependents=transitive_dependents,
        total_affected_upstream=len(set(direct_dependents) | set(transitive_dependents)),
        dependency_paths=dependency_paths,
        structural_impact_score=structural_impact_score,
        affected_package_metrics=affected_package_metrics,
    )