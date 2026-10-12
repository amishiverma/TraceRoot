"""
Graph metrics for dependency analysis.

Calculates structural metrics on the dependency graph.
"""

import networkx as nx
from typing import Any


class GraphMetrics:
    """Container for graph-level metrics."""

    def __init__(
        self,
        total_packages: int,
        total_dependencies: int,
        has_cycles: bool,
        cycles: list[list[str]],
        betweenness_centrality: dict[str, float],
    ):
        self.total_packages = total_packages
        self.total_dependencies = total_dependencies
        self.has_cycles = has_cycles
        self.cycles = cycles
        self.betweenness_centrality = betweenness_centrality

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_packages": self.total_packages,
            "total_dependencies": self.total_dependencies,
            "has_cycles": self.has_cycles,
            "cycles": self.cycles,
            "betweenness_centrality": self.betweenness_centrality,
        }


class PackageMetrics:
    """Container for per-package metrics."""

    def __init__(
        self,
        node_id: str,
        name: str,
        version: str,
        direct_dependencies: int,
        transitive_dependencies: int,
        direct_dependents: int,
        transitive_dependents: int,
        betweenness_centrality: float,
    ):
        self.node_id = node_id
        self.name = name
        self.version = version
        self.direct_dependencies = direct_dependencies
        self.transitive_dependencies = transitive_dependencies
        self.direct_dependents = direct_dependents
        self.transitive_dependents = transitive_dependents
        self.betweenness_centrality = betweenness_centrality

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "name": self.name,
            "version": self.version,
            "direct_dependencies": self.direct_dependencies,
            "transitive_dependencies": self.transitive_dependencies,
            "direct_dependents": self.direct_dependents,
            "transitive_dependents": self.transitive_dependents,
            "betweenness_centrality": self.betweenness_centrality,
        }


def calculate_graph_metrics(graph: nx.DiGraph) -> GraphMetrics:
    """
    Calculate graph-level structural metrics.

    Args:
        graph: Directed dependency graph (parent -> dependency)

    Returns:
        GraphMetrics object with structural metrics
    """
    if graph.number_of_nodes() == 0:
        return GraphMetrics(
            total_packages=0,
            total_dependencies=0,
            has_cycles=False,
            cycles=[],
            betweenness_centrality={},
        )

    # Total packages (nodes)
    total_packages = graph.number_of_nodes()

    # Total dependency edges
    total_dependencies = graph.number_of_edges()

    # Detect cycles
    cycles = list(nx.simple_cycles(graph))
    has_cycles = len(cycles) > 0

    # Betweenness centrality (normalized)
    betweenness = nx.betweenness_centrality(graph, normalized=True)

    return GraphMetrics(
        total_packages=total_packages,
        total_dependencies=total_dependencies,
        has_cycles=has_cycles,
        cycles=cycles,
        betweenness_centrality=betweenness,
    )


def calculate_package_metrics(graph: nx.DiGraph) -> dict[str, PackageMetrics]:
    """
    Calculate per-package metrics for all nodes in the graph.

    Args:
        graph: Directed dependency graph (parent -> dependency)

    Returns:
        Dict mapping node_id to PackageMetrics
    """
    if graph.number_of_nodes() == 0:
        return {}

    # Betweenness centrality for all nodes
    betweenness = nx.betweenness_centrality(graph, normalized=True)

    results = {}

    for node_id in graph.nodes():
        node_data = graph.nodes[node_id]
        name = node_data.get("name", "")
        version = node_data.get("version", "")

        # Direct dependencies (outgoing edges)
        direct_deps = graph.out_degree(node_id)

        # Transitive dependencies (all reachable nodes via outgoing edges)
        try:
            transitive_deps = len(nx.descendants(graph, node_id))
        except nx.NetworkXError:
            transitive_deps = 0

        # Direct dependents (incoming edges)
        direct_dependents = graph.in_degree(node_id)

        # Transitive dependents (all nodes that can reach this node)
        try:
            transitive_dependents = len(nx.ancestors(graph, node_id))
        except nx.NetworkXError:
            transitive_dependents = 0

        results[node_id] = PackageMetrics(
            node_id=node_id,
            name=name,
            version=version,
            direct_dependencies=direct_deps,
            transitive_dependencies=transitive_deps,
            direct_dependents=direct_dependents,
            transitive_dependents=transitive_dependents,
            betweenness_centrality=betweenness.get(node_id, 0.0),
        )

    return results