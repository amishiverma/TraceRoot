"""
Dependency traversal utilities.

Provides functions for traversing the dependency graph in both directions:
- Outgoing: dependencies (what a package depends on)
- Incoming: dependents (what depends on a package)

Edge convention: parent package -> dependency
"""

import networkx as nx
from typing import Any


def get_direct_dependencies(graph: nx.DiGraph, node_id: str) -> list[str]:
    """
    Get direct dependencies of a package (outgoing edges).

    Args:
        graph: Directed dependency graph
        node_id: Package node ID (e.g., "express@4.18.2")

    Returns:
        List of direct dependency node IDs
    """
    if not graph.has_node(node_id):
        return []

    return list(graph.successors(node_id))


def get_transitive_dependencies(graph: nx.DiGraph, node_id: str) -> list[str]:
    """
    Get all transitive dependencies of a package (all reachable nodes).

    Args:
        graph: Directed dependency graph
        node_id: Package node ID

    Returns:
        List of transitive dependency node IDs (excluding the starting node)
    """
    if not graph.has_node(node_id):
        return []

    try:
        return list(nx.descendants(graph, node_id))
    except nx.NetworkXError:
        return []


def get_direct_dependents(graph: nx.DiGraph, node_id: str) -> list[str]:
    """
    Get packages that directly depend on the given package (incoming edges).

    Args:
        graph: Directed dependency graph
        node_id: Package node ID

    Returns:
        List of direct dependent node IDs
    """
    if not graph.has_node(node_id):
        return []

    return list(graph.predecessors(node_id))


def get_transitive_dependents(graph: nx.DiGraph, node_id: str) -> list[str]:
    """
    Get all packages that transitively depend on the given package (all ancestors).

    Args:
        graph: Directed dependency graph
        node_id: Package node ID

    Returns:
        List of transitive dependent node IDs (excluding the starting node)
    """
    if not graph.has_node(node_id):
        return []

    try:
        return list(nx.ancestors(graph, node_id))
    except nx.NetworkXError:
        return []


def get_dependency_paths(
    graph: nx.DiGraph,
    source: str,
    target: str,
    max_paths: int = 10,
) -> list[list[str]]:
    """
    Find all simple paths from source to target.

    Args:
        graph: Directed dependency graph
        source: Starting node ID
        target: Target node ID
        max_paths: Maximum number of paths to return

    Returns:
        List of paths (each path is a list of node IDs)
    """
    if not graph.has_node(source) or not graph.has_node(target):
        return []

    try:
        paths = list(nx.all_simple_paths(graph, source, target))
        return paths[:max_paths]
    except nx.NetworkXError:
        return []


def get_upstream_paths_to_vulnerable(
    graph: nx.DiGraph,
    vulnerable_node: str,
    max_paths_per_dependent: int = 5,
) -> dict[str, list[list[str]]]:
    """
    Find dependency paths from each upstream dependent to a vulnerable package.

    Args:
        graph: Directed dependency graph
        vulnerable_node: Node ID of the vulnerable package
        max_paths_per_dependent: Max paths to return per dependent

    Returns:
        Dict mapping dependent node ID to list of paths to vulnerable node
    """
    if not graph.has_node(vulnerable_node):
        return {}

    transitive_dependents = get_transitive_dependents(graph, vulnerable_node)
    direct_dependents = get_direct_dependents(graph, vulnerable_node)

    all_dependents = set(transitive_dependents) | set(direct_dependents)

    result = {}
    for dependent in all_dependents:
        paths = get_dependency_paths(graph, dependent, vulnerable_node, max_paths_per_dependent)
        if paths:
            result[dependent] = paths

    return result


def get_downstream_impact_set(graph: nx.DiGraph, node_id: str) -> set[str]:
    """
    Get all packages affected if the given package is compromised.

    This includes the package itself and all its transitive dependents.

    Args:
        graph: Directed dependency graph
        node_id: Package node ID

    Returns:
        Set of affected node IDs
    """
    if not graph.has_node(node_id):
        return set()

    dependents = get_transitive_dependents(graph, node_id)
    return set(dependents) | {node_id}