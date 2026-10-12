"""
Graph analysis package for DevSecOps scanner.
"""

from app.graph.builder import build_dependency_graph
from app.graph.metrics import (
    calculate_graph_metrics,
    calculate_package_metrics,
    GraphMetrics,
    PackageMetrics,
)
from app.graph.traversal import (
    get_direct_dependencies,
    get_transitive_dependencies,
    get_direct_dependents,
    get_transitive_dependents,
    get_dependency_paths,
    get_upstream_paths_to_vulnerable,
    get_downstream_impact_set,
)
from app.graph.impact_analysis import (
    analyze_impact,
    ImpactAnalysis,
)

__all__ = [
    "build_dependency_graph",
    "calculate_graph_metrics",
    "calculate_package_metrics",
    "GraphMetrics",
    "PackageMetrics",
    "get_direct_dependencies",
    "get_transitive_dependencies",
    "get_direct_dependents",
    "get_transitive_dependents",
    "get_dependency_paths",
    "get_upstream_paths_to_vulnerable",
    "get_downstream_impact_set",
    "analyze_impact",
    "ImpactAnalysis",
]