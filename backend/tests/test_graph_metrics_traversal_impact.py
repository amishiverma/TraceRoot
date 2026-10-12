"""
Tests for graph metrics, traversal, and impact analysis.
"""

import pytest
import networkx as nx
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


def _make_test_graph() -> nx.DiGraph:
    """Create a standard test graph."""
    deps = [
        {
            "name": "app",
            "version": "1.0.0",
            "dependencies": [
                {"name": "lib-a", "version": "1.0.0"},
                {"name": "lib-b", "version": "1.0.0"},
            ],
        },
        {
            "name": "lib-a",
            "version": "1.0.0",
            "dependencies": [
                {"name": "lib-c", "version": "1.0.0"},
                {"name": "lib-d", "version": "1.0.0"},
            ],
        },
        {
            "name": "lib-b",
            "version": "1.0.0",
            "dependencies": [
                {"name": "lib-c", "version": "1.0.0"},
                {"name": "lib-e", "version": "1.0.0"},
            ],
        },
        {"name": "lib-c", "version": "1.0.0", "dependencies": []},
        {"name": "lib-d", "version": "1.0.0", "dependencies": []},
        {"name": "lib-e", "version": "1.0.0", "dependencies": []},
    ]
    return build_dependency_graph(deps)


def _make_cyclic_graph() -> nx.DiGraph:
    """Create a graph with a cycle."""
    deps = [
        {"name": "pkg-a", "version": "1.0.0", "dependencies": [{"name": "pkg-b", "version": "1.0.0"}]},
        {"name": "pkg-b", "version": "1.0.0", "dependencies": [{"name": "pkg-c", "version": "1.0.0"}]},
        {"name": "pkg-c", "version": "1.0.0", "dependencies": [{"name": "pkg-a", "version": "1.0.0"}]},
    ]
    return build_dependency_graph(deps)


def _make_multi_version_graph() -> nx.DiGraph:
    """Create a graph with multiple versions of the same package."""
    deps = [
        {
            "name": "app",
            "version": "1.0.0",
            "dependencies": [
                {"name": "lib", "version": "1.0.0"},
            ],
        },
        {
            "name": "lib",
            "version": "1.0.0",
            "dependencies": [
                {"name": "lodash", "version": "4.17.15"},
            ],
        },
        {
            "name": "other",
            "version": "1.0.0",
            "dependencies": [
                {"name": "lodash", "version": "4.17.21"},
            ],
        },
        {"name": "lodash", "version": "4.17.15", "dependencies": []},
        {"name": "lodash", "version": "4.17.21", "dependencies": []},
    ]
    return build_dependency_graph(deps)


class TestGraphMetrics:
    def test_empty_graph_metrics(self):
        graph = nx.DiGraph()
        metrics = calculate_graph_metrics(graph)

        assert isinstance(metrics, GraphMetrics)
        assert metrics.total_packages == 0
        assert metrics.total_dependencies == 0
        assert metrics.has_cycles is False
        assert metrics.cycles == []
        assert metrics.betweenness_centrality == {}

    def test_single_package_metrics(self):
        graph = build_dependency_graph([{"name": "express", "version": "4.18.2", "dependencies": []}])
        metrics = calculate_graph_metrics(graph)

        assert metrics.total_packages == 1
        assert metrics.total_dependencies == 0
        assert metrics.has_cycles is False
        assert "express@4.18.2" in metrics.betweenness_centrality

    def test_standard_graph_metrics(self):
        graph = _make_test_graph()
        metrics = calculate_graph_metrics(graph)

        assert metrics.total_packages == 6
        assert metrics.total_dependencies == 6
        assert metrics.has_cycles is False
        assert len(metrics.betweenness_centrality) == 6

    def test_cyclic_graph_metrics(self):
        graph = _make_cyclic_graph()
        metrics = calculate_graph_metrics(graph)

        assert metrics.total_packages == 3
        assert metrics.total_dependencies == 3
        assert metrics.has_cycles is True
        assert len(metrics.cycles) > 0

    def test_package_metrics_empty_graph(self):
        graph = nx.DiGraph()
        metrics = calculate_package_metrics(graph)
        assert metrics == {}

    def test_package_metrics_standard_graph(self):
        graph = _make_test_graph()
        metrics = calculate_package_metrics(graph)

        assert len(metrics) == 6

        # app has 2 direct deps, 5 transitive deps (includes direct)
        app_metrics = metrics["app@1.0.0"]
        assert app_metrics.direct_dependencies == 2
        assert app_metrics.transitive_dependencies == 5
        assert app_metrics.direct_dependents == 0
        assert app_metrics.transitive_dependents == 0

        # lib-c has 0 direct deps, 0 transitive, 2 direct dependents (lib-a, lib-b), 3 transitive (lib-a, lib-b, app)
        lib_c_metrics = metrics["lib-c@1.0.0"]
        assert lib_c_metrics.direct_dependencies == 0
        assert lib_c_metrics.transitive_dependencies == 0
        assert lib_c_metrics.direct_dependents == 2
        assert lib_c_metrics.transitive_dependents == 3

    def test_package_metrics_isolated_node(self):
        graph = build_dependency_graph([
            {"name": "pkg-a", "version": "1.0.0", "dependencies": []},
            {"name": "pkg-b", "version": "1.0.0", "dependencies": []},
        ])
        metrics = calculate_package_metrics(graph)

        assert metrics["pkg-a@1.0.0"].direct_dependencies == 0
        assert metrics["pkg-a@1.0.0"].transitive_dependencies == 0
        assert metrics["pkg-a@1.0.0"].direct_dependents == 0


class TestTraversal:
    def test_empty_graph_traversal(self):
        graph = nx.DiGraph()

        assert get_direct_dependencies(graph, "missing") == []
        assert get_transitive_dependencies(graph, "missing") == []
        assert get_direct_dependents(graph, "missing") == []
        assert get_transitive_dependents(graph, "missing") == []

    def test_direct_dependencies(self):
        graph = _make_test_graph()

        deps = get_direct_dependencies(graph, "app@1.0.0")
        assert set(deps) == {"lib-a@1.0.0", "lib-b@1.0.0"}

        deps = get_direct_dependencies(graph, "lib-c@1.0.0")
        assert deps == []

    def test_transitive_dependencies(self):
        graph = _make_test_graph()

        deps = get_transitive_dependencies(graph, "app@1.0.0")
        assert set(deps) == {"lib-a@1.0.0", "lib-b@1.0.0", "lib-c@1.0.0", "lib-d@1.0.0", "lib-e@1.0.0"}

        deps = get_transitive_dependencies(graph, "lib-a@1.0.0")
        assert set(deps) == {"lib-c@1.0.0", "lib-d@1.0.0"}

        deps = get_transitive_dependencies(graph, "lib-c@1.0.0")
        assert deps == []

    def test_direct_dependents(self):
        graph = _make_test_graph()

        dependents = get_direct_dependents(graph, "lib-c@1.0.0")
        assert set(dependents) == {"lib-a@1.0.0", "lib-b@1.0.0"}

        dependents = get_direct_dependents(graph, "app@1.0.0")
        assert dependents == []

    def test_transitive_dependents(self):
        graph = _make_test_graph()

        dependents = get_transitive_dependents(graph, "lib-c@1.0.0")
        assert set(dependents) == {"lib-a@1.0.0", "lib-b@1.0.0", "app@1.0.0"}

        dependents = get_transitive_dependents(graph, "lib-d@1.0.0")
        assert set(dependents) == {"lib-a@1.0.0", "app@1.0.0"}

        dependents = get_transitive_dependents(graph, "app@1.0.0")
        assert dependents == []

    def test_dependency_paths(self):
        graph = _make_test_graph()

        paths = get_dependency_paths(graph, "app@1.0.0", "lib-c@1.0.0")
        assert len(paths) == 2
        assert ["app@1.0.0", "lib-a@1.0.0", "lib-c@1.0.0"] in paths
        assert ["app@1.0.0", "lib-b@1.0.0", "lib-c@1.0.0"] in paths

        # No path
        paths = get_dependency_paths(graph, "lib-c@1.0.0", "app@1.0.0")
        assert paths == []

    def test_upstream_paths_to_vulnerable(self):
        graph = _make_test_graph()

        paths = get_upstream_paths_to_vulnerable(graph, "lib-c@1.0.0")

        assert "lib-a@1.0.0" in paths
        assert "lib-b@1.0.0" in paths
        assert "app@1.0.0" in paths

        # lib-a and lib-b have direct paths
        assert ["lib-a@1.0.0", "lib-c@1.0.0"] in paths["lib-a@1.0.0"]
        assert ["lib-b@1.0.0", "lib-c@1.0.0"] in paths["lib-b@1.0.0"]

        # app has two paths
        assert len(paths["app@1.0.0"]) == 2

    def test_downstream_impact_set(self):
        graph = _make_test_graph()

        impact = get_downstream_impact_set(graph, "lib-c@1.0.0")
        assert impact == {"lib-c@1.0.0", "lib-a@1.0.0", "lib-b@1.0.0", "app@1.0.0"}

        impact = get_downstream_impact_set(graph, "app@1.0.0")
        assert impact == {"app@1.0.0"}

    def test_cyclic_graph_traversal(self):
        graph = _make_cyclic_graph()

        # Should not include starting node in results
        deps = get_transitive_dependencies(graph, "pkg-a@1.0.0")
        assert "pkg-a@1.0.0" not in deps
        assert set(deps) == {"pkg-b@1.0.0", "pkg-c@1.0.0"}

        dependents = get_transitive_dependents(graph, "pkg-a@1.0.0")
        assert "pkg-a@1.0.0" not in dependents
        assert set(dependents) == {"pkg-b@1.0.0", "pkg-c@1.0.0"}

    def test_multi_version_traversal(self):
        graph = _make_multi_version_graph()

        # app@1.0.0 depends on lib@1.0.0 which depends on lodash@4.17.15
        deps = get_transitive_dependencies(graph, "app@1.0.0")
        assert "lodash@4.17.15" in deps
        assert "lodash@4.17.21" not in deps

        # other@1.0.0 depends on lodash@4.17.21
        deps = get_transitive_dependents(graph, "lodash@4.17.21")
        assert "other@1.0.0" in deps
        assert "app@1.0.0" not in deps


class TestImpactAnalysis:
    def test_unknown_target_raises(self):
        graph = _make_test_graph()

        with pytest.raises(ValueError, match="not found in graph"):
            analyze_impact(graph, "nonexistent@1.0.0")

    def test_impact_analysis_leaf_package(self):
        graph = _make_test_graph()

        result = analyze_impact(graph, "lib-d@1.0.0")

        assert isinstance(result, ImpactAnalysis)
        assert result.target_package["node_id"] == "lib-d@1.0.0"
        assert result.direct_upstream_dependents == ["lib-a@1.0.0"]
        # transitive_dependents includes direct, so lib-a is also in transitive
        assert set(result.transitive_upstream_dependents) == {"lib-a@1.0.0", "app@1.0.0"}
        assert result.total_affected_upstream == 2
        assert "lib-a@1.0.0" in result.dependency_paths
        assert "app@1.0.0" in result.dependency_paths
        assert 0.0 <= result.structural_impact_score <= 1.0

    def test_impact_analysis_shared_dependency(self):
        graph = _make_test_graph()

        result = analyze_impact(graph, "lib-c@1.0.0")

        assert result.target_package["node_id"] == "lib-c@1.0.0"
        assert set(result.direct_upstream_dependents) == {"lib-a@1.0.0", "lib-b@1.0.0"}
        # transitive includes direct
        assert set(result.transitive_upstream_dependents) == {"lib-a@1.0.0", "lib-b@1.0.0", "app@1.0.0"}
        assert result.total_affected_upstream == 3
        assert len(result.dependency_paths) == 3

    def test_impact_analysis_root_package(self):
        graph = _make_test_graph()

        result = analyze_impact(graph, "app@1.0.0")

        assert result.target_package["node_id"] == "app@1.0.0"
        assert result.direct_upstream_dependents == []
        assert result.transitive_upstream_dependents == []
        assert result.total_affected_upstream == 0
        assert result.dependency_paths == {}
        # Root package with no dependents should have low impact
        assert result.structural_impact_score >= 0.0

    def test_impact_analysis_cyclic_graph(self):
        graph = _make_cyclic_graph()

        result = analyze_impact(graph, "pkg-a@1.0.0")

        assert result.target_package["node_id"] == "pkg-a@1.0.0"
        # In a cycle, each package depends on the others
        assert result.total_affected_upstream == 2
        assert 0.0 <= result.structural_impact_score <= 1.0

    def test_impact_analysis_multi_version(self):
        graph = _make_multi_version_graph()

        result = analyze_impact(graph, "lodash@4.17.15")

        assert result.target_package["node_id"] == "lodash@4.17.15"
        # Only lib@1.0.0 and app@1.0.0 depend on this version
        assert result.total_affected_upstream == 2
        assert "lib@1.0.0" in result.direct_upstream_dependents
        assert "app@1.0.0" in result.transitive_upstream_dependents

        # The other version should not be affected
        assert "lodash@4.17.21" not in result.dependency_paths

    def test_impact_analysis_to_dict(self):
        graph = _make_test_graph()

        result = analyze_impact(graph, "lib-c@1.0.0")
        d = result.to_dict()

        assert "target_package" in d
        assert "direct_upstream_dependents" in d
        assert "transitive_upstream_dependents" in d
        assert "total_affected_upstream" in d
        assert "dependency_paths" in d
        assert "structural_impact_score" in d
        assert "affected_package_metrics" in d