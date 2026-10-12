"""
Tests for the dependency graph builder.
"""

import pytest
import networkx as nx
from app.graph.builder import build_dependency_graph, _make_node_id, _is_version_range


class TestNodeIdGeneration:
    def test_make_node_id_basic(self):
        assert _make_node_id("express", "4.18.2") == "express@4.18.2"

    def test_make_node_id_with_special_chars(self):
        assert _make_node_id("@scope/package", "1.0.0") == "@scope/package@1.0.0"


class TestVersionRangeDetection:
    def test_detects_caret_range(self):
        assert _is_version_range("^4.18.0") is True

    def test_detects_tilde_range(self):
        assert _is_version_range("~1.2.0") is True

    def test_detects_greater_than(self):
        assert _is_version_range(">=1.0.0") is True

    def test_detects_less_than(self):
        assert _is_version_range("<2.0.0") is True

    def test_detects_x_range(self):
        assert _is_version_range("1.x.0") is True

    def test_detects_star(self):
        assert _is_version_range("*") is True

    def test_detects_or(self):
        assert _is_version_range("1.0.0 || 2.0.0") is True

    def test_resolved_version_not_detected(self):
        assert _is_version_range("4.18.2") is False

    def test_exact_version_not_detected(self):
        assert _is_version_range("1.0.0") is False

    def test_prerelease_version_not_detected(self):
        assert _is_version_range("1.0.0-alpha.1") is False


class TestBuildDependencyGraph:
    def test_empty_input_returns_empty_graph(self):
        graph = build_dependency_graph([])
        assert isinstance(graph, nx.DiGraph)
        assert graph.number_of_nodes() == 0
        assert graph.number_of_edges() == 0

    def test_single_package_no_dependencies(self):
        deps = [{"name": "express", "version": "4.18.2", "dependencies": []}]
        graph = build_dependency_graph(deps)

        assert graph.number_of_nodes() == 1
        assert graph.number_of_edges() == 0
        assert graph.has_node("express@4.18.2")
        node = graph.nodes["express@4.18.2"]
        assert node["name"] == "express"
        assert node["version"] == "4.18.2"
        assert node.get("incomplete", False) is False

    def test_parent_to_dependency_edge_direction(self):
        deps = [
            {
                "name": "express",
                "version": "4.18.2",
                "dependencies": [
                    {"name": "body-parser", "version": "1.20.1"},
                    {"name": "cookie", "version": "0.6.0"},
                ],
            },
            {
                "name": "body-parser",
                "version": "1.20.1",
                "dependencies": [{"name": "qs", "version": "6.11.0"}],
            },
            {"name": "cookie", "version": "0.6.0", "dependencies": []},
            {"name": "qs", "version": "6.11.0", "dependencies": []},
        ]
        graph = build_dependency_graph(deps)

        assert graph.has_edge("express@4.18.2", "body-parser@1.20.1")
        assert graph.has_edge("express@4.18.2", "cookie@0.6.0")
        assert graph.has_edge("body-parser@1.20.1", "qs@6.11.0")

        assert not graph.has_edge("body-parser@1.20.1", "express@4.18.2")

    def test_package_metadata_preserved(self):
        deps = [{"name": "express", "version": "4.18.2", "dependencies": []}]
        graph = build_dependency_graph(deps)

        node = graph.nodes["express@4.18.2"]
        assert node["name"] == "express"
        assert node["version"] == "4.18.2"

    def test_missing_transitive_dependency_represented(self):
        deps = [
            {
                "name": "express",
                "version": "4.18.2",
                "dependencies": [{"name": "body-parser", "version": "1.20.1"}],
            }
        ]
        graph = build_dependency_graph(deps)

        assert graph.has_node("body-parser@1.20.1")
        assert graph.has_edge("express@4.18.2", "body-parser@1.20.1")

        dep_node = graph.nodes["body-parser@1.20.1"]
        assert dep_node["name"] == "body-parser"
        assert dep_node["version"] == "1.20.1"
        assert dep_node["incomplete"] is True

    def test_missing_transitive_marked_incomplete_then_completed(self):
        deps = [
            {
                "name": "express",
                "version": "4.18.2",
                "dependencies": [{"name": "body-parser", "version": "1.20.1"}],
            },
            {"name": "body-parser", "version": "1.20.1", "dependencies": []},
        ]
        graph = build_dependency_graph(deps)

        dep_node = graph.nodes["body-parser@1.20.1"]
        assert dep_node["incomplete"] is False

    def test_duplicate_relationships_not_duplicated(self):
        deps = [
            {
                "name": "express",
                "version": "4.18.2",
                "dependencies": [
                    {"name": "body-parser", "version": "1.20.1"},
                    {"name": "body-parser", "version": "1.20.1"},
                ],
            },
            {"name": "body-parser", "version": "1.20.1", "dependencies": []},
        ]
        graph = build_dependency_graph(deps)

        assert graph.number_of_edges() == 1
        assert graph.has_edge("express@4.18.2", "body-parser@1.20.1")

    def test_different_versions_same_package_distinct_nodes(self):
        deps = [
            {
                "name": "pkg-a",
                "version": "1.0.0",
                "dependencies": [{"name": "lodash", "version": "4.17.15"}],
            },
            {
                "name": "pkg-b",
                "version": "2.0.0",
                "dependencies": [{"name": "lodash", "version": "4.17.21"}],
            },
            {"name": "lodash", "version": "4.17.15", "dependencies": []},
            {"name": "lodash", "version": "4.17.21", "dependencies": []},
        ]
        graph = build_dependency_graph(deps)

        assert graph.has_node("lodash@4.17.15")
        assert graph.has_node("lodash@4.17.21")
        assert graph.number_of_nodes() == 4

        assert graph.has_edge("pkg-a@1.0.0", "lodash@4.17.15")
        assert graph.has_edge("pkg-b@2.0.0", "lodash@4.17.21")

    def test_malformed_input_missing_name_raises(self):
        deps = [{"version": "1.0.0", "dependencies": []}]
        with pytest.raises(ValueError, match="missing required field 'name'"):
            build_dependency_graph(deps)

    def test_malformed_input_missing_version_raises(self):
        deps = [{"name": "express", "dependencies": []}]
        with pytest.raises(ValueError, match="missing required field 'version'"):
            build_dependency_graph(deps)

    def test_malformed_input_empty_name_raises(self):
        deps = [{"name": "", "version": "1.0.0", "dependencies": []}]
        with pytest.raises(ValueError, match="'name' must be a non-empty string"):
            build_dependency_graph(deps)

    def test_malformed_input_empty_version_raises(self):
        deps = [{"name": "express", "version": "", "dependencies": []}]
        with pytest.raises(ValueError, match="'version' must be a non-empty string"):
            build_dependency_graph(deps)

    def test_malformed_input_not_a_list_raises(self):
        deps = {"name": "express", "version": "1.0.0", "dependencies": []}
        with pytest.raises(ValueError, match="must be a dictionary"):
            build_dependency_graph(deps)

    def test_malformed_dependency_not_a_dict_raises(self):
        deps = [
            {"name": "express", "version": "4.18.2", "dependencies": ["not-a-dict"]}
        ]
        with pytest.raises(ValueError, match="must be a dictionary"):
            build_dependency_graph(deps)

    def test_malformed_dependency_missing_name_raises(self):
        deps = [
            {"name": "express", "version": "4.18.2", "dependencies": [{"version": "1.0.0"}]}
        ]
        with pytest.raises(ValueError, match="missing required field 'name'"):
            build_dependency_graph(deps)

    def test_version_range_in_main_record_raises(self):
        deps = [{"name": "express", "version": "^4.18.0", "dependencies": []}]
        with pytest.raises(ValueError, match="version range"):
            build_dependency_graph(deps)

    def test_version_range_in_dependency_raises(self):
        deps = [
            {"name": "express", "version": "4.18.2", "dependencies": [{"name": "body-parser", "version": "^1.20.0"}]}
        ]
        with pytest.raises(ValueError, match="version range"):
            build_dependency_graph(deps)

    def test_cycle_handled_without_crash(self):
        deps = [
            {"name": "pkg-a", "version": "1.0.0", "dependencies": [{"name": "pkg-b", "version": "1.0.0"}]},
            {"name": "pkg-b", "version": "1.0.0", "dependencies": [{"name": "pkg-a", "version": "1.0.0"}]},
        ]
        graph = build_dependency_graph(deps)

        assert graph.has_edge("pkg-a@1.0.0", "pkg-b@1.0.0")
        assert graph.has_edge("pkg-b@1.0.0", "pkg-a@1.0.0")

        assert not nx.is_directed_acyclic_graph(graph)

    def test_complex_graph_structure(self):
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
        graph = build_dependency_graph(deps)

        assert graph.number_of_nodes() == 6
        assert graph.number_of_edges() == 6

        assert graph.has_edge("app@1.0.0", "lib-a@1.0.0")
        assert graph.has_edge("app@1.0.0", "lib-b@1.0.0")
        assert graph.has_edge("lib-a@1.0.0", "lib-c@1.0.0")
        assert graph.has_edge("lib-a@1.0.0", "lib-d@1.0.0")
        assert graph.has_edge("lib-b@1.0.0", "lib-c@1.0.0")
        assert graph.has_edge("lib-b@1.0.0", "lib-e@1.0.0")

        assert graph.nodes["lib-c@1.0.0"]["incomplete"] is False
        assert graph.nodes["lib-d@1.0.0"]["incomplete"] is False
        assert graph.nodes["lib-e@1.0.0"]["incomplete"] is False