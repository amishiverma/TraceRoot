"""
Tests for API response parsing and graph construction from API format.
"""

import json
import pytest
from pathlib import Path
import networkx as nx
from app.graph.builder import (
    build_graph_from_api_response,
    _extract_advisory_ids,
    _determine_version_precision,
    _make_node_id,
    _is_version_range,
)

DUMMY_RESPONSE_PATH = Path(__file__).resolve().parent.parent / "dummy_response.json.json"


def _load_dummy_response() -> dict:
    """Load the dummy response from the JSON file."""
    with open(DUMMY_RESPONSE_PATH, "r") as f:
        return json.load(f)


class TestAPIResponseHelpers:
    def test_extract_advisory_ids(self):
        vulns = [
            {"id": "GHSA-123", "summary": "test"},
            {"id": "GHSA-456", "summary": "test2"},
            {"summary": "no id"},
        ]
        ids = _extract_advisory_ids(vulns)
        assert ids == ["GHSA-123", "GHSA-456"]

    def test_extract_advisory_ids_empty(self):
        assert _extract_advisory_ids([]) == []
        assert _extract_advisory_ids([{}]) == []

    def test_determine_version_precision_range(self):
        assert _determine_version_precision("^2.0.0") == "range"
        assert _determine_version_precision("~1.0.0") == "range"
        assert _determine_version_precision(">=1.0.0") == "range"

    def test_determine_version_precision_resolved(self):
        assert _determine_version_precision("2.0.1") == "resolved"
        assert _determine_version_precision("1.0.0-alpha.1") == "resolved"
        assert _determine_version_precision("1.2.3") == "resolved"


class TestBuildGraphFromAPIResponse:
    def test_loads_dummy_response(self):
        response = _load_dummy_response()
        graph = build_graph_from_api_response(response)

        assert isinstance(graph, nx.DiGraph)
        assert graph.number_of_nodes() == 5  # accepts, body-parser, content-disposition, content-type, cookie
        assert graph.number_of_edges() == 0  # No dependency edges in API response

    def test_transaction_hash_preserved(self):
        response = _load_dummy_response()
        graph = build_graph_from_api_response(response)

        assert graph.graph["transaction_hash"] == response["transaction_hash"]
        assert graph.graph["graph_complete"] is False
        assert graph.graph["source"] == "api_response"

    def test_package_names_from_package_field(self):
        response = _load_dummy_response()
        graph = build_graph_from_api_response(response)

        # Check node IDs use package name from "package" field
        assert graph.has_node("accepts@^2.0.0")
        assert graph.has_node("body-parser@^2.3.0")
        assert graph.has_node("content-disposition@^2.0.1")
        assert graph.has_node("content-type@^2.0.0")
        assert graph.has_node("cookie@^0.7.1")

    def test_version_preserved_as_supplied(self):
        response = _load_dummy_response()
        graph = build_graph_from_api_response(response)

        node = graph.nodes["accepts@^2.0.0"]
        assert node["version"] == "^2.0.0"
        assert node["version_precision"] == "range"

    def test_version_precision_marked(self):
        response = _load_dummy_response()
        graph = build_graph_from_api_response(response)

        for node_id, node_data in graph.nodes(data=True):
            assert "version_precision" in node_data
            assert node_data["version_precision"] in ("range", "resolved")
            # All versions in dummy response are ranges
            assert node_data["version_precision"] == "range"

    def test_vulnerability_count_preserved(self):
        response = _load_dummy_response()
        graph = build_graph_from_api_response(response)

        # accepts has no vulnerabilities
        accepts = graph.nodes["accepts@^2.0.0"]
        assert accepts["vulnerability_count"] == 0
        assert accepts["vulnerability_advisory_ids"] == []

        # body-parser has 2 vulnerabilities
        body_parser = graph.nodes["body-parser@^2.3.0"]
        assert body_parser["vulnerability_count"] == 2
        assert "GHSA-qwcr-r2fm-qrc7" in body_parser["vulnerability_advisory_ids"]
        assert "GHSA-v422-hmwv-36x6" in body_parser["vulnerability_advisory_ids"]

        # cookie has 1 vulnerability
        cookie = graph.nodes["cookie@^0.7.1"]
        assert cookie["vulnerability_count"] == 1
        assert "GHSA-pxg6-pf52-xh8x" in cookie["vulnerability_advisory_ids"]

    def test_npm_metadata_preserved(self):
        response = _load_dummy_response()
        graph = build_graph_from_api_response(response)

        accepts = graph.nodes["accepts@^2.0.0"]
        assert "npm_maintainers" in accepts
        assert "npm_times" in accepts
        assert len(accepts["npm_maintainers"]) == 4
        assert accepts["npm_maintainers"][0]["name"] == "ulisesgascon"
        assert "2.0.0" in accepts["npm_times"]

    def test_no_edges_fabricated(self):
        response = _load_dummy_response()
        graph = build_graph_from_api_response(response)

        assert graph.number_of_edges() == 0

    def test_incomplete_flag_set(self):
        response = _load_dummy_response()
        graph = build_graph_from_api_response(response)

        for node_id, node_data in graph.nodes(data=True):
            assert node_data["incomplete"] is True

    def test_empty_dependencies_array(self):
        response = {"transaction_hash": "test", "dependencies": []}
        graph = build_graph_from_api_response(response)

        assert graph.number_of_nodes() == 0
        assert graph.number_of_edges() == 0
        assert graph.graph["transaction_hash"] == "test"

    def test_missing_dependencies_raises(self):
        response = {"transaction_hash": "test"}
        with pytest.raises(ValueError, match="missing required 'dependencies'"):
            build_graph_from_api_response(response)

    def test_dependencies_not_list_raises(self):
        response = {"transaction_hash": "test", "dependencies": "not-a-list"}
        with pytest.raises(ValueError, match="'dependencies' must be a list"):
            build_graph_from_api_response(response)

    def test_missing_package_field_raises(self):
        response = {"dependencies": [{"version": "1.0.0"}]}
        with pytest.raises(ValueError, match="missing required field 'package'"):
            build_graph_from_api_response(response)

    def test_missing_version_field_raises(self):
        response = {"dependencies": [{"package": "express"}]}
        with pytest.raises(ValueError, match="missing required field 'version'"):
            build_graph_from_api_response(response)

    def test_empty_package_name_raises(self):
        response = {"dependencies": [{"package": "", "version": "1.0.0"}]}
        with pytest.raises(ValueError, match="'package' cannot be empty"):
            build_graph_from_api_response(response)

    def test_empty_version_raises(self):
        response = {"dependencies": [{"package": "express", "version": ""}]}
        with pytest.raises(ValueError, match="'version' cannot be empty"):
            build_graph_from_api_response(response)

    def test_malformed_vulnerabilities_handled(self):
        response = {
            "dependencies": [
                {"package": "test", "version": "1.0.0", "vulnerabilities": "not-a-list"}
            ]
        }
        graph = build_graph_from_api_response(response)
        node = graph.nodes["test@1.0.0"]
        assert node["vulnerability_count"] == 0

    def test_malformed_npm_metadata_handled(self):
        response = {
            "dependencies": [
                {"package": "test", "version": "1.0.0", "npm_metadata": "not-a-dict"}
            ]
        }
        graph = build_graph_from_api_response(response)
        node = graph.nodes["test@1.0.0"]
        assert node["npm_maintainers"] == []
        assert node["npm_times"] == {}

    def test_duplicate_packages_merged(self):
        response = {
            "dependencies": [
                {"package": "express", "version": "4.18.2", "vulnerabilities": []},
                {"package": "express", "version": "4.18.2", "vulnerabilities": [{"id": "GHSA-123"}]},
            ]
        }
        graph = build_graph_from_api_response(response)
        assert graph.number_of_nodes() == 1
        node = graph.nodes["express@4.18.2"]
        assert node["vulnerability_count"] == 1
        assert "GHSA-123" in node["vulnerability_advisory_ids"]


class TestIntegrationWithDummyResponse:
    def test_full_dummy_response_parses(self):
        """Integration test with the actual dummy response file."""
        response = _load_dummy_response()
        graph = build_graph_from_api_response(response)

        # Verify all 5 packages
        assert graph.number_of_nodes() == 5
        assert graph.number_of_edges() == 0

        # Verify transaction hash
        assert graph.graph["transaction_hash"] == response["transaction_hash"]

        # Verify each package has expected structure
        expected_packages = {
            "accepts@^2.0.0": {"vulns": 0, "maintainers": 4},
            "body-parser@^2.3.0": {"vulns": 2, "maintainers": 4},
            "content-disposition@^2.0.1": {"vulns": 0, "maintainers": 4},
            "content-type@^2.0.0": {"vulns": 0, "maintainers": 3},
            "cookie@^0.7.1": {"vulns": 1, "maintainers": 3},
        }

        for node_id, expected in expected_packages.items():
            assert graph.has_node(node_id), f"Missing node: {node_id}"
            node = graph.nodes[node_id]
            assert node["vulnerability_count"] == expected["vulns"]
            assert len(node["npm_maintainers"]) == expected["maintainers"]
            assert node["version_precision"] == "range"
            assert node["incomplete"] is True