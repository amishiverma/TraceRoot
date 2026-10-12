"""
Dependency graph builder for DevSecOps scanner.

Constructs a directed graph from normalized dependency data using NetworkX.
Each node represents a specific package version (e.g., "express@4.18.2").
Edges represent parent → dependency relationships.
"""

import networkx as nx
from typing import Any


def _validate_package_record(record: dict[str, Any], index: int) -> None:
    """Validate a single package record has required fields."""
    if not isinstance(record, dict):
        raise ValueError(f"Package record at index {index} must be a dictionary")

    if "name" not in record:
        raise ValueError(f"Package record at index {index} missing required field 'name'")

    if "version" not in record:
        raise ValueError(f"Package record at index {index} missing required field 'version'")

    name = record["name"]
    version = record["version"]

    if not isinstance(name, str) or not name.strip():
        raise ValueError(f"Package record at index {index}: 'name' must be a non-empty string")

    if not isinstance(version, str) or not version.strip():
        raise ValueError(f"Package record at index {index}: 'version' must be a non-empty string")

    if "dependencies" in record and not isinstance(record["dependencies"], list):
        raise ValueError(f"Package record at index {index}: 'dependencies' must be a list")


def _make_node_id(name: str, version: str) -> str:
    """Create a unique node identifier for a package version."""
    return f"{name}@{version}"


def _is_version_range(version: str) -> bool:
    """Check if version string appears to be a range rather than a resolved version.

    Prerelease versions like '1.0.0-alpha.1' or '1.0.0-beta.2' are NOT ranges.
    Range indicators: ^, ~, >, <, =, ||, x, X, *, or hyphen used as range separator (e.g., '1.0.0 - 2.0.0')
    """
    version = version.strip()

    if version in ("*", "latest"):
        return True

    if any(op in version for op in ["||", ">=", "<=", ">", "<", "="]):
        return True

    if version.startswith(("^", "~")):
        return True

    parts = version.split(".")
    if any(part.lower() in ("x", "X", "*") for part in parts):
        return True

    if " - " in version:
        return True

    return False


def build_dependency_graph(dependencies: list[dict[str, Any]]) -> nx.DiGraph:
    """
    Build a directed dependency graph from normalized dependency data.

    Args:
        dependencies: List of package records, each containing:
            - name: Package name (str)
            - version: Resolved version string (str)
            - dependencies: List of dependency records with name and version

    Returns:
        nx.DiGraph: Directed graph with nodes as package@version and edges parent → dependency

    Raises:
        ValueError: If input is malformed or contains version ranges instead of resolved versions
    """
    graph = nx.DiGraph()

    if not dependencies:
        return graph

    for idx, record in enumerate(dependencies):
        _validate_package_record(record, idx)

        name = record["name"].strip()
        version = record["version"].strip()

        if _is_version_range(version):
            raise ValueError(
                f"Package '{name}' has version range '{version}' instead of resolved version. "
                "Graph builder requires resolved versions (e.g., '4.18.2', not '^4.18.0'). "
                "Ensure lockfile normalization has been performed before calling this function."
            )

        node_id = _make_node_id(name, version)

        if not graph.has_node(node_id):
            graph.add_node(node_id, name=name, version=version, incomplete=False)
        else:
            existing = graph.nodes[node_id]
            if existing.get("name") != name or existing.get("version") != version:
                raise ValueError(f"Node ID collision: {node_id} has conflicting metadata")
            graph.nodes[node_id]["incomplete"] = False

        deps = record.get("dependencies", [])
        for dep_idx, dep in enumerate(deps):
            if not isinstance(dep, dict):
                raise ValueError(
                    f"Package '{name}' dependency at index {dep_idx} must be a dictionary"
                )

            if "name" not in dep:
                raise ValueError(
                    f"Package '{name}' dependency at index {dep_idx} missing required field 'name'"
                )

            if "version" not in dep:
                raise ValueError(
                    f"Package '{name}' dependency at index {dep_idx} missing required field 'version'"
                )

            dep_name = dep["name"].strip()
            dep_version = dep["version"].strip()

            if not dep_name:
                raise ValueError(f"Package '{name}' dependency at index {dep_idx}: 'name' cannot be empty")

            if not dep_version:
                raise ValueError(f"Package '{name}' dependency at index {dep_idx}: 'version' cannot be empty")

            if _is_version_range(dep_version):
                raise ValueError(
                    f"Package '{name}' dependency '{dep_name}' has version range '{dep_version}' "
                    "instead of resolved version. Graph builder requires resolved versions."
                )

            dep_node_id = _make_node_id(dep_name, dep_version)

            if not graph.has_node(dep_node_id):
                graph.add_node(dep_node_id, name=dep_name, version=dep_version, incomplete=True)
            else:
                if graph.nodes[dep_node_id].get("incomplete", False):
                    graph.nodes[dep_node_id]["incomplete"] = False

            graph.add_edge(node_id, dep_node_id)

    return graph