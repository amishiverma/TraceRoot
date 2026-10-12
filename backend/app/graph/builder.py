"""
Dependency graph builder for DevSecOps scanner - Phase 3.

Constructs a directed graph from dependency data using NetworkX.
Supports both:
1. Flat manifest format (package, version, parent, vulnerabilities, npm_metadata)
2. Tree-based dependency structure (name, version, dependencies)
"""

import networkx as nx
from typing import Any


def _is_version_range(version: str) -> bool:
    """Check if version string appears to be a range rather than a resolved version."""
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


def _validate_package_record(record: dict[str, Any], index: int) -> None:
    """Validate a single package record has required fields."""
    if not isinstance(record, dict):
        raise ValueError(f"Package record at index {index} must be a dictionary")

    if "parent" in record:
        # Flat manifest format
        if "package" not in record:
            raise ValueError(f"Package record at index {index} missing required field 'package'")
        if "version" not in record:
            raise ValueError(f"Package record at index {index} missing required field 'version'")

        package = record["package"]
        version = record["version"]
        parent = record["parent"]

        if not isinstance(package, str) or not package.strip():
            raise ValueError(f"Package record at index {index}: 'package' must be a non-empty string")
        if not isinstance(version, str) or not version.strip():
            raise ValueError(f"Package record at index {index}: 'version' must be a non-empty string")
        if not isinstance(parent, str) or not parent.strip():
            raise ValueError(f"Package record at index {index}: 'parent' must be a non-empty string")
    else:
        # Tree-based dependency format (Param's original schema)
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


def _make_node_id(package: str, version: str) -> str:
    """Create a unique node identifier for a package version."""
    return f"{package}@{version}"


def build_dependency_graph(manifest: list[dict[str, Any]]) -> nx.DiGraph:
    """
    Build a directed dependency graph from a manifest or dependency list.

    Args:
        manifest: List of package records, supporting both:
            - Flat manifest: records with 'package', 'version', 'parent',
              'vulnerabilities', and 'npm_metadata'
            - Tree list: records with 'name', 'version', and 'dependencies'

    Returns:
        nx.DiGraph: Directed graph with nodes as package@version and edges parent -> child.
    """
    graph = nx.DiGraph()

    if not manifest:
        return graph

    is_flat_manifest = any("parent" in r for r in manifest if isinstance(r, dict))

    if is_flat_manifest:
        # Add root node explicitly to represent the repository
        graph.add_node("root", name="root", version="", vulnerabilities=[], npm_metadata={}, incomplete=False)

        # First pass: add all nodes from manifest with attributes
        for idx, record in enumerate(manifest):
            _validate_package_record(record, idx)

            package = record["package"].strip()
            version = record["version"].strip()

            vulnerabilities = record.get("vulnerabilities", [])
            npm_metadata = record.get("npm_metadata", {})

            if not isinstance(vulnerabilities, list):
                vulnerabilities = []
            if not isinstance(npm_metadata, dict):
                npm_metadata = {}

            node_id = _make_node_id(package, version)

            if not graph.has_node(node_id):
                graph.add_node(
                    node_id,
                    name=package,
                    version=version,
                    vulnerabilities=vulnerabilities,
                    npm_metadata=npm_metadata,
                    incomplete=False,
                )
            else:
                existing = graph.nodes[node_id]
                if existing.get("name") != package or existing.get("version") != version:
                    raise ValueError(f"Node ID collision: {node_id} has conflicting metadata")
                graph.nodes[node_id]["vulnerabilities"] = vulnerabilities
                graph.nodes[node_id]["npm_metadata"] = npm_metadata
                graph.nodes[node_id]["incomplete"] = False

        # Second pass: add edges parent -> child
        for idx, record in enumerate(manifest):
            package = record["package"].strip()
            version = record["version"].strip()
            parent = record["parent"].strip()

            child_node_id = _make_node_id(package, version)

            if parent == "root":
                graph.add_edge("root", child_node_id)
            else:
                parent_nodes = [n for n in graph.nodes if graph.nodes[n].get("name") == parent]

                if parent_nodes:
                    parent_node_id = parent_nodes[0]
                else:
                    # Sliced parent fallback: create placeholder with incomplete=True
                    parent_node_id = _make_node_id(parent, "unknown")
                    if not graph.has_node(parent_node_id):
                        graph.add_node(
                            parent_node_id,
                            name=parent,
                            version="unknown",
                            vulnerabilities=[],
                            npm_metadata={},
                            incomplete=True,
                        )

                graph.add_edge(parent_node_id, child_node_id)

    else:
        # Tree-based dependency format (Param's original implementation & test suite)
        for idx, record in enumerate(manifest):
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