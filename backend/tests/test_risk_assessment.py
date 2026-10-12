"""
Tests for the heuristic risk engine.

Uses deterministic fixtures. No real security findings are fabricated.
"""

import pytest
import networkx as nx
from app.risk.heuristic_rules import (
    SignalResult,
    evaluate_vulnerability_signal,
    evaluate_dormancy_signal,
    evaluate_maintainer_change_signal,
    _extract_release_timestamps,
    _find_dormancy_gaps,
    _version_in_range,
)
from app.risk.assessment import (
    RiskAssessment,
    assess_package_risk,
    assess_all_packages,
)
from app.graph.builder import build_graph_from_api_response


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_vuln(vuln_id, pkg_name, introduced="0", fixed=None):
    """Build a minimal OSV-style vulnerability object."""
    events = [{"introduced": introduced}]
    if fixed is not None:
        events.append({"fixed": fixed})
    return {
        "id": vuln_id,
        "summary": f"Test advisory {vuln_id}",
        "affected": [
            {
                "package": {"name": pkg_name, "ecosystem": "npm"},
                "ranges": [{"type": "SEMVER", "events": events}],
            }
        ],
    }


def _node(
    name="testpkg",
    version="1.0.0",
    version_precision="resolved",
    advisory_ids=None,
    vuln_count=0,
    maintainers=None,
    times=None,
):
    """Build a node_data dict as produced by build_graph_from_api_response."""
    return {
        "name": name,
        "version": version,
        "version_precision": version_precision,
        "vulnerability_count": vuln_count,
        "vulnerability_advisory_ids": advisory_ids or [],
        "npm_maintainers": maintainers or [],
        "npm_times": times or {},
        "incomplete": True,
    }


# ---------------------------------------------------------------------------
# Version-in-range helper tests
# ---------------------------------------------------------------------------

class TestVersionInRange:
    def test_version_in_vulnerable_range(self):
        assert _version_in_range("1.20.1", "0", "1.20.3") is True

    def test_version_at_fixed_not_vulnerable(self):
        assert _version_in_range("1.20.3", "0", "1.20.3") is False

    def test_version_above_fixed_not_vulnerable(self):
        assert _version_in_range("2.0.0", "0", "1.20.3") is False

    def test_version_before_introduced_not_vulnerable(self):
        assert _version_in_range("0.5.0", "1.0.0", "2.0.0") is False

    def test_unfixed_advisory(self):
        assert _version_in_range("5.0.0", "4.0.0", None) is True

    def test_malformed_version_returns_false(self):
        assert _version_in_range("not-a-version", "0", "1.0.0") is False


# ---------------------------------------------------------------------------
# RULE 1: Known vulnerability
# ---------------------------------------------------------------------------

class TestVulnerabilitySignal:
    def test_confirmed_applicable_vulnerability(self):
        node = _node(
            name="body-parser",
            version="1.20.1",
            version_precision="resolved",
            advisory_ids=["GHSA-qwcr-r2fm-qrc7"],
            vuln_count=1,
        )
        vulns = [_make_vuln("GHSA-qwcr-r2fm-qrc7", "body-parser", "0", "1.20.3")]

        result = evaluate_vulnerability_signal(node, vulns)

        assert result.status == "confirmed"
        assert result.points == 50
        assert "GHSA-qwcr-r2fm-qrc7" in str(result.evidence)
        assert result.evidence["resolved_version"] == "1.20.1"

    def test_unresolved_version_marks_unknown(self):
        """A supplied range like ^2.0.0 cannot confirm applicability."""
        node = _node(
            name="accepts",
            version="^2.0.0",
            version_precision="range",
            advisory_ids=["GHSA-x"],
            vuln_count=1,
        )
        vulns = [_make_vuln("GHSA-x", "accepts", "0", "2.0.5")]

        result = evaluate_vulnerability_signal(node, vulns)

        assert result.status == "unknown"
        assert result.points == 0
        assert "range" in result.explanation

    def test_advisory_not_affecting_resolved_version(self):
        """Advisory exists but fixed version is below the resolved version."""
        node = _node(
            name="body-parser",
            version="1.20.3",
            version_precision="resolved",
            advisory_ids=["GHSA-qwcr-r2fm-qrc7"],
            vuln_count=1,
        )
        vulns = [_make_vuln("GHSA-qwcr-r2fm-qrc7", "body-parser", "0", "1.20.3")]

        result = evaluate_vulnerability_signal(node, vulns)

        assert result.status == "not_detected"
        assert result.points == 0

    def test_no_vulnerabilities(self):
        node = _node(name="safe-pkg", version="1.0.0", version_precision="resolved")
        result = evaluate_vulnerability_signal(node, [])

        assert result.status == "not_detected"
        assert result.points == 0

    def test_advisory_for_different_package_ignored(self):
        node = _node(
            name="express",
            version="4.18.2",
            version_precision="resolved",
            advisory_ids=["GHSA-x"],
            vuln_count=1,
        )
        vulns = [_make_vuln("GHSA-x", "some-other-package", "0", "9.9.9")]

        result = evaluate_vulnerability_signal(node, vulns)

        assert result.status == "not_detected"
        assert result.points == 0


# ---------------------------------------------------------------------------
# RULE 2: Release after extended dormancy
# ---------------------------------------------------------------------------

class TestDormancySignal:
    def test_gap_of_at_least_two_years_confirmed(self):
        times = {
            "created": "2013-01-01T00:00:00Z",
            "modified": "2025-01-01T00:00:00Z",
            "1.0.0": "2013-01-01T00:00:00Z",
            "1.1.0": "2013-06-01T00:00:00Z",
            "2.0.0": "2018-01-01T00:00:00Z",  # ~4.5 year gap
        }
        node = _node(version="2.0.0", times=times)
        result = evaluate_dormancy_signal(node)

        assert result.status == "confirmed"
        assert result.points == 30
        assert result.evidence["max_gap_days"] >= 730
        assert result.evidence["gap_from_version"] == "1.1.0"
        assert result.evidence["gap_to_version"] == "2.0.0"

    def test_gap_shorter_than_two_years_not_detected(self):
        times = {
            "1.0.0": "2020-01-01T00:00:00Z",
            "1.1.0": "2021-06-01T00:00:00Z",  # ~1.4 year gap
            "2.0.0": "2022-01-01T00:00:00Z",
        }
        node = _node(version="2.0.0", times=times)
        result = evaluate_dormancy_signal(node)

        assert result.status == "not_detected"
        assert result.points == 0

    def test_invalid_timestamps_ignored(self):
        times = {
            "1.0.0": "not-a-timestamp",
            "2.0.0": "2022-01-01T00:00:00Z",
        }
        node = _node(version="2.0.0", times=times)
        result = evaluate_dormancy_signal(node)

        # Only one valid release -> insufficient history
        assert result.status == "not_detected"
        assert result.points == 0

    def test_empty_release_history(self):
        node = _node(version="1.0.0", times={})
        result = evaluate_dormancy_signal(node)

        assert result.status == "unknown"
        assert result.points == 0

    def test_modified_not_treated_as_release(self):
        """The 'modified' key must not be interpreted as a release."""
        times = {
            "created": "2010-01-01T00:00:00Z",
            "modified": "2030-01-01T00:00:00Z",  # far future - should be ignored
            "1.0.0": "2020-01-01T00:00:00Z",
            "1.1.0": "2020-06-01T00:00:00Z",
        }
        node = _node(version="1.1.0", times=times)
        result = evaluate_dormancy_signal(node)

        # If 'modified' were treated as release, we'd see a 2030 date in evidence
        assert result.status == "not_detected"
        for r in result.evidence.get("releases", []):
            assert "2030" not in r["date"]

    def test_release_extraction_helper(self):
        times = {
            "created": "2010-01-01T00:00:00Z",
            "modified": "2026-01-01T00:00:00Z",
            "1.0.0": "2012-01-01T00:00:00Z",
            "2.0.0": "2015-01-01T00:00:00Z",
        }
        releases = _extract_release_timestamps(times)
        assert len(releases) == 2
        assert releases[0][0] == "1.0.0"
        assert releases[1][0] == "2.0.0"

    def test_find_dormancy_gaps_helper(self):
        times = {
            "1.0.0": "2010-01-01T00:00:00Z",
            "1.1.0": "2010-06-01T00:00:00Z",
            "2.0.0": "2015-01-01T00:00:00Z",
        }
        releases = _extract_release_timestamps(times)
        gaps = _find_dormancy_gaps(releases)
        assert len(gaps) == 1
        assert gaps[0]["from_version"] == "1.1.0"
        assert gaps[0]["to_version"] == "2.0.0"


# ---------------------------------------------------------------------------
# RULE 3: Verified maintainer change
# ---------------------------------------------------------------------------

class TestMaintainerChangeSignal:
    def test_missing_historical_data_marks_unknown(self):
        maintainers = [{"name": "alice", "email": "a@x.com"}]
        node = _node(maintainers=maintainers)

        result = evaluate_maintainer_change_signal(node, historical_maintainers=None)

        assert result.status == "unknown"
        assert result.points == 0
        assert "historical" in result.explanation.lower()

    def test_verified_change_confirmed(self):
        current = [
            {"name": "alice", "email": "a@x.com"},
            {"name": "evil", "email": "evil@x.com"},
        ]
        historical = [{"name": "alice", "email": "a@x.com"}]

        node = _node(maintainers=current)
        result = evaluate_maintainer_change_signal(node, historical_maintainers=historical)

        assert result.status == "confirmed"
        assert result.points == 20
        assert result.evidence["added_maintainers"] == ["evil@x.com"]

    def test_no_change_not_detected(self):
        maintainers = [{"name": "alice", "email": "a@x.com"}]
        node = _node(maintainers=maintainers)

        result = evaluate_maintainer_change_signal(node, historical_maintainers=maintainers)

        assert result.status == "not_detected"
        assert result.points == 0

    def test_removed_maintainer_confirmed(self):
        current = []
        historical = [{"name": "alice", "email": "a@x.com"}]

        node = _node(maintainers=current)
        result = evaluate_maintainer_change_signal(node, historical_maintainers=historical)

        assert result.status == "confirmed"
        assert result.points == 20
        assert result.evidence["removed_maintainers"] == ["a@x.com"]


# ---------------------------------------------------------------------------
# Assessment integration
# ---------------------------------------------------------------------------

class TestRiskAssessment:
    def test_score_capped_at_100(self):
        """Confirmed vuln (50) + dormancy (30) + maintainer change (20) = 100.

        Adding more confirmed signals should not exceed 100.
        """
        node = _node(
            name="risky",
            version="1.0.0",
            version_precision="resolved",
            advisory_ids=["GHSA-1"],
            vuln_count=1,
            maintainers=[{"name": "new", "email": "new@x.com"}],
            times={
                "1.0.0": "2015-01-01T00:00:00Z",
                "2.0.0": "2020-01-01T00:00:00Z",  # >2yr gap before... wait:
            },
        )
        vulns = [_make_vuln("GHSA-1", "risky", "0", "2.0.0")]
        historical = [{"name": "old", "email": "old@x.com"}]

        assessment = assess_package_risk(node, vulns, historical)

        # 50 + 30 + 20 = 100 exactly; cap must not exceed 100
        assert assessment.heuristic_risk_score <= 100
        assert assessment.heuristic_risk_score == 100

    def test_no_signals_zero_score(self):
        node = _node(
            name="safe",
            version="1.0.0",
            version_precision="resolved",
            times={
                "1.0.0": "2020-01-01T00:00:00Z",
                "1.1.0": "2021-01-01T00:00:00Z",
            },
        )
        assessment = assess_package_risk(node, vulnerabilities=[], historical_maintainers=None)

        # Maintainer signal is unknown but contributes 0 points
        assert assessment.heuristic_risk_score == 0

    def test_unknown_signals_incomplete_assessment(self):
        node = _node(
            name="accepts",
            version="^2.0.0",
            version_precision="range",
            advisory_ids=[],
            vuln_count=0,
            times={"1.0.0": "2020-01-01T00:00:00Z"},
        )
        assessment = assess_package_risk(node)

        assert assessment.assessment_complete is False
        assert assessment.resolved_version is None
        assert assessment.version_resolution_status == "range"

    def test_complete_assessment_with_resolved_version(self):
        node = _node(
            name="pkg",
            version="1.0.0",
            version_precision="resolved",
            times={
                "1.0.0": "2020-01-01T00:00:00Z",
                "1.1.0": "2021-01-01T00:00:00Z",
            },
            maintainers=[{"name": "alice", "email": "a@x.com"}],
        )
        historical = [{"name": "alice", "email": "a@x.com"}]

        assessment = assess_package_risk(node, vulnerabilities=[], historical_maintainers=historical)

        assert assessment.assessment_complete is True
        assert assessment.resolved_version == "1.0.0"

    def test_assessment_to_dict_shape(self):
        node = _node()
        assessment = assess_package_risk(node, vulnerabilities=[], historical_maintainers=None)
        d = assessment.to_dict()

        assert "package_name" in d
        assert "supplied_version" in d
        assert "resolved_version" in d
        assert "heuristic_risk_score" in d
        assert "signals" in d
        assert "supporting_advisory_ids" in d
        assert "assessment_complete" in d
        assert "evidence" in d
        assert "recommended_next_action" in d
        assert len(d["signals"]) == 3

    def test_advisory_ids_preserved_in_assessment(self):
        node = _node(
            name="body-parser",
            version="1.20.1",
            version_precision="resolved",
            advisory_ids=["GHSA-qwcr-r2fm-qrc7"],
            vuln_count=1,
        )
        vulns = [_make_vuln("GHSA-qwcr-r2fm-qrc7", "body-parser", "0", "1.20.3")]
        assessment = assess_package_risk(node, vulns)

        assert "GHSA-qwcr-r2fm-qrc7" in assessment.supporting_advisory_ids


class TestAssessAllPackages:
    def test_assesses_all_nodes(self):
        response = {
            "transaction_hash": "tx123",
            "dependencies": [
                {"package": "a", "version": "1.0.0", "vulnerabilities": [], "npm_metadata": {}},
                {"package": "b", "version": "2.0.0", "vulnerabilities": [], "npm_metadata": {}},
            ],
        }
        assessments = assess_all_packages(response)

        assert len(assessments) == 2
        names = {a.package_name for a in assessments}
        assert names == {"a", "b"}

    def test_malformed_record_raises(self):
        response = {
            "transaction_hash": "tx123",
            "dependencies": [{"version": "1.0.0"}],  # missing "package"
        }
        with pytest.raises(ValueError, match="missing required field 'package'"):
            assess_all_packages(response)


# ---------------------------------------------------------------------------
# Integration with real dummy response
# ---------------------------------------------------------------------------

class TestDummyResponseIntegration:
    def test_risk_assessment_on_dummy_response(self):
        """All dummy response packages have version ranges.

        Vulnerability signals must be 'unknown' (not confirmed), because we
        cannot confirm applicability without resolved versions. This is the
        critical no-false-positive behavior.
        """
        import json
        from pathlib import Path

        path = Path(__file__).resolve().parent.parent / "dummy_response.json.json"
        with open(path) as f:
            response = json.load(f)

        graph = build_graph_from_api_response(response)

        for node_id in graph.nodes():
            node_data = graph.nodes[node_id]
            assessment = assess_package_risk(node_data)

            vuln_signal = next(
                s for s in assessment.signals if s["rule"] == "KNOWN_VULNERABILITY"
            )
            # Versions are ranges - vulnerability status MUST be unknown
            assert vuln_signal["status"] == "unknown", (
                f"{node_id}: vulnerability signal incorrectly "
                f"{vuln_signal['status']} on a version range"
            )
            assert assessment.assessment_complete is False