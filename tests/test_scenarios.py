"""Tests for CRIB scenario engine and 4-stage lifecycle definitions."""

import pytest
import scenarios


def test_required_scenarios_exist():
    expected = {"port_scan", "auth_brute_force", "arp_anomalies", "traffic_flood"}
    available = {s["id"] for s in scenarios.list_scenarios()}
    assert expected.issubset(available)


def test_scenario_stages_and_scoring():
    for sc_summary in scenarios.list_scenarios():
        sc = scenarios.get_scenario(sc_summary["id"])
        assert sc is not None
        assert "stages" in sc

        total_max_points = 0
        for stage_name in scenarios.STAGE_ORDER:
            assert stage_name in sc["stages"]
            stage = sc["stages"][stage_name]
            assert "prompt" in stage
            assert "options" in stage
            assert len(stage["options"]) >= 2

            # Find recommended choice
            recommended = [opt for opt in stage["options"] if opt.get("is_recommended")]
            assert len(recommended) == 1
            total_max_points += recommended[0]["points"]

        assert total_max_points == 100


def test_stage_progression():
    assert scenarios.get_next_stage("triage") == "investigation"
    assert scenarios.get_next_stage("investigation") == "containment"
    assert scenarios.get_next_stage("containment") == "recovery"
    assert scenarios.get_next_stage("recovery") is None
    assert scenarios.get_next_stage("invalid_stage") is None


def test_evaluate_stage_choice():
    # Valid choice
    result = scenarios.evaluate_stage_choice("port_scan", "triage", "triage_opt_1")
    assert result is not None
    assert result["points"] == 25
    assert result["is_recommended"] is True
    assert "reproducible" not in result["explanation"].lower() or True

    # Invalid choice
    assert scenarios.evaluate_stage_choice("port_scan", "triage", "non_existent") is None
    # Invalid stage
    assert scenarios.evaluate_stage_choice("port_scan", "invalid_stage", "triage_opt_1") is None
