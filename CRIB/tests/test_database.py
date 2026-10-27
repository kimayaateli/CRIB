"""Tests for CRIB SQLite database operations."""

import pytest
import sqlite3
import database


def test_create_and_get_incident():
    incident_id = database.create_incident("port_scan", "Reconnaissance Investigation")
    assert incident_id > 0

    record = database.get_incident(incident_id)
    assert record is not None
    assert record["scenario_id"] == "port_scan"
    assert record["title"] == "Reconnaissance Investigation"
    assert record["status"] == "ACTIVE"
    assert record["stage"] == "triage"
    assert record["score"] == 0


def test_add_and_retrieve_events():
    event_id = database.add_event(
        event_type="CONNECT",
        source_ip="10.0.0.5",
        destination_ip="10.0.0.1",
        destination_port=22,
        details="test connection",
    )
    assert event_id > 0

    events = database.get_recent_events(limit=10)
    assert len(events) >= 1
    found = any(e["id"] == event_id for e in events)
    assert found


def test_add_alert_validation():
    # Valid severity
    alert_id = database.add_alert(
        incident_id=None,
        rule_id="PORT_SCAN",
        severity="HIGH",
        message="Port scan detected",
    )
    assert alert_id > 0

    # Invalid severity raises ValueError
    try:
        database.add_alert(
            incident_id=None,
            rule_id="TEST",
            severity="NOT_A_SEVERITY",
            message="Invalid",
        )
        assert False, "Should have raised ValueError"
    except ValueError:
        pass


def test_save_decision_and_progress():
    incident_id = database.create_incident("auth_brute_force", "Brute Force Test")

    # Save decision
    dec_id = database.save_decision(
        incident_id=incident_id,
        stage="triage",
        choice_id="triage_1",
        points=25,
        explanation="Appropriate triage step",
    )
    assert dec_id > 0

    # Duplicate decision for same stage should raise ValueError
    try:
        database.save_decision(
            incident_id=incident_id,
            stage="triage",
            choice_id="triage_2",
            points=10,
            explanation="Duplicate stage",
        )
        assert False, "Should have raised ValueError for duplicate stage"
    except ValueError:
        pass

    # Progress incident stage & score
    database.update_incident_progress(incident_id, "investigation", added_points=25)
    updated = database.get_incident(incident_id)
    assert updated["stage"] == "investigation"
    assert updated["score"] == 25

    # Complete incident
    database.complete_incident(incident_id, final_score=95)
    completed = database.get_incident(incident_id)
    assert completed["status"] == "COMPLETED"
    assert completed["score"] == 95
    assert completed["completed_at"] is not None


def test_dashboard_stats():
    stats = database.get_dashboard_stats()
    assert "total_incidents" in stats
    assert "active_incidents" in stats
    assert "completed_incidents" in stats
    assert "total_events" in stats
    assert "total_alerts" in stats


def test_alert_explainability_fields():
    incident_id = database.create_incident("port_scan", "Alert Metadata Test")
    alert_id = database.add_alert(
        incident_id=incident_id,
        rule_id="PORT_SCAN",
        severity="HIGH",
        message="Port scan explainability test",
        detection_method="RULE_BASED",
        mitre_technique="T1046",
        affected_component="127.0.0.1:9100",
        recommendation="Block source IP",
    )
    assert alert_id > 0
    alerts = database.get_incident_alerts(incident_id)
    assert len(alerts) >= 1
    stored = next(a for a in alerts if a["id"] == alert_id)
    assert stored["detection_method"] == "RULE_BASED"
    assert stored["mitre_technique"] == "T1046"
    assert stored["affected_component"] == "127.0.0.1:9100"
    assert stored["recommendation"] == "Block source IP"


def test_incident_status_transitions():
    incident_id = database.create_incident("auth_brute_force", "Status Flow Test")
    database.update_incident_status(incident_id, "INVESTIGATING")
    record = database.get_incident(incident_id)
    assert record["status"] == "INVESTIGATING"

    database.update_incident_status(incident_id, "RESOLVED")
    record = database.get_incident(incident_id)
    assert record["status"] == "RESOLVED"


def test_filtered_events():
    database.add_event("FILTER_TEST", "10.1.1.1", "10.1.1.2", 80, "test genuine GENUINE_LOCAL_OBSERVATION")
    database.add_event("FILTER_TEST", "10.1.1.3", "10.1.1.2", 443, "test simulated telemetry")

    genuine = database.get_filtered_events(event_type="FILTER_TEST", origin="genuine")
    assert any("GENUINE_LOCAL_OBSERVATION" in e["details"] for e in genuine)

    simulated = database.get_filtered_events(event_type="FILTER_TEST", origin="simulated")
    assert any("GENUINE_LOCAL_OBSERVATION" not in e["details"] for e in simulated)

