"""Tests for CRIB controlled local networking lab."""

import pytest
import lab


def test_target_validation():
    # Valid targets
    lab.validate_lab_target("127.0.0.1", 9100)
    lab.validate_lab_target("localhost", 8080)

    # Invalid host
    with pytest.raises(ValueError, match="strictly restricted to local loopback"):
        lab.validate_lab_target("192.168.1.1", 9100)

    # Invalid port range
    with pytest.raises(ValueError, match="Port must be an integer"):
        lab.validate_lab_target("127.0.0.1", 80)  # Privileged port below 1024

    with pytest.raises(ValueError, match="Port must be an integer"):
        lab.validate_lab_target("127.0.0.1", 70000)  # Above 65535


def test_lab_echo_service_lifecycle():
    test_port = 9198

    # Start service
    start_res = lab.start_lab_echo_service(port=test_port)
    assert start_res["status"] in ("started", "already_running")

    # Probe service
    probe_res = lab.run_tcp_probe(host="127.0.0.1", port=test_port, payload="HELLO")
    assert probe_res["success"] is True
    assert "CRIB_ECHO: HELLO" in probe_res["response"]
    assert probe_res["origin"] == "GENUINE_LOCAL_OBSERVATION"

    # Stop service
    stop_res = lab.stop_lab_echo_service(port=test_port)
    assert stop_res["status"] == "stopped"


def test_tcp_probe_closed_port():
    # Probe a likely unused port
    res = lab.run_tcp_probe(host="127.0.0.1", port=9197)
    assert res["success"] is False
    assert "Refused" in res["response"] or "Timed Out" in res["response"]


def test_controlled_scan():
    results = lab.run_controlled_scan(ports=[9195, 9196])
    assert len(results) == 2
    for r in results:
        assert r["state"] in ("OPEN", "CLOSED")
        assert r["host"] == "127.0.0.1"


def test_detection_demo():
    res = lab.run_detection_demo(burst_size=12)
    assert res["generated_events_count"] == 12
    assert len(res["triggered_alerts"]) >= 1
    assert any(a["rule_id"] == "PORT_SCAN" for a in res["triggered_alerts"])
