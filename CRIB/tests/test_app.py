"""Integration tests for CRIB Flask web routes and end-to-end IR workflows."""

import pytest
from app import app
import database


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_dashboard_route(client):
    res = client.get("/")
    assert res.status_code == 200
    assert b"Security Operations Dashboard" in res.data
    assert b"Port Scanning" in res.data


def test_network_monitor_route(client):
    res = client.get("/network")
    assert res.status_code == 200
    assert b"Network Monitor &amp; Telemetry" in res.data or b"Network Monitor" in res.data


def test_lab_route(client):
    res = client.get("/lab")
    assert res.status_code == 200
    assert b"Controlled TCP Network Lab" in res.data


def test_scenarios_list_route(client):
    res = client.get("/scenarios")
    assert res.status_code == 200
    assert b"Incident Response Scenarios" in res.data
    assert b"Repeated Authentication Failures" in res.data
    assert b"ARP Anomalies" in res.data
    assert b"Traffic Flooding" in res.data


def test_history_and_logs_routes(client):
    res = client.get("/history")
    assert res.status_code == 200
    assert b"Incident Training History" in res.data

    res_logs = client.get("/logs")
    assert res_logs.status_code == 200
    assert b"Event &amp; Alert Logs" in res_logs.data or b"Event" in res_logs.data


def test_end_to_end_incident_workflow(client):
    # 1. Start a new incident
    start_res = client.post("/incident/port_scan/start", follow_redirects=False)
    assert start_res.status_code == 302
    redirect_url = start_res.headers["Location"]
    incident_id = int(redirect_url.rstrip("/").split("/")[-1])
    assert incident_id > 0

    # 2. View Stage 1: Triage
    stage1_res = client.get(f"/incident/{incident_id}")
    assert stage1_res.status_code == 200
    assert b"Triage" in stage1_res.data

    # 3. Submit Stage 1 Choice
    triage_sub = client.post(
        f"/incident/{incident_id}/submit",
        data={"stage": "triage", "choice_id": "triage_opt_1"},
        follow_redirects=True,
    )
    assert triage_sub.status_code == 200
    assert b"Investigation" in triage_sub.data

    # 4. Submit Stage 2 Choice
    invest_sub = client.post(
        f"/incident/{incident_id}/submit",
        data={"stage": "investigation", "choice_id": "invest_opt_1"},
        follow_redirects=True,
    )
    assert invest_sub.status_code == 200
    assert b"Containment" in invest_sub.data

    # 5. Submit Stage 3 Choice
    contain_sub = client.post(
        f"/incident/{incident_id}/submit",
        data={"stage": "containment", "choice_id": "contain_opt_1"},
        follow_redirects=True,
    )
    assert contain_sub.status_code == 200
    assert b"Recovery" in contain_sub.data

    # 6. Submit Stage 4 Choice (Final stage)
    recov_sub = client.post(
        f"/incident/{incident_id}/submit",
        data={"stage": "recovery", "choice_id": "recov_opt_1"},
        follow_redirects=True,
    )
    assert recov_sub.status_code == 200
    assert b"After-Action Report" in recov_sub.data
    assert b"100" in recov_sub.data  # Full score awarded
    assert b"Exemplary Response" in recov_sub.data


def test_lab_interactive_actions(client):
    # Start service
    res_start = client.post("/lab/start", follow_redirects=True)
    assert res_start.status_code == 200

    # Probe service
    res_probe = client.post(
        "/lab/probe",
        data={"port": "9100", "payload": "PING_TEST"},
        follow_redirects=True,
    )
    assert res_probe.status_code == 200
    assert b"SUCCESS" in res_probe.data or b"TCP probe executed" in res_probe.data

    # Stop service
    res_stop = client.post("/lab/stop", follow_redirects=True)
    assert res_stop.status_code == 200

    # Scan
    res_scan = client.post("/lab/scan", follow_redirects=True)
    assert res_scan.status_code == 200
    assert b"Designated lab ports scanned" in res_scan.data

    # Demo
    res_demo = client.post("/lab/demo", follow_redirects=True)
    assert res_demo.status_code == 200
    assert b"Detection demonstration executed" in res_demo.data


def test_404_error_page(client):
    res = client.get("/non_existent_page_12345")
    assert res.status_code == 404
    assert b"Page or Resource Not Found" in res.data
