"""CRIB — Cyber Range in a Box.

Main Flask web application providing interactive cybersecurity incident response
training, controlled loopback networking exercises, rule-based detection,
and training history tracking.

Runs locally at: http://127.0.0.1:5001
"""

import os
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    abort,
    jsonify,
)

import database
import scenarios
import lab
import ml_detector

app = Flask(__name__)
app.secret_key = os.environ.get("CRIB_SECRET_KEY", "crib-cyber-range-secret-key-local-2026")


# ----------------------------------------------------------------------
# Security Dashboard
# ----------------------------------------------------------------------
@app.route("/")
@app.route("/dashboard")
def dashboard():
    """Display environment statistics, scenario quick-starts, and recent activity."""
    stats = database.get_dashboard_stats()
    scenarios_summary = scenarios.list_scenarios()
    recent_incidents = database.list_incidents(limit=5)
    recent_alerts = database.get_recent_alerts(limit=5)

    return render_template(
        "dashboard.html",
        active_page="dashboard",
        stats=stats,
        scenarios_summary=scenarios_summary,
        recent_incidents=recent_incidents,
        recent_alerts=recent_alerts,
    )


# ----------------------------------------------------------------------
# Network Monitor
# ----------------------------------------------------------------------
@app.route("/network")
def network_view():
    """Display real-time / recorded loopback telemetry, listening sockets, alerts, and filters."""
    origin_filter = request.args.get("origin", "all").strip().lower()
    event_type_filter = request.args.get("event_type", "").strip()
    search_query = request.args.get("search", "").strip()

    events = database.get_filtered_events(
        event_type=event_type_filter if event_type_filter else None,
        origin=origin_filter if origin_filter in ("genuine", "simulated") else None,
        search=search_query if search_query else None,
        limit=50,
    )
    alerts = database.get_recent_alerts(limit=50)
    lab_status = lab.get_lab_status()
    metrics = ml_detector.get_model_metrics()

    return render_template(
        "network.html",
        active_page="network",
        events=events,
        alerts=alerts,
        lab_status=lab_status,
        metrics=metrics,
        origin_filter=origin_filter,
        event_type_filter=event_type_filter,
        search_query=search_query,
    )


@app.route("/api/ml/metrics")
def ml_metrics_api():
    """Return model evaluation metrics and confusion matrix in JSON format."""
    return jsonify(ml_detector.get_model_metrics())


# ----------------------------------------------------------------------
# Controlled Network Lab
# ----------------------------------------------------------------------
@app.route("/lab")
def lab_view():
    """Controlled TCP lab control panel and status."""
    lab_status = lab.get_lab_status()
    output = request.args.get("output", "")

    return render_template(
        "lab.html",
        active_page="lab",
        lab_status=lab_status,
        output=output,
    )


@app.route("/lab/start", methods=["POST"])
def lab_start_service():
    """Start local TCP echo service on port 9100."""
    res = lab.start_lab_echo_service(port=9100)
    flash(res["message"], "success" if res["status"] in ("started", "already_running") else "error")
    return redirect(url_for("lab_view"))


@app.route("/lab/stop", methods=["POST"])
def lab_stop_service():
    """Stop local TCP echo service on port 9100."""
    res = lab.stop_lab_echo_service(port=9100)
    flash(res["message"], "info")
    return redirect(url_for("lab_view"))


@app.route("/lab/probe", methods=["POST"])
def lab_probe():
    """Transmit a safe, genuine TCP probe to loopback port and report response."""
    try:
        port = int(request.form.get("port", 9100))
        payload = request.form.get("payload", "CRIB_PING")
        res = lab.run_tcp_probe(host="127.0.0.1", port=port, payload=payload)

        output_str = (
            f"[+] TCP Probe Target: {res['host']}:{res['port']}\n"
            f"[+] Status: {'SUCCESS' if res['success'] else 'FAILED'}\n"
            f"[+] Round-Trip Latency: {res['elapsed_ms']} ms\n"
            f"[+] Response Data: {res['response']}\n"
            f"[+] Telemetry Origin: {res['origin']}\n"
        )
        flash("TCP probe executed successfully.", "success")
        return redirect(url_for("lab_view", output=output_str))
    except ValueError as exc:
        flash(str(exc), "error")
        return redirect(url_for("lab_view"))


@app.route("/lab/scan", methods=["POST"])
def lab_scan():
    """Check connectivity across designated lab ports on loopback."""
    results = lab.run_controlled_scan()
    lines = ["[+] Controlled Port Scan on 127.0.0.1:"]
    for r in results:
        lines.append(f"    Port {r['port']}/TCP: {r['state']}")
    lines.append("[+] Evidence Origin: GENUINE_LOCAL_OBSERVATION")

    output_str = "\n".join(lines)
    flash("Designated lab ports scanned.", "info")
    return redirect(url_for("lab_view", output=output_str))


@app.route("/lab/demo", methods=["POST"])
def lab_trigger_demo():
    """Generate controlled burst of events and run detection engine."""
    res = lab.run_detection_demo(burst_size=12)
    lines = [
        f"[+] Generated {res['generated_events_count']} sequential TCP connections.",
        f"[+] Detection Engine Evaluation Triggered.",
        f"[+] Alerts Created: {len(res['triggered_alerts'])}",
    ]
    for alert in res["triggered_alerts"]:
        lines.append(f"    -> [{alert['severity']}] {alert['rule_id']}: {alert['message']}")

    output_str = "\n".join(lines)
    flash("Detection demonstration executed.", "success")
    return redirect(url_for("lab_view", output=output_str))


# ----------------------------------------------------------------------
# Incident Scenarios & Workflow
# ----------------------------------------------------------------------
@app.route("/scenarios")
def scenarios_list():
    """Display catalog of available incident scenarios."""
    all_scenarios = scenarios.list_scenarios()
    return render_template(
        "scenarios.html",
        active_page="scenarios",
        scenarios=all_scenarios,
    )


@app.route("/incident/<scenario_id>/start", methods=["POST"])
def start_incident(scenario_id):
    """Instantiate a new incident exercise from a scenario."""
    sc = scenarios.get_scenario(scenario_id)
    if not sc:
        abort(404)

    incident_id = database.create_incident(scenario_id, sc["title"])

    # Load initial simulated scenario events into database for investigation
    for ev in sc.get("simulated_events", []):
        database.add_event(
            event_type=ev["event_type"],
            source_ip=ev.get("source_ip"),
            destination_ip=ev.get("destination_ip"),
            destination_port=ev.get("destination_port"),
            details=f"{ev.get('details', '')} (SIMULATED SCENARIO EVIDENCE)",
            incident_id=incident_id,
        )

    flash(f"Incident #{incident_id} activated. Begin Stage 1: Triage.", "info")
    return redirect(url_for("incident_view", incident_id=incident_id))


@app.route("/incident/<int:incident_id>")
def incident_view(incident_id):
    """Present the current stage of the incident response workflow with correlated telemetry."""
    incident = database.get_incident(incident_id)
    if not incident:
        abort(404)

    if incident["status"] in ("COMPLETED", "RESOLVED"):
        return redirect(url_for("results_view", incident_id=incident_id))

    sc = scenarios.get_scenario(incident["scenario_id"])
    if not sc:
        abort(404)

    current_stage = incident["stage"]
    stage_info = scenarios.get_stage_info(incident["scenario_id"], current_stage)
    if not stage_info:
        abort(500)

    try:
        current_stage_idx = scenarios.STAGE_ORDER.index(current_stage)
    except ValueError:
        current_stage_idx = 0

    incident_alerts = database.get_incident_alerts(incident_id)
    incident_events = database.get_incident_events(incident_id)

    return render_template(
        "incident.html",
        active_page="scenarios",
        incident=incident,
        scenario=sc,
        stage_info=stage_info,
        current_stage_idx=current_stage_idx,
        incident_alerts=incident_alerts,
        incident_events=incident_events,
    )


@app.route("/incident/<int:incident_id>/submit", methods=["POST"])
def submit_decision(incident_id):
    """Evaluate decision, record points, and progress incident lifecycle."""
    incident = database.get_incident(incident_id)
    if not incident or incident["status"] not in ("ACTIVE", "OPEN", "INVESTIGATING"):
        flash("Incident is inactive or does not exist.", "error")
        return redirect(url_for("history_view"))

    stage = request.form.get("stage")
    choice_id = request.form.get("choice_id")

    if stage != incident["stage"]:
        flash("Invalid stage submission sequence.", "error")
        return redirect(url_for("incident_view", incident_id=incident_id))

    eval_result = scenarios.evaluate_stage_choice(incident["scenario_id"], stage, choice_id)
    if not eval_result:
        flash("Please select a valid option to proceed.", "error")
        return redirect(url_for("incident_view", incident_id=incident_id))

    # Save decision in audit log
    database.save_decision(
        incident_id=incident_id,
        stage=stage,
        choice_id=choice_id,
        points=eval_result["points"],
        explanation=eval_result["explanation"],
    )

    next_stage = scenarios.get_next_stage(stage)
    if next_stage:
        database.update_incident_progress(incident_id, next_stage, added_points=eval_result["points"])
        flash(f"{stage.capitalize()} decision submitted. Advanced to {next_stage.capitalize()}.", "success")
        return redirect(url_for("incident_view", incident_id=incident_id))
    else:
        # Final stage (Recovery) completed
        decisions = database.get_decisions(incident_id)
        final_score = sum(d["points"] for d in decisions)
        database.complete_incident(incident_id, final_score=final_score)
        flash("Exercise completed! Review your After-Action Report below.", "success")
        return redirect(url_for("results_view", incident_id=incident_id))


@app.route("/incident/<int:incident_id>/results")
def results_view(incident_id):
    """Display comprehensive After-Action Report (AAR) for completed exercise."""
    incident = database.get_incident(incident_id)
    if not incident:
        abort(404)

    sc = scenarios.get_scenario(incident["scenario_id"])
    if not sc:
        abort(404)

    decisions = database.get_decisions(incident_id)
    decisions_by_stage = {d["stage"]: d for d in decisions}

    stage_breakdown = []
    for st_name in scenarios.STAGE_ORDER:
        stage_spec = sc["stages"].get(st_name, {})
        user_dec = decisions_by_stage.get(st_name)

        user_choice_text = "No decision recorded"
        points = 0
        explanation = "Stage skipped or incomplete."

        if user_dec:
            points = user_dec["points"]
            explanation = user_dec["explanation"]
            for opt in stage_spec.get("options", []):
                if opt["id"] == user_dec["choice_id"]:
                    user_choice_text = opt["text"]
                    break

        stage_breakdown.append({
            "stage": st_name,
            "title": stage_spec.get("title", st_name.capitalize()),
            "points": points,
            "user_choice_text": user_choice_text,
            "explanation": explanation,
        })

    return render_template(
        "results.html",
        active_page="history",
        incident=incident,
        scenario=sc,
        stage_breakdown=stage_breakdown,
    )


# ----------------------------------------------------------------------
# History & Logs
# ----------------------------------------------------------------------
@app.route("/history")
def history_view():
    """Display table of all past and current incident exercises."""
    incidents = database.list_incidents(limit=100)
    return render_template(
        "history.html",
        active_page="history",
        incidents=incidents,
    )


@app.route("/logs")
def logs_view():
    """Display combined event and alert telemetry logs with detection explainability."""
    events = database.get_recent_events(limit=100)
    alerts = database.get_recent_alerts(limit=100)
    metrics = ml_detector.get_model_metrics()
    return render_template(
        "logs.html",
        active_page="logs",
        events=events,
        alerts=alerts,
        metrics=metrics,
    )


# ----------------------------------------------------------------------
# Error Handlers
# ----------------------------------------------------------------------
@app.errorhandler(404)
def not_found_error(error):
    return render_template(
        "error.html",
        code=404,
        title="Page or Resource Not Found",
        message="The requested range resource or incident does not exist.",
    ), 404


@app.errorhandler(500)
def internal_error(error):
    return render_template(
        "error.html",
        code=500,
        title="Internal Training Range Error",
        message="An unexpected condition was encountered on the server.",
    ), 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=True)
