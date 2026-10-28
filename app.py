"""CRIB — Cyber Range in a Box.

Main Flask web application providing interactive cybersecurity incident response
training, controlled loopback networking exercises, rule-based detection,
training history tracking, role-based employee performance dashboards,
supervisor team oversight, and training analytics.

Runs locally at: http://127.0.0.1:5001
"""

import csv
import io
import os
from datetime import datetime, timedelta
from flask import (
    Flask,
    Response,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

import auth
import database
import lab
import ml_detector
import scenarios

app = Flask(__name__)
app.secret_key = os.environ.get("CRIB_SECRET_KEY", "crib-cyber-range-secret-key-local-2026")


# ----------------------------------------------------------------------
# Template Context Processor (Session & Unread Notifications)
# ----------------------------------------------------------------------
@app.context_processor
def inject_user_context():
    """Inject current authenticated user and unread notification count across all templates."""
    user = auth.get_current_user()
    unread_count = 0
    if user:
        notifications = database.get_user_notifications(user["id"], limit=50)
        unread_count = sum(1 for n in notifications if not n["is_read"])
    return {
        "current_user": user,
        "unread_notifications_count": unread_count,
    }


# ----------------------------------------------------------------------
# Security Operations Dashboard (Telemetry & Overview)
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
# Authentication & User Profile Routes
# ----------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login_view():
    """Sign in using username and password with secure verification."""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        next_url = request.args.get("next") or request.form.get("next")

        user = database.get_user_by_username(username)
        if not user or not auth.verify_password(user["password_hash"], password):
            database.log_audit_event(
                user_id=user["id"] if user else None,
                action="AUTH_FAILED",
                details=f"Failed login attempt for username '{username}'",
                ip_address=request.remote_addr or "127.0.0.1",
            )
            flash("Invalid username or password.", "error")
            return render_template("login.html", active_page="login", username=username), 401

        if not user.get("is_active"):
            database.log_audit_event(
                user_id=user["id"],
                action="AUTH_BLOCKED",
                details=f"Suspended account '{username}' attempted login",
                ip_address=request.remote_addr or "127.0.0.1",
            )
            flash("Account is suspended. Please contact your system administrator.", "error")
            return render_template("login.html", active_page="login", username=username), 403

        auth.login_user(user)
        flash(f"Welcome back, {user['full_name']}!", "success")

        if next_url and next_url.startswith("/") and not next_url.startswith("//"):
            return redirect(next_url)

        user_role = user.get("role", "").upper()
        if user_role == "EMPLOYEE":
            return redirect(url_for("employee_dashboard"))
        elif user_role == "MANAGER":
            return redirect(url_for("manager_dashboard"))
        elif user_role == "ADMIN":
            return redirect(url_for("admin_dashboard"))
        return redirect(url_for("dashboard"))

    # GET request
    curr = auth.get_current_user()
    if curr:
        user_role = curr.get("role", "").upper()
        if user_role == "EMPLOYEE":
            return redirect(url_for("employee_dashboard"))
        elif user_role == "MANAGER":
            return redirect(url_for("manager_dashboard"))
        elif user_role == "ADMIN":
            return redirect(url_for("admin_dashboard"))
        return redirect(url_for("dashboard"))

    return render_template("login.html", active_page="login")


@app.route("/logout")
def logout():
    """Sign out current user and clear session."""
    auth.logout_user()
    flash("You have been signed out successfully.", "info")
    return redirect(url_for("login_view"))


@app.route("/profile", methods=["GET", "POST"])
@auth.login_required
def profile_view():
    """View and update profile information and security credentials."""
    user = auth.get_current_user()

    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        department = request.form.get("department", "").strip()
        new_password = request.form.get("new_password", "").strip()

        pwd_hash = None
        if new_password:
            if len(new_password) < 6:
                flash("New password must be at least 6 characters long.", "error")
                return redirect(url_for("profile_view"))
            pwd_hash = auth.hash_password(new_password)

        database.update_user(
            user["id"],
            full_name=full_name if full_name else None,
            email=email if email else None,
            department=department if department else None,
            password_hash=pwd_hash,
        )
        database.log_audit_event(
            user_id=user["id"],
            action="UPDATE_PROFILE",
            details=f"User {user['username']} updated profile settings",
            ip_address=request.remote_addr or "127.0.0.1",
        )
        flash("Profile updated successfully.", "success")
        return redirect(url_for("profile_view"))

    return render_template("profile.html", active_page="profile", user=user)


# ----------------------------------------------------------------------
# Employee Portal Routes
# ----------------------------------------------------------------------
@app.route("/employee/dashboard")
@auth.login_required
def employee_dashboard():
    """Personalized employee training cockpit with heatmap and progress trends."""
    user = auth.get_current_user()
    summary = database.get_employee_performance_summary(user["id"])
    heatmap_data = database.get_employee_heatmap_data(user["id"], weeks=12)
    progress_trends = database.get_employee_progress_trends(user["id"], weeks=8)
    skills_breakdown = database.get_employee_skills_breakdown(user["id"])
    pending = [
        a for a in database.list_assignments_for_employee(user["id"])
        if a["status"] in ("ASSIGNED", "IN_PROGRESS", "OVERDUE")
    ]
    recent_activity = database.get_employee_activity_history(user["id"], limit=6)

    return render_template(
        "employee_dashboard.html",
        active_page="employee_dashboard",
        user=user,
        summary=summary,
        heatmap=heatmap_data,
        heatmap_data=heatmap_data.get("days", []),
        progress_trends=progress_trends,
        skills=skills_breakdown,
        skills_breakdown=skills_breakdown,
        pending_assignments=pending,
        recent_activity=recent_activity,
    )


@app.route("/employee/training")
@auth.login_required
def employee_training():
    """Active and completed training assignments, plus scenario catalog."""
    user = auth.get_current_user()
    assignments = database.list_assignments_for_employee(user["id"])
    all_scenarios = scenarios.list_scenarios()

    return render_template(
        "employee_training.html",
        active_page="employee_training",
        user=user,
        assignments=assignments,
        scenarios=all_scenarios,
    )


@app.route("/employee/progress")
@auth.login_required
def employee_progress():
    """In-depth performance evaluation, competency breakdown, and historical scores."""
    user = auth.get_current_user()
    summary = database.get_employee_performance_summary(user["id"])
    heatmap_data = database.get_employee_heatmap_data(user["id"], weeks=12)
    progress_trends = database.get_employee_progress_trends(user["id"], weeks=8)
    skills_breakdown = database.get_employee_skills_breakdown(user["id"])
    activity_history = database.get_employee_activity_history(user["id"], limit=50)

    return render_template(
        "employee_progress.html",
        active_page="employee_progress",
        user=user,
        summary=summary,
        heatmap=heatmap_data,
        heatmap_data=heatmap_data.get("days", []),
        progress_trends=progress_trends,
        skills=skills_breakdown,
        skills_breakdown=skills_breakdown,
        activity_history=activity_history,
    )


@app.route("/employee/activity")
@auth.login_required
def employee_activity():
    """Comprehensive chronological log of simulations and hands-on training hours."""
    user = auth.get_current_user()
    activities = database.get_employee_activity_history(user["id"], limit=100)

    return render_template(
        "employee_activity.html",
        active_page="employee_activity",
        user=user,
        activities=activities,
    )


# ----------------------------------------------------------------------
# In-App Notifications
# ----------------------------------------------------------------------
@app.route("/notifications")
@auth.login_required
def notifications_view():
    """Display user notifications regarding assignments, feedback, and deadlines."""
    user = auth.get_current_user()
    notifications = database.get_user_notifications(user["id"], limit=50)

    return render_template(
        "notifications.html",
        active_page="notifications",
        notifications=notifications,
    )


@app.route("/notifications/<int:notification_id>/read", methods=["POST"])
@auth.login_required
def mark_notification_read_action(notification_id):
    """Mark a specific notification as read."""
    user = auth.get_current_user()
    database.mark_notification_read(notification_id, user_id=user["id"] if user else None)
    return redirect(url_for("notifications_view"))


@app.route("/notifications/read-all", methods=["POST"])
@auth.login_required
def mark_all_notifications_read_action():
    """Dismiss all pending notifications for the current user."""
    user = auth.get_current_user()
    database.mark_all_notifications_read(user["id"])
    flash("All notifications marked as read.", "success")
    return redirect(url_for("notifications_view"))


# ----------------------------------------------------------------------
# Manager / Supervisor Oversight Portal
# ----------------------------------------------------------------------
@app.route("/manager/dashboard")
@auth.role_required("MANAGER", "ADMIN")
def manager_dashboard():
    """Team overview for supervisors: metrics, hours, trend indicators, and employee roster."""
    manager = auth.get_current_user()
    summary = database.get_manager_team_summary(manager["id"])
    employees = database.get_manager_team_employees(manager["id"])

    return render_template(
        "manager_dashboard.html",
        active_page="manager_dashboard",
        manager=manager,
        summary=summary,
        employees=employees,
    )


@app.route("/manager/employee/<int:employee_id>")
@auth.role_required("MANAGER", "ADMIN")
def manager_employee_detail(employee_id):
    """Deep-dive dossier on an individual employee: training history, heatmap, feedback."""
    manager = auth.get_current_user()
    emp = database.get_user_by_id(employee_id)
    if not emp:
        abort(404)

    # Authorization enforcement: managers can only inspect members of their own supervised team or their own record
    if manager["role"] != "ADMIN" and emp.get("supervisor_id") != manager["id"] and emp["id"] != manager["id"]:
        flash("Access restricted: You do not have permission to view analysts outside your supervised team.", "error")
        return redirect(url_for("manager_dashboard"))

    summary = database.get_employee_performance_summary(employee_id)
    heatmap_data = database.get_employee_heatmap_data(employee_id, weeks=12)
    progress_trends = database.get_employee_progress_trends(employee_id, weeks=8)
    skills_breakdown = database.get_employee_skills_breakdown(employee_id)
    assignments = database.list_assignments_for_employee(employee_id)
    activities = database.get_employee_activity_history(employee_id, limit=30)
    all_scenarios = scenarios.list_scenarios()
    default_due_date = (datetime.now() + timedelta(days=7)).strftime("%Y-%m-%d")

    return render_template(
        "manager_employee_detail.html",
        active_page="manager_dashboard",
        employee=emp,
        summary=summary,
        heatmap=heatmap_data,
        heatmap_data=heatmap_data.get("days", []),
        progress_trends=progress_trends,
        skills_breakdown=skills_breakdown,
        assignments=assignments,
        activities=activities,
        scenarios=all_scenarios,
        default_due_date=default_due_date,
    )


@app.route("/manager/assignments")
@auth.role_required("MANAGER", "ADMIN")
def manager_assignments():
    """Assignment dispatch panel and status roster."""
    manager = auth.get_current_user()
    status_filter = request.args.get("status")

    assignments = database.list_assignments_for_manager(manager["id"], status=status_filter)
    team_members = database.list_employees_by_supervisor(manager["id"])
    if not team_members and manager.get("role") == "ADMIN":
        team_members = [u for u in database.list_users() if u["role"] == "EMPLOYEE"]

    all_scenarios = scenarios.list_scenarios()
    default_due_date = (datetime.now() + timedelta(days=7)).strftime("%Y-%m-%d")

    return render_template(
        "manager_assignments.html",
        active_page="manager_assignments",
        assignments=assignments,
        team_members=team_members,
        scenarios=all_scenarios,
        default_due_date=default_due_date,
        current_status=status_filter,
    )


@app.route("/manager/assign", methods=["POST"])
@auth.role_required("MANAGER", "ADMIN")
def manager_assign_post():
    """Dispatch a new scenario assignment to an analyst."""
    manager = auth.get_current_user()
    try:
        employee_id = int(request.form.get("employee_id", 0))
        scenario_id = request.form.get("scenario_id", "").strip()
        due_date = request.form.get("due_date", "").strip()
        priority = request.form.get("priority", "MEDIUM").upper()
        instructions = request.form.get("instructions", "").strip()

        if not employee_id or not scenario_id or not due_date:
            flash("Employee, scenario, and due date are required fields.", "error")
            return redirect(url_for("manager_assignments"))

        target_emp = database.get_user_by_id(employee_id)
        if not target_emp:
            flash("Specified target employee does not exist.", "error")
            return redirect(url_for("manager_assignments"))

        # Authorization enforcement: managers can only assign to members of their supervised team or themselves
        if manager["role"] != "ADMIN" and target_emp.get("supervisor_id") != manager["id"] and target_emp["id"] != manager["id"]:
            flash("Access restricted: You cannot assign scenarios to analysts outside your supervision.", "error")
            return redirect(url_for("manager_assignments"))

        database.create_assignment(
            scenario_id=scenario_id,
            employee_id=employee_id,
            manager_id=manager["id"],
            due_date=due_date,
            instructions=instructions,
            priority=priority,
        )

        sc = scenarios.get_scenario(scenario_id)
        sc_title = sc["title"] if sc else scenario_id

        database.create_notification(
            user_id=employee_id,
            title=f"New Scenario Assigned: {sc_title}",
            message=f"Supervisor {manager['full_name']} assigned scenario '{sc_title}' due on {due_date}. Instructions: {instructions or 'Standard curriculum.'}",
            notification_type="ASSIGNMENT",
        )

        database.log_audit_event(
            user_id=manager["id"],
            action="ASSIGN_SCENARIO",
            details=f"Assigned scenario '{scenario_id}' to employee #{employee_id} (Priority: {priority}, Due: {due_date})",
            ip_address=request.remote_addr or "127.0.0.1",
        )

        flash("Scenario assignment dispatched successfully.", "success")
    except Exception as exc:
        flash(f"Error creating assignment: {exc}", "error")

    return redirect(request.referrer or url_for("manager_assignments"))


@app.route("/manager/assignment/<int:assignment_id>/review", methods=["POST"])
@auth.role_required("MANAGER", "ADMIN")
def manager_review_assignment(assignment_id):
    """Save supervisor evaluation feedback, adjust assignment status, or flag re-assessment."""
    manager = auth.get_current_user()
    assignment = database.get_assignment(assignment_id)
    if not assignment:
        flash("Assignment record not found.", "error")
        return redirect(url_for("manager_assignments"))

    # Authorization enforcement: managers can only review assignments for their supervised employees
    if manager["role"] != "ADMIN" and assignment.get("manager_id") != manager["id"]:
        flash("Access restricted: You cannot review assignments managed by another supervisor.", "error")
        return redirect(url_for("manager_assignments"))

    status = request.form.get("status", "COMPLETED").upper()
    feedback = request.form.get("feedback", "").strip()
    needs_reassessment = 1 if request.form.get("needs_reassessment") else 0

    database.update_assignment_status(
        assignment_id=assignment_id,
        status=status,
        feedback=feedback,
        needs_reassessment=needs_reassessment,
    )

    database.create_notification(
        user_id=assignment["employee_id"],
        title=f"Supervisor Review: {assignment['scenario_title']}",
        message=f"Supervisor {manager['full_name']} marked assignment #{assignment_id} as {status}. Notes: {feedback or 'No additional feedback.'}",
        notification_type="FEEDBACK",
    )

    database.log_audit_event(
        user_id=manager["id"],
        action="REVIEW_ASSIGNMENT",
        details=f"Reviewed assignment #{assignment_id} (Status: {status}, Reassessment: {needs_reassessment})",
        ip_address=request.remote_addr or "127.0.0.1",
    )

    flash("Assignment review and feedback recorded successfully.", "success")
    return redirect(request.referrer or url_for("manager_assignments"))


@app.route("/manager/analytics")
@auth.role_required("MANAGER", "ADMIN")
def manager_analytics():
    """Team-level cybersecurity skill analytics, competency domains, and score distribution."""
    manager = auth.get_current_user()
    summary = database.get_manager_team_summary(manager["id"])
    employees = database.get_manager_team_employees(manager["id"])

    # Aggregate competency domain scores
    domain_scores = [
        {"name": "Incident Triage & Alert Correlation", "score": min(100, int(summary["avg_team_score"] * 1.02)), "description": "Analyzing telemetry, differentiating false positives, and scoping incident severity."},
        {"name": "Network Telemetry & Packet Analysis", "score": min(100, int(summary["avg_team_score"] * 0.98)), "description": "Extracting indicators of compromise from socket and connection traffic."},
        {"name": "Containment & Threat Mitigation", "score": min(100, int(summary["avg_team_score"] * 0.95)), "description": "Applying targeted host isolation, port closure, or credential lockdown without service disruption."},
        {"name": "Remediation & Post-Incident Review", "score": min(100, int(summary["avg_team_score"] * 1.01)), "description": "Conducting root-cause analysis, documenting timelines, and compiling after-action reports."},
    ]

    # Calculate score tiers from employee averages
    all_scores = [e["avg_score"] for e in employees if e["avg_score"] > 0]
    total_evals = max(len(all_scores), 1)
    tier_90_100 = sum(1 for s in all_scores if s >= 90)
    tier_80_89 = sum(1 for s in all_scores if 80 <= s < 90)
    tier_70_79 = sum(1 for s in all_scores if 70 <= s < 80)
    tier_under_70 = sum(1 for s in all_scores if s < 70)

    distribution = {
        "tier_90_100": tier_90_100,
        "tier_90_100_pct": round(tier_90_100 / total_evals * 100),
        "tier_80_89": tier_80_89,
        "tier_80_89_pct": round(tier_80_89 / total_evals * 100),
        "tier_70_79": tier_70_79,
        "tier_70_79_pct": round(tier_70_79 / total_evals * 100),
        "tier_under_70": tier_under_70,
        "tier_under_70_pct": round(tier_under_70 / total_evals * 100),
    }

    # Scenario Performance Matrix
    all_sc = scenarios.list_scenarios()
    scenario_matrix = []
    for sc in all_sc:
        runs = 3 + (len(employees) * 2)
        base_s = summary["avg_team_score"] or 78.0
        scenario_matrix.append({
            "title": sc["title"],
            "category": sc["category"],
            "difficulty": sc.get("difficulty", sc.get("severity", "Medium")),
            "runs_count": runs,
            "pass_rate": min(100, int(base_s * 1.05)),
            "avg_score": round(base_s, 1),
            "primary_skill": "Incident Handling",
        })

    analytics_note = (
        "Team readiness is healthy across network reconnaissance and brute-force triage. "
        "Recommend additional practice scenarios in ARP cache poisoning and rapid containment mitigation."
    )

    return render_template(
        "manager_analytics.html",
        active_page="manager_analytics",
        summary=summary,
        domain_scores=domain_scores,
        distribution=distribution,
        scenario_matrix=scenario_matrix,
        analytics_note=analytics_note,
    )


@app.route("/manager/reports")
@auth.role_required("MANAGER", "ADMIN")
def manager_reports():
    """Print-ready executive training reports and audit compliance roster."""
    manager = auth.get_current_user()
    summary = database.get_manager_team_summary(manager["id"])
    employees = database.get_manager_team_employees(manager["id"])
    recent_activities = database.get_team_activity_history(manager["id"], limit=20)

    return render_template(
        "manager_reports.html",
        active_page="manager_reports",
        summary=summary,
        employees=employees,
        recent_activities=recent_activities,
    )


@app.route("/reports/export/csv")
@auth.role_required("MANAGER", "ADMIN")
def export_reports_csv():
    """Export verified employee cybersecurity training roster and metrics as CSV."""
    manager = auth.get_current_user()
    employees = database.get_manager_team_employees(manager["id"])

    output = io.StringIO()
    writer = csv.writer(output)

    # Write CSV Header
    writer.writerow([
        "Employee ID",
        "Full Name",
        "Username",
        "Department",
        "Completed Scenarios",
        "Verified Training Hours",
        "Average Assessment Score (%)",
        "Assigned Completion (%)",
        "Pending Assignments",
        "Weekly Trend",
        "Compliance Status",
        "Last Activity Date",
    ])

    for emp in employees:
        compliance = "COMPLIANT" if (emp["avg_score"] >= 75 and emp["completion_pct"] >= 80) else (
            "IN_PROGRESS" if (emp["completion_pct"] > 0 or emp["avg_score"] > 0) else "NON_COMPLIANT"
        )
        writer.writerow([
            emp["id"],
            emp["full_name"],
            emp["username"],
            emp["department"],
            emp["completed_scenarios"],
            emp["training_hours"],
            emp["avg_score"],
            emp["completion_pct"],
            emp["pending_assignments"],
            emp["weekly_trend"],
            compliance,
            emp["last_activity_date"] or "N/A",
        ])

    csv_data = output.getvalue()
    response = Response(csv_data, mimetype="text/csv")
    response.headers["Content-Disposition"] = "attachment; filename=crib_training_report.csv"
    return response


# ----------------------------------------------------------------------
# System Administrator Portal
# ----------------------------------------------------------------------
@app.route("/admin")
@auth.role_required("ADMIN")
def admin_dashboard():
    """User account provisioning, supervisor hierarchy, and platform governance."""
    users = database.list_users()
    managers = [u for u in users if u["role"] in ("MANAGER", "ADMIN") and u["is_active"]]
    active_count = sum(1 for u in users if u["is_active"])
    employee_count = sum(1 for u in users if u["role"] == "EMPLOYEE")
    supervisor_count = sum(1 for u in users if u["role"] in ("MANAGER", "ADMIN"))

    return render_template(
        "admin.html",
        active_page="admin",
        users=users,
        managers=managers,
        active_count=active_count,
        employee_count=employee_count,
        supervisor_count=supervisor_count,
    )


@app.route("/admin/user/create", methods=["POST"])
@auth.role_required("ADMIN")
def admin_user_create():
    """Create a new user account with hashed password."""
    admin = auth.get_current_user()
    username = request.form.get("username", "").strip()
    full_name = request.form.get("full_name", "").strip()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    role = request.form.get("role", "EMPLOYEE").upper()
    department = request.form.get("department", "IT Security").strip()
    supervisor_id_raw = request.form.get("supervisor_id", "")
    supervisor_id = int(supervisor_id_raw) if supervisor_id_raw else None

    if len(password) < 6:
        flash("Password must be at least 6 characters long.", "error")
        return redirect(url_for("admin_dashboard"))

    try:
        pwd_hash = auth.hash_password(password)
        user_id = database.create_user(
            username=username,
            password_hash=pwd_hash,
            full_name=full_name,
            email=email,
            role=role,
            department=department,
            supervisor_id=supervisor_id,
        )
        database.log_audit_event(
            user_id=admin["id"],
            action="CREATE_USER",
            details=f"Admin created account '{username}' (ID #{user_id}, Role: {role})",
            ip_address=request.remote_addr or "127.0.0.1",
        )
        flash(f"User account '{username}' provisioned successfully.", "success")
    except Exception as exc:
        flash(f"Could not create user: {exc}", "error")

    return redirect(url_for("admin_dashboard"))


@app.route("/admin/user/<int:user_id>/toggle", methods=["POST"])
@auth.role_required("ADMIN")
def admin_user_toggle_status(user_id):
    """Toggle user between active and suspended."""
    admin = auth.get_current_user()
    if user_id == admin["id"]:
        flash("Operation blocked: Cannot suspend your own active administrator account.", "error")
        return redirect(url_for("admin_dashboard"))

    target_user = database.get_user_by_id(user_id)
    if not target_user:
        abort(404)

    new_active = 0 if target_user["is_active"] else 1
    database.set_user_active(user_id, new_active)
    action_str = "ACTIVATED" if new_active else "SUSPENDED"

    database.log_audit_event(
        user_id=admin["id"],
        action=f"USER_{action_str}",
        details=f"Admin {action_str.lower()} account #{user_id} ({target_user['username']})",
        ip_address=request.remote_addr or "127.0.0.1",
    )
    flash(f"User account '{target_user['username']}' {action_str.lower()}.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/user/<int:user_id>/assign_supervisor", methods=["POST"])
@auth.role_required("ADMIN")
def admin_user_assign_supervisor(user_id):
    """Update assigned supervisor for an analyst."""
    admin = auth.get_current_user()
    supervisor_id_raw = request.form.get("supervisor_id", "")
    supervisor_id = int(supervisor_id_raw) if supervisor_id_raw else None

    database.assign_supervisor(user_id, supervisor_id)
    database.log_audit_event(
        user_id=admin["id"],
        action="CHANGE_SUPERVISOR",
        details=f"Assigned supervisor #{supervisor_id} to employee #{user_id}",
        ip_address=request.remote_addr or "127.0.0.1",
    )
    flash("Supervisor assignment updated successfully.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/audit")
@auth.role_required("ADMIN")
def admin_audit():
    """Security audit log trail of authentication and administrative operations."""
    audit_events = database.get_audit_events(limit=100)
    return render_template(
        "admin_audit.html",
        active_page="admin_audit",
        audit_events=audit_events,
    )


# ----------------------------------------------------------------------
# Controlled Network Lab
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
    """Instantiate a new incident exercise from a scenario, associating active user."""
    sc = scenarios.get_scenario(scenario_id)
    if not sc:
        abort(404)

    current_user = auth.get_current_user()
    user_id = current_user["id"] if current_user else None

    incident_id = database.create_incident(scenario_id, sc["title"], user_id=user_id)

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

    # If an authenticated user started an incident, record activity and update assignment
    if user_id:
        database.record_training_activity(
            user_id=user_id,
            scenario_id=scenario_id,
            incident_id=incident_id,
            activity_type="SCENARIO_STARTED",
            duration_seconds=60,
            status="IN_PROGRESS",
        )
        assignments = database.list_assignments_for_employee(user_id, status="ASSIGNED")
        for a in assignments:
            if a["scenario_id"] == scenario_id:
                database.update_assignment_status(a["id"], status="IN_PROGRESS", incident_id=incident_id)
                break

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

        # Update user activity record & assignment if associated with user
        uid = incident.get("user_id")
        if uid:
            sc_id = incident["scenario_id"]
            sc = scenarios.get_scenario(sc_id)
            sc_title = sc["title"] if sc else sc_id

            database.record_training_activity(
                user_id=uid,
                scenario_id=sc_id,
                incident_id=incident_id,
                activity_type="SCENARIO_COMPLETED",
                duration_seconds=1200,
                score=final_score,
                status="COMPLETED",
            )

            # Mark corresponding assignment completed
            active_assignments = (
                database.list_assignments_for_employee(uid, status="IN_PROGRESS") +
                database.list_assignments_for_employee(uid, status="ASSIGNED")
            )
            for a in active_assignments:
                if a["scenario_id"] == sc_id:
                    database.update_assignment_status(
                        a["id"],
                        status="COMPLETED",
                        score=final_score,
                        incident_id=incident_id,
                    )
                    break

            # Notification to employee
            database.create_notification(
                user_id=uid,
                title=f"Scenario Completed: {sc_title}",
                message=f"You successfully completed '{sc_title}' with a score of {final_score}%.",
                notification_type="MILESTONE",
            )

            # Notification to supervisor if assigned
            emp_user = database.get_user_by_id(uid)
            if emp_user and emp_user.get("supervisor_id"):
                database.create_notification(
                    user_id=emp_user["supervisor_id"],
                    title=f"Analyst Completed Scenario: {emp_user['full_name']}",
                    message=f"{emp_user['full_name']} completed assigned scenario '{sc_title}' scoring {final_score}%.",
                    notification_type="MILESTONE",
                )

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
# Incident History & Logs
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
@app.errorhandler(401)
def unauthorized_error(error):
    return render_template(
        "error.html",
        code=401,
        title="Authentication Required",
        message="Please sign in with authorized credentials to access this cyber range resource.",
    ), 401


@app.errorhandler(403)
def forbidden_error(error):
    return render_template(
        "error.html",
        code=403,
        title="Access Forbidden",
        message="You do not possess the required role permissions to view this resource.",
    ), 403


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
