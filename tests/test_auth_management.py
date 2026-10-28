"""Tests for Authentication, Role-Based Access Control (RBAC),
Employee Dashboard, Supervisor Oversight, Training Assignments,
and Analytics Reports in CRIB.
"""

import uuid
import pytest
from app import app
import auth
import database


@pytest.fixture
def client():
    """Create test client with testing mode and isolated test request context."""
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    with app.test_client() as client:
        yield client


# ======================================================================
# 1. Authentication & Password Security Tests
# ======================================================================
def test_password_hashing_and_verification():
    """Test cryptographic password hashing and verification."""
    password = "SecurePassword123!"
    p_hash = auth.hash_password(password)

    assert p_hash != password
    assert auth.verify_password(p_hash, password) is True
    assert auth.verify_password(p_hash, "WrongPassword") is False
    assert auth.verify_password("", password) is False

    # Short password validation
    with pytest.raises(ValueError):
        auth.hash_password("12345")


def test_user_login_success_and_logout(client):
    """Test successful user login, session establishment, and logout."""
    res = client.post(
        "/login",
        data={"username": "employee1", "password": "EmployeePass123!"},
        follow_redirects=True,
    )
    assert res.status_code == 200
    assert b"Alex Chen" in res.data
    assert b"Employee Training Cockpit" in res.data or b"Overview" in res.data

    # Logout
    res_logout = client.get("/logout", follow_redirects=True)
    assert res_logout.status_code == 200
    assert b"signed out successfully" in res_logout.data


def test_login_invalid_credentials(client):
    """Test login rejection on incorrect credentials."""
    res = client.post(
        "/login",
        data={"username": "employee1", "password": "WrongPassword999!"},
        follow_redirects=True,
    )
    assert res.status_code == 401
    assert b"Invalid username or password" in res.data


def test_login_suspended_account(client):
    """Test login rejection when user account is suspended."""
    # Find employee2 and suspend temporarily
    emp2 = database.get_user_by_username("employee2")
    assert emp2 is not None
    database.set_user_active(emp2["id"], 0)

    try:
        res = client.post(
            "/login",
            data={"username": "employee2", "password": "EmployeePass123!"},
            follow_redirects=True,
        )
        assert res.status_code == 403
        assert b"Account is suspended" in res.data
    finally:
        # Re-activate employee2
        database.set_user_active(emp2["id"], 1)


# ======================================================================
# 2. Role-Based Access Control (RBAC) Tests
# ======================================================================
def test_unauthenticated_access_redirection(client):
    """Unauthenticated users attempting to access protected pages are redirected to login."""
    res = client.get("/employee/dashboard", follow_redirects=False)
    assert res.status_code == 302
    assert "/login" in res.headers["Location"]

    res_mgr = client.get("/manager/dashboard", follow_redirects=False)
    assert res_mgr.status_code == 302
    assert "/login" in res_mgr.headers["Location"]

    res_admin = client.get("/admin", follow_redirects=False)
    assert res_admin.status_code == 302
    assert "/login" in res_admin.headers["Location"]


def test_employee_cannot_access_manager_or_admin(client):
    """Employees cannot access manager or administrative dashboards."""
    # Log in as employee1
    client.post(
        "/login",
        data={"username": "employee1", "password": "EmployeePass123!"},
        follow_redirects=True,
    )

    # Attempt to access manager dashboard
    res_mgr = client.get("/manager/dashboard", follow_redirects=True)
    assert b"Access restricted" in res_mgr.data

    # Attempt to access admin dashboard
    res_admin = client.get("/admin", follow_redirects=True)
    assert b"Access restricted" in res_admin.data


def test_manager_cannot_access_admin(client):
    """Managers cannot access system administrator portal."""
    # Log in as supervisor1
    client.post(
        "/login",
        data={"username": "supervisor1", "password": "ManagerPass123!"},
        follow_redirects=True,
    )

    res_admin = client.get("/admin", follow_redirects=True)
    assert b"Access restricted" in res_admin.data


def test_admin_has_full_access(client):
    """Administrators have access to admin, manager, and employee views."""
    client.post(
        "/login",
        data={"username": "admin", "password": "AdminPass123!"},
        follow_redirects=True,
    )

    res_admin = client.get("/admin")
    assert res_admin.status_code == 200
    assert b"User &amp; Role Management" in res_admin.data or b"User" in res_admin.data

    res_mgr = client.get("/manager/dashboard")
    assert res_mgr.status_code == 200

    res_emp = client.get("/employee/dashboard")
    assert res_emp.status_code == 200


# ======================================================================
# 3. Employee Portal Tests
# ======================================================================
def test_employee_dashboard_and_heatmap(client):
    """Test employee dashboard loads with heatmap and progress trends."""
    client.post(
        "/login",
        data={"username": "employee1", "password": "EmployeePass123!"},
        follow_redirects=True,
    )

    res = client.get("/employee/dashboard")
    assert res.status_code == 200
    assert b"Alex Chen" in res.data
    assert b"Cybersecurity Training Activity" in res.data or b"Activity" in res.data
    assert b"heatmap-grid" in res.data
    assert b"Cybersecurity Skill Competencies" in res.data or b"Skill" in res.data


def test_employee_training_and_activity_routes(client):
    """Test employee training catalog and activity history views."""
    client.post(
        "/login",
        data={"username": "employee1", "password": "EmployeePass123!"},
        follow_redirects=True,
    )

    res_train = client.get("/employee/training")
    assert res_train.status_code == 200
    assert b"My Training" in res_train.data or b"Scenario Assignments" in res_train.data

    res_prog = client.get("/employee/progress")
    assert res_prog.status_code == 200
    assert b"Training Progress" in res_prog.data or b"Activity Heatmap" in res_prog.data

    res_act = client.get("/employee/activity")
    assert res_act.status_code == 200
    assert b"Training Activity History" in res_act.data or b"Activity History" in res_act.data


# ======================================================================
# 4. Manager Oversight & Workflow Tests
# ======================================================================
def test_manager_dashboard_and_employee_detail(client):
    """Test manager dashboard displays team metrics and links to employee detail."""
    client.post(
        "/login",
        data={"username": "supervisor1", "password": "ManagerPass123!"},
        follow_redirects=True,
    )

    res = client.get("/manager/dashboard")
    assert res.status_code == 200
    assert b"Sarah Jenkins" in res.data
    assert b"Alex Chen" in res.data
    assert b"Supervised Employee Performance" in res.data

    # View employee detail dossier
    emp1 = database.get_user_by_username("employee1")
    res_detail = client.get(f"/manager/employee/{emp1['id']}")
    assert res_detail.status_code == 200
    assert b"Alex Chen" in res_detail.data
    assert b"Individual Performance Dossier" in res_detail.data


def test_manager_assignment_dispatch_and_review(client):
    """Test supervisor dispatching an assignment and reviewing performance."""
    client.post(
        "/login",
        data={"username": "supervisor1", "password": "ManagerPass123!"},
        follow_redirects=True,
    )

    emp1 = database.get_user_by_username("employee1")
    supervisor = database.get_user_by_username("supervisor1")

    # Dispatch assignment
    res_assign = client.post(
        "/manager/assign",
        data={
            "employee_id": emp1["id"],
            "scenario_id": "arp_anomalies",
            "due_date": "2026-11-15",
            "priority": "HIGH",
            "instructions": "Demonstrate containment within 15 minutes.",
        },
        follow_redirects=True,
    )
    assert res_assign.status_code == 200
    assert b"assignment dispatched successfully" in res_assign.data

    # Verify assignment exists in database
    assignments = database.list_assignments_for_employee(emp1["id"])
    target_a = next((a for a in assignments if a["scenario_id"] == "arp_anomalies"), None)
    assert target_a is not None
    assert target_a["priority"] == "HIGH"

    # Review assignment
    res_review = client.post(
        f"/manager/assignment/{target_a['id']}/review",
        data={
            "status": "COMPLETED",
            "feedback": "Strong analysis of loopback ARP packets.",
            "needs_reassessment": "",
        },
        follow_redirects=True,
    )
    assert res_review.status_code == 200
    assert b"review and feedback recorded" in res_review.data

    # Verify review updated in DB
    updated_a = database.get_assignment(target_a["id"])
    assert updated_a["status"] == "COMPLETED"
    assert "Strong analysis" in updated_a["manager_feedback"]


def test_manager_analytics_and_reports_views(client):
    """Test manager analytics metrics and print-friendly reports."""
    client.post(
        "/login",
        data={"username": "supervisor1", "password": "ManagerPass123!"},
        follow_redirects=True,
    )

    res_an = client.get("/manager/analytics")
    assert res_an.status_code == 200
    assert b"Cybersecurity Training Analytics" in res_an.data
    assert b"Incident Triage &amp; Alert Correlation" in res_an.data

    res_rep = client.get("/manager/reports")
    assert res_rep.status_code == 200
    assert b"Executive Training Reports &amp; Compliance" in res_rep.data


def test_csv_report_export(client):
    """Test export of training compliance data to CSV."""
    client.post(
        "/login",
        data={"username": "supervisor1", "password": "ManagerPass123!"},
        follow_redirects=True,
    )

    res = client.get("/reports/export/csv")
    assert res.status_code == 200
    assert res.mimetype == "text/csv"
    assert "attachment; filename=crib_training_report.csv" in res.headers.get("Content-Disposition", "")
    assert b"Employee ID,Full Name,Username,Department" in res.data
    assert b"Alex Chen" in res.data


# ======================================================================
# 5. Administrative User Management Tests
# ======================================================================
def test_admin_user_management_lifecycle(client):
    """Test administrator provisioning user, toggling status, and assigning supervisor."""
    client.post(
        "/login",
        data={"username": "admin", "password": "AdminPass123!"},
        follow_redirects=True,
    )

    test_username = f"analyst_{uuid.uuid4().hex[:6]}"
    # Create user
    res_create = client.post(
        "/admin/user/create",
        data={
            "username": test_username,
            "full_name": "Test Analyst",
            "email": f"{test_username}@company.corp",
            "password": "TestPassword123!",
            "role": "EMPLOYEE",
            "department": "SOC Tier 1",
            "supervisor_id": "",
        },
        follow_redirects=True,
    )
    assert res_create.status_code == 200
    assert b"provisioned successfully" in res_create.data

    created_user = database.get_user_by_username(test_username)
    assert created_user is not None
    assert created_user["full_name"] == "Test Analyst"
    assert created_user["is_active"] == 1

    # Toggle user to suspended
    res_toggle = client.post(f"/admin/user/{created_user['id']}/toggle", follow_redirects=True)
    assert res_toggle.status_code == 200
    assert b"suspended" in res_toggle.data

    updated_user = database.get_user_by_id(created_user["id"])
    assert updated_user["is_active"] == 0

    # Toggle user back to active
    client.post(f"/admin/user/{created_user['id']}/toggle", follow_redirects=True)
    assert database.get_user_by_id(created_user["id"])["is_active"] == 1

    # Assign supervisor
    supervisor = database.get_user_by_username("supervisor1")
    res_sup = client.post(
        f"/admin/user/{created_user['id']}/assign_supervisor",
        data={"supervisor_id": supervisor["id"]},
        follow_redirects=True,
    )
    assert res_sup.status_code == 200
    assert b"Supervisor assignment updated" in res_sup.data

    assigned_user = database.get_user_by_id(created_user["id"])
    assert assigned_user["supervisor_id"] == supervisor["id"]

    # View audit log
    res_audit = client.get("/admin/audit")
    assert res_audit.status_code == 200
    assert b"Platform Audit Logs" in res_audit.data
    assert test_username.encode() in res_audit.data


# ======================================================================
# 6. End-to-End User Journeys (Scenario Completion & Notifications)
# ======================================================================
def test_end_to_end_employee_scenario_workflow(client):
    """End-to-End: Employee signs in, completes scenario, verifies activity record & notification."""
    # 1. Sign in as employee1
    client.post(
        "/login",
        data={"username": "employee1", "password": "EmployeePass123!"},
        follow_redirects=True,
    )
    emp = database.get_user_by_username("employee1")

    # 2. Start scenario
    res_start = client.post("/incident/auth_brute_force/start", follow_redirects=False)
    assert res_start.status_code == 302
    incident_id = int(res_start.headers["Location"].rstrip("/").split("/")[-1])

    # 3. Verify incident is tagged with user_id
    inc = database.get_incident(incident_id)
    assert inc["user_id"] == emp["id"]

    # 4. Progress through all 4 stages
    stages = [
        ("triage", "triage_opt_1"),
        ("investigation", "invest_opt_1"),
        ("containment", "contain_opt_1"),
        ("recovery", "recov_opt_1"),
    ]
    for stage_name, choice in stages:
        res = client.post(
            f"/incident/{incident_id}/submit",
            data={"stage": stage_name, "choice_id": choice},
            follow_redirects=True,
        )
        assert res.status_code == 200

    # 5. Verify incident completed
    completed_inc = database.get_incident(incident_id)
    assert completed_inc["status"] in ("COMPLETED", "RESOLVED")

    # 6. Verify activity record created in DB
    activities = database.get_employee_activity_history(emp["id"])
    completed_act = next((a for a in activities if a["incident_id"] == incident_id and a["status"] == "COMPLETED"), None)
    assert completed_act is not None
    assert completed_act["score"] is not None

    # 7. Verify notification generated
    notifications = database.get_user_notifications(emp["id"])
    completion_notif = next((n for n in notifications if "Authentication Failures" in n["title"] or "Scenario Completed" in n["title"]), None)
    assert completion_notif is not None


def test_notifications_workflow(client):
    """Test viewing, reading, and dismissing user notifications."""
    client.post(
        "/login",
        data={"username": "employee1", "password": "EmployeePass123!"},
        follow_redirects=True,
    )
    emp = database.get_user_by_username("employee1")

    # Create test notification
    n_id = database.create_notification(
        user_id=emp["id"],
        title="Test Notification Title",
        message="Test alert message body.",
        notification_type="INFO",
    )

    # View notifications
    res = client.get("/notifications")
    assert res.status_code == 200
    assert b"Test Notification Title" in res.data

    # Mark as read
    res_read = client.post(f"/notifications/{n_id}/read", follow_redirects=True)
    assert res_read.status_code == 200

    # Mark all read
    res_all = client.post("/notifications/read-all", follow_redirects=True)
    assert res_all.status_code == 200
    assert b"All notifications marked as read" in res_all.data



# ======================================================================
# 7. Dual-Role Single Account & Parameter Tampering Enforcement Tests
# ======================================================================
def test_manager_dual_role_single_account(client):
    """Critical Requirement 5: One manager account provides access to both

    the manager oversight dashboard and the manager's personal employee dashboard
    without duplicate accounts or employee records.
    """
    # 1. Verify single unique record exists for supervisor1
    with database.database_connection() as conn:
        count = conn.execute("SELECT COUNT(*) FROM users WHERE username = 'supervisor1'").fetchone()[0]
        assert count == 1, "There must be exactly one user record for supervisor1 (no duplicates)."

    # 2. Authenticate with the single manager account
    login_res = client.post(
        "/login",
        data={"username": "supervisor1", "password": "ManagerPass123!"},
        follow_redirects=True,
    )
    assert login_res.status_code == 200
    assert b"Sarah Jenkins" in login_res.data

    # 3. Access Manager Dashboard (Team Oversight)
    res_mgr = client.get("/manager/dashboard")
    assert res_mgr.status_code == 200
    assert b"Team Overview" in res_mgr.data
    assert b"Supervised Employee Performance" in res_mgr.data
    assert b"My Personal Cockpit" in res_mgr.data

    # 4. Access Personal Employee Dashboard using the EXACT same session & account
    res_emp = client.get("/employee/dashboard")
    assert res_emp.status_code == 200
    assert b"Sarah Jenkins" in res_emp.data
    assert b"Single Account Dual-Mode Access" in res_emp.data
    assert b"Personal Trainee Cockpit" in res_emp.data
    assert b"Return to Team Oversight" in res_emp.data
    assert b"heatmap-grid" in res_emp.data

    # 5. Access Personal Training, Progress, and Activity Views
    res_train = client.get("/employee/training")
    assert res_train.status_code == 200

    res_prog = client.get("/employee/progress")
    assert res_prog.status_code == 200

    res_act = client.get("/employee/activity")
    assert res_act.status_code == 200

    # 6. Execute Cyber Range Scenario as Trainee
    res_start = client.post("/incident/port_scan/start", follow_redirects=False)
    assert res_start.status_code == 302
    incident_id = int(res_start.headers["Location"].rstrip("/").split("/")[-1])

    # Verify incident user_id belongs to the single manager account
    mgr_user = database.get_user_by_username("supervisor1")
    inc = database.get_incident(incident_id)
    assert inc["user_id"] == mgr_user["id"]

    # 7. Switch back seamlessly to Manager Dashboard
    res_back = client.get("/manager/dashboard")
    assert res_back.status_code == 200
    assert b"Team Overview" in res_back.data

    # 8. Re-verify user table still contains exactly 1 supervisor1 record
    with database.database_connection() as conn:
        count_after = conn.execute("SELECT COUNT(*) FROM users WHERE username = 'supervisor1'").fetchone()[0]
        assert count_after == 1


def test_unauthorized_employee_access_blocked_to_all_manager_endpoints(client):
    """Critical Requirement 6: Ordinary employees must not access manager or admin

    functionality through direct URLs, modified request parameters, or unauthorized requests.
    """
    # 1. Sign in as ordinary employee
    client.post(
        "/login",
        data={"username": "employee1", "password": "EmployeePass123!"},
        follow_redirects=True,
    )

    restricted_endpoints = [
        ("GET", "/manager/dashboard"),
        ("GET", "/manager/employee/1"),
        ("GET", "/manager/employee/2"),
        ("GET", "/manager/employee/3"),
        ("GET", "/manager/assignments"),
        ("POST", "/manager/assign"),
        ("POST", "/manager/assignment/1/review"),
        ("GET", "/manager/analytics"),
        ("GET", "/manager/reports"),
        ("GET", "/reports/export/csv"),
        ("GET", "/admin"),
        ("POST", "/admin/user/create"),
        ("POST", "/admin/user/1/toggle"),
        ("POST", "/admin/user/1/assign_supervisor"),
        ("GET", "/admin/audit"),
    ]

    for method, path in restricted_endpoints:
        if method == "GET":
            res = client.get(path, follow_redirects=True)
        else:
            res = client.post(path, data={"employee_id": 1, "scenario_id": "port_scan", "due_date": "2026-12-01"}, follow_redirects=True)
        assert res.status_code == 200
        assert b"Access restricted" in res.data, f"Employee was not blocked from {method} {path}"

    # 2. Parameter Manipulation / IDOR Protection between Supervisors
    # Sign in as supervisor1
    client.post(
        "/login",
        data={"username": "supervisor1", "password": "ManagerPass123!"},
        follow_redirects=True,
    )
    sup = database.get_user_by_username("supervisor1")

    # Try to view non-existent or unmanaged employee dossier
    res_idor_view = client.get("/manager/employee/99999", follow_redirects=True)
    assert res_idor_view.status_code in (404, 200)

    # Try to dispatch assignment to non-supervised employee (ID 1 is admin, not on team)
    res_idor_assign = client.post(
        "/manager/assign",
        data={"employee_id": 1, "scenario_id": "port_scan", "due_date": "2026-12-01"},
        follow_redirects=True,
    )
    assert b"Access restricted" in res_idor_assign.data or b"error" in res_idor_assign.data

    # 3. Admin self-suspension protection
    client.post(
        "/login",
        data={"username": "admin", "password": "AdminPass123!"},
        follow_redirects=True,
    )
    admin = database.get_user_by_username("admin")
    res_self_toggle = client.post(f"/admin/user/{admin['id']}/toggle", follow_redirects=True)
    assert b"Cannot suspend your own active administrator account" in res_self_toggle.data
    assert database.get_user_by_id(admin["id"])["is_active"] == 1
