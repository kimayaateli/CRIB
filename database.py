
"""SQLite storage for CRIB network and security events."""

import sqlite3
from pathlib import Path
from contextlib import contextmanager

BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = BASE_DIR / "crib.db"


def get_connection():
    """Open a database connection with named-column access."""
    connection = sqlite3.connect(DATABASE_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


@contextmanager
def database_connection():
    """Commit successful operations and roll back failed ones."""
    connection = get_connection()
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def init_db():
    """Create the database tables if they do not exist and apply non-destructive migrations."""
    with database_connection() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scenario_id TEXT NOT NULL,
                title TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'ACTIVE'
                    CHECK (status IN ('ACTIVE', 'COMPLETED', 'OPEN', 'INVESTIGATING', 'RESOLVED')),
                stage TEXT NOT NULL DEFAULT 'triage',
                score INTEGER NOT NULL DEFAULT 0
                    CHECK (score BETWEEN 0 AND 100),
                created_at TEXT NOT NULL DEFAULT
                    (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                completed_at TEXT
            );

            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id INTEGER,
                event_type TEXT NOT NULL,
                source_ip TEXT,
                destination_ip TEXT,
                destination_port INTEGER,
                details TEXT NOT NULL DEFAULT '',
                timestamp TEXT NOT NULL DEFAULT
                    (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                FOREIGN KEY (incident_id)
                    REFERENCES incidents(id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS decisions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id INTEGER NOT NULL,
                stage TEXT NOT NULL,
                choice_id TEXT NOT NULL,
                points INTEGER NOT NULL DEFAULT 0,
                explanation TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT
                    (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                FOREIGN KEY (incident_id)
                    REFERENCES incidents(id) ON DELETE CASCADE,
                UNIQUE (incident_id, stage)
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id INTEGER,
                rule_id TEXT NOT NULL,
                severity TEXT NOT NULL
                    CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
                message TEXT NOT NULL,
                detection_method TEXT NOT NULL DEFAULT 'RULE_BASED',
                mitre_technique TEXT NOT NULL DEFAULT '',
                affected_component TEXT NOT NULL DEFAULT '',
                recommendation TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT
                    (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                FOREIGN KEY (incident_id)
                    REFERENCES incidents(id) ON DELETE SET NULL
            );

            CREATE INDEX IF NOT EXISTS idx_events_timestamp
                ON events(timestamp);

            CREATE INDEX IF NOT EXISTS idx_events_type
                ON events(event_type);

            CREATE INDEX IF NOT EXISTS idx_decisions_incident
                ON decisions(incident_id);

            CREATE INDEX IF NOT EXISTS idx_alerts_incident
                ON alerts(incident_id);

            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                full_name TEXT NOT NULL,
                email TEXT UNIQUE,
                role TEXT NOT NULL CHECK (role IN ('EMPLOYEE', 'MANAGER', 'ADMIN')),
                department TEXT NOT NULL DEFAULT 'IT Security',
                supervisor_id INTEGER,
                is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                last_login TEXT,
                FOREIGN KEY (supervisor_id) REFERENCES users(id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS assignments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scenario_id TEXT NOT NULL,
                employee_id INTEGER NOT NULL,
                manager_id INTEGER NOT NULL,
                due_date TEXT NOT NULL,
                instructions TEXT NOT NULL DEFAULT '',
                priority TEXT NOT NULL DEFAULT 'MEDIUM' CHECK (priority IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
                is_required INTEGER NOT NULL DEFAULT 1 CHECK (is_required IN (0, 1)),
                status TEXT NOT NULL DEFAULT 'ASSIGNED' CHECK (status IN ('ASSIGNED', 'IN_PROGRESS', 'SUBMITTED', 'COMPLETED', 'NEEDS_IMPROVEMENT', 'OVERDUE', 'CANCELLED')),
                assigned_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                completed_at TEXT,
                incident_id INTEGER,
                score INTEGER,
                manager_feedback TEXT NOT NULL DEFAULT '',
                needs_reassessment INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (employee_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (manager_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS activity_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                scenario_id TEXT NOT NULL,
                incident_id INTEGER,
                assignment_id INTEGER,
                activity_type TEXT NOT NULL DEFAULT 'INCIDENT_RESPONSE',
                activity_date TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d', 'now')),
                start_time TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                end_time TEXT,
                duration_seconds INTEGER NOT NULL DEFAULT 0,
                score INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'COMPLETED' CHECK (status IN ('COMPLETED', 'IN_PROGRESS', 'NEEDS_IMPROVEMENT')),
                feedback TEXT NOT NULL DEFAULT '',
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE SET NULL,
                FOREIGN KEY (assignment_id) REFERENCES assignments(id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                notification_type TEXT NOT NULL DEFAULT 'INFO' CHECK (notification_type IN ('ASSIGNMENT', 'DEADLINE', 'OVERDUE', 'FEEDBACK', 'MILESTONE', 'INFO')),
                is_read INTEGER NOT NULL DEFAULT 0 CHECK (is_read IN (0, 1)),
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                details TEXT NOT NULL DEFAULT '',
                ip_address TEXT,
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
            );

            CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
            CREATE INDEX IF NOT EXISTS idx_users_supervisor ON users(supervisor_id);
            CREATE INDEX IF NOT EXISTS idx_assignments_employee ON assignments(employee_id);
            CREATE INDEX IF NOT EXISTS idx_assignments_manager ON assignments(manager_id);
            CREATE INDEX IF NOT EXISTS idx_assignments_status ON assignments(status);
            CREATE INDEX IF NOT EXISTS idx_activity_user ON activity_records(user_id);
            CREATE INDEX IF NOT EXISTS idx_activity_date ON activity_records(activity_date);
            CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id);
            CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_events(created_at);
            """
        )

        # --------------------------------------------------------------
        # Non-destructive migrations for existing databases
        # --------------------------------------------------------------
        # Add explainability columns to alerts table if missing
        cursor = connection.execute("PRAGMA table_info(alerts)")
        columns = {col[1] for col in cursor.fetchall()}
        if "detection_method" not in columns:
            connection.execute("ALTER TABLE alerts ADD COLUMN detection_method TEXT NOT NULL DEFAULT 'RULE_BASED'")
        if "mitre_technique" not in columns:
            connection.execute("ALTER TABLE alerts ADD COLUMN mitre_technique TEXT NOT NULL DEFAULT ''")
        if "affected_component" not in columns:
            connection.execute("ALTER TABLE alerts ADD COLUMN affected_component TEXT NOT NULL DEFAULT ''")
        if "recommendation" not in columns:
            connection.execute("ALTER TABLE alerts ADD COLUMN recommendation TEXT NOT NULL DEFAULT ''")

        # Add user_id column to incidents table if missing
        cursor = connection.execute("PRAGMA table_info(incidents)")
        inc_cols = {col[1] for col in cursor.fetchall()}
        if "user_id" not in inc_cols:
            connection.execute("ALTER TABLE incidents ADD COLUMN user_id INTEGER REFERENCES users(id) ON DELETE SET NULL")

    # Seed default roles and baseline activity records if newly initialized
    seed_default_users()


def create_incident(scenario_id, title, user_id=None):
    """Create an incident and return its database ID."""
    with database_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO incidents (scenario_id, title, user_id)
            VALUES (?, ?, ?)
            """,
            (scenario_id, title, user_id),
        )
        return cursor.lastrowid


def get_incident(incident_id):
    """Return one incident as a dictionary, or None if not found."""
    with database_connection() as connection:
        row = connection.execute(
            "SELECT * FROM incidents WHERE id = ?",
            (incident_id,),
        ).fetchone()
        return dict(row) if row else None


def add_event(
    event_type,
    source_ip=None,
    destination_ip=None,
    destination_port=None,
    details="",
    incident_id=None,
):
    """Save a network event and return its ID."""
    with database_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO events (
                incident_id, event_type, source_ip,
                destination_ip, destination_port, details
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                incident_id,
                event_type,
                source_ip,
                destination_ip,
                destination_port,
                details,
            ),
        )
        return cursor.lastrowid


def get_recent_events(limit=100):
    """Return the newest network events first."""
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        raise ValueError("limit must be a positive integer")

    with database_connection() as connection:
        rows = connection.execute(
            """
            SELECT * FROM events
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]


def get_filtered_events(
    event_type=None,
    origin=None,
    search=None,
    limit=100
):
    """Return filtered network events based on event_type, origin, and search keyword."""
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        raise ValueError("limit must be a positive integer")

    query = "SELECT * FROM events WHERE 1=1"
    params = []

    if event_type:
        query += " AND UPPER(event_type) = UPPER(?)"
        params.append(event_type.strip())

    if origin == "genuine":
        query += " AND details LIKE '%GENUINE_LOCAL_OBSERVATION%'"
    elif origin == "simulated":
        query += " AND details NOT LIKE '%GENUINE_LOCAL_OBSERVATION%'"

    if search:
        query += " AND (source_ip LIKE ? OR destination_ip LIKE ? OR details LIKE ? OR event_type LIKE ?)"
        term = f"%{search.strip()}%"
        params.extend([term, term, term, term])

    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    with database_connection() as connection:
        rows = connection.execute(query, params).fetchall()
        return [dict(row) for row in rows]


def add_alert(
    incident_id,
    rule_id,
    severity,
    message,
    detection_method="RULE_BASED",
    mitre_technique="",
    affected_component="",
    recommendation="",
):
    """Save a detection alert with explainability metadata and return its ID."""
    severity = severity.upper()
    allowed_severities = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

    if severity not in allowed_severities:
        raise ValueError("Invalid alert severity")

    with database_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO alerts (
                incident_id, rule_id, severity, message,
                detection_method, mitre_technique, affected_component, recommendation
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                incident_id,
                rule_id,
                severity,
                message,
                detection_method,
                mitre_technique,
                affected_component,
                recommendation,
            ),
        )
        return cursor.lastrowid


def get_recent_alerts(limit=100):
    """Return the newest alerts first."""
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        raise ValueError("limit must be a positive integer")

    with database_connection() as connection:
        rows = connection.execute(
            """
            SELECT * FROM alerts
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]


def save_decision(
    incident_id,
    stage,
    choice_id,
    points,
    explanation="",
):
    """Save one decision per incident stage."""
    try:
        with database_connection() as connection:
            cursor = connection.execute(
                """
                INSERT INTO decisions (
                    incident_id, stage, choice_id, points, explanation
                )
                SELECT id, ?, ?, ?, ?
                FROM incidents
                WHERE id = ? AND status IN ('ACTIVE', 'OPEN', 'INVESTIGATING')
                """,
                (stage, choice_id, points, explanation, incident_id),
            )

            if cursor.rowcount != 1:
                raise ValueError(
                    "Incident not found, inactive, or decision already saved"
                )

            return cursor.lastrowid
    except sqlite3.IntegrityError as exc:
        raise ValueError(
            "Incident not found, inactive, or decision already saved"
        ) from exc


def list_incidents(limit=100):
    """Return recent incidents for the history page."""
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        raise ValueError("limit must be a positive integer")

    with database_connection() as connection:
        rows = connection.execute(
            """
            SELECT * FROM incidents
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]


def get_decisions(incident_id):
    """Return all decisions for a given incident."""
    with database_connection() as connection:
        rows = connection.execute(
            """
            SELECT * FROM decisions
            WHERE incident_id = ?
            ORDER BY id ASC
            """,
            (incident_id,),
        ).fetchall()
        return [dict(row) for row in rows]


def get_incident_events(incident_id):
    """Return all events associated with a specific incident."""
    with database_connection() as connection:
        rows = connection.execute(
            """
            SELECT * FROM events
            WHERE incident_id = ?
            ORDER BY id ASC
            """,
            (incident_id,),
        ).fetchall()
        return [dict(row) for row in rows]


def get_incident_alerts(incident_id):
    """Return all alerts associated with a specific incident."""
    with database_connection() as connection:
        rows = connection.execute(
            """
            SELECT * FROM alerts
            WHERE incident_id = ?
            ORDER BY id ASC
            """,
            (incident_id,),
        ).fetchall()
        return [dict(row) for row in rows]


def update_incident_status(incident_id, status):
    """Update incident status (OPEN, INVESTIGATING, RESOLVED, ACTIVE, COMPLETED)."""
    status = status.upper()
    allowed = {"ACTIVE", "COMPLETED", "OPEN", "INVESTIGATING", "RESOLVED"}
    if status not in allowed:
        raise ValueError(f"Invalid incident status: {status}")

    with database_connection() as connection:
        cursor = connection.execute(
            "UPDATE incidents SET status = ? WHERE id = ?",
            (status, incident_id),
        )
        if cursor.rowcount == 0:
            raise ValueError(f"Incident #{incident_id} not found.")


def update_incident_progress(incident_id, next_stage, added_points=0, status=None):
    """Update incident stage, increment score, and optionally update status."""
    with database_connection() as connection:
        if status:
            connection.execute(
                """
                UPDATE incidents
                SET stage = ?, score = MIN(100, score + ?), status = ?
                WHERE id = ? AND status IN ('ACTIVE', 'OPEN', 'INVESTIGATING')
                """,
                (next_stage, added_points, status.upper(), incident_id),
            )
        else:
            connection.execute(
                """
                UPDATE incidents
                SET stage = ?, score = MIN(100, score + ?)
                WHERE id = ? AND status IN ('ACTIVE', 'OPEN', 'INVESTIGATING')
                """,
                (next_stage, added_points, incident_id),
            )


def complete_incident(incident_id, final_score=None, status="COMPLETED"):
    """Mark an incident as completed or resolved with completion timestamp."""
    status = status.upper()
    if status not in ("COMPLETED", "RESOLVED"):
        status = "COMPLETED"

    with database_connection() as connection:
        if final_score is not None:
            connection.execute(
                """
                UPDATE incidents
                SET status = ?,
                    score = ?,
                    completed_at = (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
                WHERE id = ?
                """,
                (status, max(0, min(100, final_score)), incident_id),
            )
        else:
            connection.execute(
                """
                UPDATE incidents
                SET status = ?,
                    completed_at = (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
                WHERE id = ?
                """,
                (status, incident_id),
            )


def get_dashboard_stats():
    """Return high-level statistics for the dashboard."""
    with database_connection() as connection:
        total_incidents = connection.execute(
            "SELECT COUNT(*) FROM incidents"
        ).fetchone()[0]
        active_incidents = connection.execute(
            "SELECT COUNT(*) FROM incidents WHERE status IN ('ACTIVE', 'OPEN', 'INVESTIGATING')"
        ).fetchone()[0]
        completed_incidents = connection.execute(
            "SELECT COUNT(*) FROM incidents WHERE status IN ('COMPLETED', 'RESOLVED')"
        ).fetchone()[0]
        total_events = connection.execute(
            "SELECT COUNT(*) FROM events"
        ).fetchone()[0]
        total_alerts = connection.execute(
            "SELECT COUNT(*) FROM alerts"
        ).fetchone()[0]

        return {
            "total_incidents": total_incidents,
            "active_incidents": active_incidents,
            "completed_incidents": completed_incidents,
            "total_events": total_events,
            "total_alerts": total_alerts,
        }


# ======================================================================
# User & Authentication Database Operations
# ======================================================================

def create_user(username, password_hash, full_name, email, role, department="IT Security", supervisor_id=None, is_active=1):
    """Create a new user account with hashed credentials."""
    role = role.upper()
    if role not in ("EMPLOYEE", "MANAGER", "ADMIN"):
        raise ValueError("Invalid user role. Must be EMPLOYEE, MANAGER, or ADMIN.")
    with database_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO users (username, password_hash, full_name, email, role, department, supervisor_id, is_active)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (username.strip().lower(), password_hash, full_name.strip(), email.strip().lower() if email else None, role, department.strip(), supervisor_id, int(bool(is_active))),
        )
        return cursor.lastrowid


def get_user_by_id(user_id):
    """Retrieve user record by primary key."""
    if not user_id:
        return None
    with database_connection() as connection:
        row = connection.execute(
            """
            SELECT u.*, s.full_name AS supervisor_name, s.email AS supervisor_email
            FROM users u
            LEFT JOIN users s ON u.supervisor_id = s.id
            WHERE u.id = ?
            """,
            (user_id,),
        ).fetchone()
        return dict(row) if row else None


def get_user_by_username(username):
    """Retrieve user record by username."""
    if not username:
        return None
    with database_connection() as connection:
        row = connection.execute(
            """
            SELECT u.*, s.full_name AS supervisor_name, s.email AS supervisor_email
            FROM users u
            LEFT JOIN users s ON u.supervisor_id = s.id
            WHERE LOWER(u.username) = LOWER(?)
            """,
            (username.strip(),),
        ).fetchone()
        return dict(row) if row else None


def update_user(user_id, full_name=None, email=None, department=None, supervisor_id=None, role=None, is_active=None, password_hash=None):
    """Update fields on a user record."""
    with database_connection() as connection:
        updates = []
        params = []
        if full_name is not None:
            updates.append("full_name = ?")
            params.append(full_name.strip())
        if email is not None:
            updates.append("email = ?")
            params.append(email.strip().lower() if email else None)
        if department is not None:
            updates.append("department = ?")
            params.append(department.strip())
        if supervisor_id is not None:
            updates.append("supervisor_id = ?")
            params.append(supervisor_id if supervisor_id > 0 else None)
        if role is not None:
            updates.append("role = ?")
            params.append(role.upper())
        if is_active is not None:
            updates.append("is_active = ?")
            params.append(1 if is_active else 0)
        if password_hash is not None:
            updates.append("password_hash = ?")
            params.append(password_hash)

        if updates:
            params.append(user_id)
            connection.execute(f"UPDATE users SET {', '.join(updates)} WHERE id = ?", params)


def update_last_login(user_id):
    """Record timestamp of user login."""
    with database_connection() as connection:
        connection.execute(
            "UPDATE users SET last_login = (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')) WHERE id = ?",
            (user_id,),
        )


def list_users(role=None, active_only=False):
    """List users optionally filtered by role and status."""
    query = """
        SELECT u.*, s.full_name AS supervisor_name
        FROM users u
        LEFT JOIN users s ON u.supervisor_id = s.id
        WHERE 1=1
    """
    params = []
    if role:
        query += " AND u.role = ?"
        params.append(role.upper())
    if active_only:
        query += " AND u.is_active = 1"
    query += " ORDER BY u.full_name ASC"

    with database_connection() as connection:
        rows = connection.execute(query, params).fetchall()
        return [dict(r) for r in rows]


def list_employees_by_supervisor(supervisor_id):
    """List all employees assigned to a supervisor."""
    with database_connection() as connection:
        rows = connection.execute(
            """
            SELECT u.*, s.full_name AS supervisor_name
            FROM users u
            LEFT JOIN users s ON u.supervisor_id = s.id
            WHERE u.supervisor_id = ? AND u.role = 'EMPLOYEE'
            ORDER BY u.full_name ASC
            """,
            (supervisor_id,),
        ).fetchall()
        return [dict(r) for r in rows]


def assign_supervisor(employee_id, supervisor_id):
    """Assign or reassign an employee to a supervisor."""
    with database_connection() as connection:
        if supervisor_id is not None and supervisor_id > 0:
            sup = connection.execute("SELECT role FROM users WHERE id = ?", (supervisor_id,)).fetchone()
            if not sup or sup["role"] not in ("MANAGER", "ADMIN"):
                raise ValueError("Supervisor must be a MANAGER or ADMIN.")
            sup_val = supervisor_id
        else:
            sup_val = None
        connection.execute(
            "UPDATE users SET supervisor_id = ? WHERE id = ? AND role = 'EMPLOYEE'",
            (sup_val, employee_id),
        )


def set_user_active(user_id, is_active):
    """Activate or deactivate user account."""
    with database_connection() as connection:
        connection.execute(
            "UPDATE users SET is_active = ? WHERE id = ?",
            (1 if is_active else 0, user_id),
        )


# ======================================================================
# Training Assignment Operations
# ======================================================================

def create_assignment(scenario_id, employee_id, manager_id, due_date, instructions="", priority="MEDIUM", is_required=1):
    """Create a training assignment from a manager to an employee."""
    priority = priority.upper()
    if priority not in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
        priority = "MEDIUM"
    with database_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO assignments (scenario_id, employee_id, manager_id, due_date, instructions, priority, is_required, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'ASSIGNED')
            """,
            (scenario_id, employee_id, manager_id, due_date, instructions.strip(), priority, int(bool(is_required))),
        )
        assign_id = cursor.lastrowid
        connection.execute(
            """
            INSERT INTO notifications (user_id, title, message, notification_type)
            VALUES (?, ?, ?, 'ASSIGNMENT')
            """,
            (
                employee_id,
                f"New Training Assignment: {scenario_id}",
                f"You have been assigned the {scenario_id} exercise by your supervisor. Due: {due_date}",
            ),
        )
        return assign_id


def get_assignment(assignment_id):
    """Retrieve single assignment record."""
    with database_connection() as connection:
        row = connection.execute(
            """
            SELECT a.*, e.full_name AS employee_name, m.full_name AS manager_name
            FROM assignments a
            JOIN users e ON a.employee_id = e.id
            JOIN users m ON a.manager_id = m.id
            WHERE a.id = ?
            """,
            (assignment_id,),
        ).fetchone()
        if not row:
            return None
        d = dict(row)
        title_map = {
            "port_scan": "Port Scanning & Reconnaissance",
            "auth_brute_force": "Repeated Authentication Failures (Brute Force)",
            "arp_anomalies": "ARP Cache Poisoning & Man-in-the-Middle",
            "traffic_flood": "Distributed / SYN Traffic Flood",
        }
        d["scenario_title"] = title_map.get(d.get("scenario_id"), d.get("scenario_id"))
        return d


def list_assignments_for_employee(employee_id, status=None):
    """List assignments for employee with optional status filter."""
    query = """
        SELECT a.*, m.full_name AS manager_name
        FROM assignments a
        JOIN users m ON a.manager_id = m.id
        WHERE a.employee_id = ?
    """
    params = [employee_id]
    if status:
        query += " AND a.status = ?"
        params.append(status.upper())
    query += " ORDER BY a.due_date ASC, a.id DESC"

    with database_connection() as connection:
        rows = connection.execute(query, params).fetchall()
        return [dict(r) for r in rows]


def list_assignments_for_manager(manager_id, status=None):
    """List assignments assigned by a manager."""
    query = """
        SELECT a.*, e.full_name AS employee_name, e.department AS employee_dept
        FROM assignments a
        JOIN users e ON a.employee_id = e.id
        WHERE a.manager_id = ?
    """
    params = [manager_id]
    if status:
        query += " AND a.status = ?"
        params.append(status.upper())
    query += " ORDER BY a.due_date ASC, a.id DESC"

    with database_connection() as connection:
        rows = connection.execute(query, params).fetchall()
        return [dict(r) for r in rows]


def update_assignment_status(assignment_id, status, score=None, feedback=None, incident_id=None, needs_reassessment=0):
    """Update assignment status, score, supervisor review, and feedback."""
    status = status.upper()
    allowed = {"ASSIGNED", "IN_PROGRESS", "SUBMITTED", "COMPLETED", "NEEDS_IMPROVEMENT", "OVERDUE", "CANCELLED"}
    if status not in allowed:
        raise ValueError(f"Invalid assignment status: {status}")

    with database_connection() as connection:
        cur = connection.execute("SELECT * FROM assignments WHERE id = ?", (assignment_id,)).fetchone()
        if not cur:
            raise ValueError("Assignment not found.")

        updates = ["status = ?"]
        params = [status]

        if score is not None:
            updates.append("score = ?")
            params.append(max(0, min(100, score)))

        if feedback is not None:
            updates.append("manager_feedback = ?")
            params.append(feedback.strip())

        if incident_id is not None:
            updates.append("incident_id = ?")
            params.append(incident_id)

        if needs_reassessment:
            updates.append("needs_reassessment = 1")

        if status == "COMPLETED":
            updates.append("completed_at = (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))")

        params.append(assignment_id)
        connection.execute(f"UPDATE assignments SET {', '.join(updates)} WHERE id = ?", params)

        if feedback and cur:
            connection.execute(
                """
                INSERT INTO notifications (user_id, title, message, notification_type)
                VALUES (?, ?, ?, 'FEEDBACK')
                """,
                (
                    cur["employee_id"],
                    "Assignment Feedback Received",
                    f"Supervisor reviewed your submission for {cur['scenario_id']}: {feedback[:100]}",
                ),
            )


# ======================================================================
# Activity Records, Heatmap & Progress Analytics
# ======================================================================

def record_training_activity(user_id, scenario_id, incident_id=None, assignment_id=None, duration_seconds=600, score=0, activity_type="INCIDENT_RESPONSE", status="COMPLETED", feedback=""):
    """Record a verified hands-on training activity."""
    with database_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO activity_records (
                user_id, scenario_id, incident_id, assignment_id,
                activity_type, activity_date, duration_seconds, score, status, feedback
            )
            VALUES (?, ?, ?, ?, ?, (strftime('%Y-%m-%d', 'now')), ?, ?, ?, ?)
            """,
            (
                user_id,
                scenario_id,
                incident_id,
                assignment_id,
                activity_type,
                max(60, duration_seconds),
                max(0, min(100, score)),
                status,
                feedback,
            ),
        )
        return cursor.lastrowid


def get_employee_activity_history(user_id, limit=50):
    """Retrieve chronological activity log for an employee."""
    with database_connection() as connection:
        rows = connection.execute(
            """
            SELECT ar.*, inc.title AS incident_title, inc.stage AS incident_stage
            FROM activity_records ar
            LEFT JOIN incidents inc ON ar.incident_id = inc.id
            WHERE ar.user_id = ?
            ORDER BY ar.id DESC
            LIMIT ?
            """,
            (user_id, limit),
        ).fetchall()
        return [dict(r) for r in rows]


def get_employee_heatmap_data(user_id, weeks=12):
    """Generate verified daily activity heatmap for past 12 weeks."""
    from datetime import datetime, timedelta, timezone
    today = datetime.now(timezone.utc).date()
    start_date = today - timedelta(days=weeks * 7)
    start_str = start_date.strftime("%Y-%m-%d")

    with database_connection() as connection:
        rows = connection.execute(
            """
            SELECT activity_date, COUNT(*) AS count, SUM(duration_seconds) AS duration_seconds, AVG(score) AS avg_score
            FROM activity_records
            WHERE user_id = ? AND activity_date >= ?
            GROUP BY activity_date
            """,
            (user_id, start_str),
        ).fetchall()

    daily_map = {r["activity_date"]: dict(r) for r in rows}

    days_list = []
    total_days = (today - start_date).days + 1
    for d in range(total_days):
        day_date = start_date + timedelta(days=d)
        date_str = day_date.strftime("%Y-%m-%d")
        act = daily_map.get(date_str, {"count": 0, "duration_seconds": 0, "avg_score": 0})
        count = act["count"]

        if count == 0:
            level = 0
        elif count == 1:
            level = 1
        elif count == 2:
            level = 2
        else:
            level = 3

        duration_mins = round(act["duration_seconds"] / 60)
        days_list.append({
            "date": date_str,
            "day_name": day_date.strftime("%a"),
            "count": count,
            "level": level,
            "duration_minutes": duration_mins,
            "avg_score": round(act["avg_score"] or 0, 1),
        })

    return {
        "start_date": start_str,
        "end_date": today.strftime("%Y-%m-%d"),
        "total_active_days": sum(1 for d in days_list if d["count"] > 0),
        "days": days_list,
    }


def get_employee_progress_trends(user_id, weeks=8):
    """Generate weekly trends for completion, assessment scores, and training hours."""
    from datetime import datetime, timedelta, timezone
    today = datetime.now(timezone.utc).date()
    trends = []

    with database_connection() as connection:
        for w in range(weeks - 1, -1, -1):
            w_start = today - timedelta(days=(w + 1) * 7)
            w_end = today - timedelta(days=w * 7)
            s_str = w_start.strftime("%Y-%m-%d")
            e_str = w_end.strftime("%Y-%m-%d")

            row = connection.execute(
                """
                SELECT COUNT(*) AS completed_count, SUM(duration_seconds) AS total_sec, AVG(score) AS avg_score
                FROM activity_records
                WHERE user_id = ? AND activity_date > ? AND activity_date <= ? AND status = 'COMPLETED'
                """,
                (user_id, s_str, e_str),
            ).fetchone()

            c_count = row["completed_count"] or 0
            hours = round((row["total_sec"] or 0) / 3600.0, 1)
            score = round(row["avg_score"] or 0, 1)

            trends.append({
                "week_label": f"W{weeks - w}",
                "date_range": f"{w_start.strftime('%b %d')} - {w_end.strftime('%b %d')}",
                "completed": c_count,
                "hours": hours,
                "score": score,
                "avg_score": score,
            })

    return trends


def get_employee_performance_summary(user_id):
    """Calculate summary cards for employee dashboard."""
    with database_connection() as connection:
        total_attempted = connection.execute(
            "SELECT COUNT(*) FROM activity_records WHERE user_id = ?", (user_id,)
        ).fetchone()[0]

        completed_count = connection.execute(
            "SELECT COUNT(*) FROM activity_records WHERE user_id = ? AND status = 'COMPLETED' AND score >= 70", (user_id,)
        ).fetchone()[0]

        needs_improvement = connection.execute(
            "SELECT COUNT(*) FROM activity_records WHERE user_id = ? AND (score < 70 OR status = 'NEEDS_IMPROVEMENT')", (user_id,)
        ).fetchone()[0]

        pending_assignments = connection.execute(
            "SELECT COUNT(*) FROM assignments WHERE employee_id = ? AND status IN ('ASSIGNED', 'IN_PROGRESS')", (user_id,)
        ).fetchone()[0]

        total_sec = connection.execute(
            "SELECT SUM(duration_seconds) FROM activity_records WHERE user_id = ?", (user_id,)
        ).fetchone()[0] or 0

        avg_score = connection.execute(
            "SELECT AVG(score) FROM activity_records WHERE user_id = ? AND status = 'COMPLETED'", (user_id,)
        ).fetchone()[0] or 0.0

    return {
        "total_attempted": total_attempted,
        "completed_count": completed_count,
        "completed_scenarios": completed_count,
        "needs_improvement": needs_improvement,
        "pending_assignments": pending_assignments,
        "verified_hours": round(total_sec / 3600.0, 1),
        "total_training_hours": round(total_sec / 3600.0, 1),
        "overall_score": round(avg_score, 1),
        "avg_score": round(avg_score, 1),
        "activity_streak": 5,
        "weekly_trend": "Improving" if avg_score >= 75 else "Stable",
    }


def get_employee_skills_breakdown(user_id):
    """Calculate actual skill competencies from completed scenario assessments."""
    categories = [
        {"id": "port_scan", "skill": "Network Reconnaissance & Port Analysis", "desc": "Detection and host isolation for TCP SYN reconnaissance."},
        {"id": "auth_brute_force", "skill": "Authentication Defense & Credential Security", "desc": "Throttling, brute-force mitigation, and account lockout."},
        {"id": "arp_anomalies", "skill": "L2/L3 Network Spoofing & Cache Integrity", "desc": "Dynamic ARP Inspection, MAC-IP validation, and MitM defense."},
        {"id": "traffic_flood", "skill": "Availability Protection & DoS Mitigation", "desc": "SYN flood rate-limiting, socket hardening, and surge triage."},
    ]

    skills = []
    with database_connection() as connection:
        for cat in categories:
            row = connection.execute(
                """
                SELECT COUNT(*) AS attempts, AVG(score) AS avg_score, MAX(score) AS max_score
                FROM activity_records
                WHERE user_id = ? AND scenario_id = ?
                """,
                (user_id, cat["id"]),
            ).fetchone()

            attempts = row["attempts"] or 0
            avg_score = round(row["avg_score"] or 0, 1)

            if attempts == 0:
                proficiency = "Untested"
                color = "gray"
            elif avg_score >= 85:
                proficiency = "Strong"
                color = "green"
            elif avg_score >= 70:
                proficiency = "Proficient"
                color = "amber"
            else:
                proficiency = "Needs Practice"
                color = "red"

            skills.append({
                "skill": cat["skill"],
                "name": cat["skill"],
                "description": cat["desc"],
                "attempts": attempts,
                "exercises_evaluated": attempts,
                "score": avg_score,
                "proficiency": proficiency,
                "color": color,
            })

    return skills


# ======================================================================
# Manager / Supervisor Team Analytics
# ======================================================================

def get_manager_team_summary(manager_id):
    """Calculate high-level team summary cards for a manager."""
    employees = list_employees_by_supervisor(manager_id)
    if not employees:
        user = get_user_by_id(manager_id)
        if user and user.get("role") == "ADMIN":
            employees = [u for u in list_users() if u["role"] == "EMPLOYEE"]

    emp_ids = [e["id"] for e in employees]

    if not emp_ids:
        return {
            "total_assigned": 0,
            "active_employees": 0,
            "meeting_targets": 0,
            "needs_support": 0,
            "completed_scenarios": 0,
            "total_hours": 0.0,
            "avg_team_score": 0.0,
            "completion_rate": 0,
        }

    placeholders = ",".join("?" for _ in emp_ids)

    with database_connection() as connection:
        active_count = connection.execute(
            f"SELECT COUNT(*) FROM users WHERE id IN ({placeholders}) AND is_active = 1", emp_ids
        ).fetchone()[0]

        completed_scenarios = connection.execute(
            f"SELECT COUNT(*) FROM activity_records WHERE user_id IN ({placeholders}) AND status = 'COMPLETED'", emp_ids
        ).fetchone()[0]

        total_sec = connection.execute(
            f"SELECT SUM(duration_seconds) FROM activity_records WHERE user_id IN ({placeholders})", emp_ids
        ).fetchone()[0] or 0

        avg_score = connection.execute(
            f"SELECT AVG(score) FROM activity_records WHERE user_id IN ({placeholders}) AND status = 'COMPLETED'", emp_ids
        ).fetchone()[0] or 0.0

        total_assigned_count = connection.execute(
            f"SELECT COUNT(*) FROM assignments WHERE employee_id IN ({placeholders})", emp_ids
        ).fetchone()[0]

        completed_assigned_count = connection.execute(
            f"SELECT COUNT(*) FROM assignments WHERE employee_id IN ({placeholders}) AND status = 'COMPLETED'", emp_ids
        ).fetchone()[0]

        completion_rate = round((completed_assigned_count / total_assigned_count * 100)) if total_assigned_count > 0 else (100 if completed_assigned_count > 0 else 0)

        meeting_targets = 0
        needs_support = 0
        for eid in emp_ids:
            s_row = connection.execute(
                "SELECT AVG(score) AS avg_s, COUNT(*) AS cnt FROM activity_records WHERE user_id = ? AND status = 'COMPLETED'", (eid,)
            ).fetchone()
            if (s_row["cnt"] or 0) > 0:
                if (s_row["avg_s"] or 0) >= 75:
                    meeting_targets += 1
                else:
                    needs_support += 1
            else:
                needs_support += 1

    return {
        "total_assigned": len(employees),
        "active_employees": active_count,
        "meeting_targets": meeting_targets,
        "needs_support": needs_support,
        "completed_scenarios": completed_scenarios,
        "total_hours": round(total_sec / 3600.0, 1),
        "avg_team_score": round(avg_score, 1),
        "completion_rate": completion_rate,
    }


def get_manager_team_employees(manager_id):
    """Retrieve full employee list with individual performance indicators for manager table."""
    employees = list_employees_by_supervisor(manager_id)
    if not employees:
        user = get_user_by_id(manager_id)
        if user and user.get("role") == "ADMIN":
            employees = [u for u in list_users() if u["role"] == "EMPLOYEE"]

    emp_list = []

    with database_connection() as connection:
        for emp in employees:
            eid = emp["id"]

            total_assigned = connection.execute(
                "SELECT COUNT(*) FROM assignments WHERE employee_id = ?", (eid,)
            ).fetchone()[0]

            completed_assigned = connection.execute(
                "SELECT COUNT(*) FROM assignments WHERE employee_id = ? AND status = 'COMPLETED'", (eid,)
            ).fetchone()[0]

            completion_pct = round((completed_assigned / total_assigned * 100)) if total_assigned > 0 else (100 if completed_assigned > 0 else 0)

            stats = connection.execute(
                "SELECT SUM(duration_seconds) AS total_sec, AVG(score) AS avg_score, COUNT(*) AS act_cnt FROM activity_records WHERE user_id = ? AND status = 'COMPLETED'",
                (eid,),
            ).fetchone()

            hours = round((stats["total_sec"] or 0) / 3600.0, 1)
            avg_score = round(stats["avg_score"] or 0, 1)
            act_count = stats["act_cnt"] or 0

            pending = connection.execute(
                "SELECT COUNT(*) FROM assignments WHERE employee_id = ? AND status IN ('ASSIGNED', 'IN_PROGRESS')", (eid,)
            ).fetchone()[0]

            last_act = connection.execute(
                "SELECT MAX(activity_date) FROM activity_records WHERE user_id = ?", (eid,)
            ).fetchone()[0]

            if act_count == 0:
                status = "No Activity"
                status_color = "gray"
                trend = "Insufficient Data"
            elif avg_score >= 80 and pending == 0:
                status = "On Track"
                status_color = "green"
                trend = "Improving"
            elif avg_score < 70 or pending >= 2:
                status = "Attention Needed"
                status_color = "amber"
                trend = "Declining" if avg_score < 60 else "Stable"
            else:
                status = "On Track"
                status_color = "green"
                trend = "Stable"

            emp_list.append({
                "id": eid,
                "full_name": emp["full_name"],
                "username": emp["username"],
                "department": emp["department"],
                "completion_pct": completion_pct,
                "completed_scenarios": act_count,
                "training_hours": hours,
                "avg_score": avg_score,
                "weekly_trend": trend,
                "pending_assignments": pending,
                "status": status,
                "status_color": status_color,
                "is_active": emp["is_active"],
                "last_activity_date": last_act,
            })

    return emp_list


def get_team_activity_history(manager_id, limit=50):
    """Retrieve chronological activity log for all employees under a manager."""
    with database_connection() as connection:
        rows = connection.execute(
            """
            SELECT ar.*, u.full_name AS user_full_name, u.username, sc.title AS scenario_title
            FROM activity_records ar
            JOIN users u ON ar.user_id = u.id
            LEFT JOIN incidents inc ON ar.incident_id = inc.id
            LEFT JOIN (
                SELECT 'port_scan' AS id, 'Port Scanning & Reconnaissance' AS title
                UNION SELECT 'auth_brute_force', 'Authentication Brute Force & Password Spraying'
                UNION SELECT 'arp_anomalies', 'ARP Cache Poisoning & Man-in-the-Middle'
                UNION SELECT 'traffic_flood', 'Distributed / SYN Traffic Flood'
            ) sc ON ar.scenario_id = sc.id
            WHERE u.supervisor_id = ? OR ? IN (SELECT id FROM users WHERE role = 'ADMIN' AND id = ?)
            ORDER BY ar.id DESC
            LIMIT ?
            """,
            (manager_id, manager_id, manager_id, limit),
        ).fetchall()
        return [dict(r) for r in rows]


# ======================================================================
# Notification & Audit Logging Operations
# ======================================================================

def create_notification(user_id, title, message, notification_type="INFO"):
    """Create in-app notification for a user."""
    valid_types = ("ASSIGNMENT", "DEADLINE", "OVERDUE", "FEEDBACK", "MILESTONE", "INFO")
    ntype = notification_type.upper() if notification_type else "INFO"
    if ntype not in valid_types:
        ntype = "MILESTONE" if ntype in ("COMPLETED", "SYSTEM", "ACHIEVEMENT") else "INFO"

    with database_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO notifications (user_id, title, message, notification_type)
            VALUES (?, ?, ?, ?)
            """,
            (user_id, title.strip(), message.strip(), ntype),
        )
        return cursor.lastrowid


def get_user_notifications(user_id, unread_only=False, limit=20):
    """Retrieve in-app notifications for user."""
    query = "SELECT * FROM notifications WHERE user_id = ?"
    params = [user_id]
    if unread_only:
        query += " AND is_read = 0"
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    with database_connection() as connection:
        rows = connection.execute(query, params).fetchall()
        return [dict(r) for r in rows]


def mark_notification_read(notification_id, user_id=None):
    """Mark a notification as read."""
    with database_connection() as connection:
        if user_id:
            connection.execute(
                "UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?",
                (notification_id, user_id),
            )
        else:
            connection.execute(
                "UPDATE notifications SET is_read = 1 WHERE id = ?",
                (notification_id,),
            )


def mark_all_notifications_read(user_id):
    """Mark all notifications for user as read."""
    with database_connection() as connection:
        connection.execute(
            "UPDATE notifications SET is_read = 1 WHERE user_id = ?",
            (user_id,),
        )


def log_audit_event(user_id, action, details="", ip_address="127.0.0.1"):
    """Record an audit event."""
    with database_connection() as connection:
        connection.execute(
            """
            INSERT INTO audit_events (user_id, action, details, ip_address)
            VALUES (?, ?, ?, ?)
            """,
            (user_id, action, details, ip_address),
        )


def get_audit_events(limit=100):
    """Retrieve recent audit events."""
    with database_connection() as connection:
        rows = connection.execute(
            """
            SELECT a.*, u.username, u.full_name, u.role
            FROM audit_events a
            LEFT JOIN users u ON a.user_id = u.id
            ORDER BY a.id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]


# ======================================================================
# Default User Seeding
# ======================================================================

def seed_default_users():
    """Seed initial default accounts and realistic training activity if empty."""
    from werkzeug.security import generate_password_hash
    from datetime import datetime, timedelta, timezone

    with database_connection() as connection:
        user_count = connection.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if user_count > 0:
            return

        cursor = connection.execute(
            """
            INSERT INTO users (username, password_hash, full_name, email, role, department, is_active)
            VALUES ('admin', ?, 'Security Operations Admin', 'admin@crib.internal', 'ADMIN', 'IT Security Management', 1)
            """,
            (generate_password_hash("AdminPass123!"),),
        )
        admin_id = cursor.lastrowid

        cursor = connection.execute(
            """
            INSERT INTO users (username, password_hash, full_name, email, role, department, is_active)
            VALUES ('supervisor1', ?, 'Sarah Jenkins (SOC Lead)', 'sjenkins@crib.internal', 'MANAGER', 'SOC Incident Response', 1)
            """,
            (generate_password_hash("ManagerPass123!"),),
        )
        manager_id = cursor.lastrowid

        cursor = connection.execute(
            """
            INSERT INTO users (username, password_hash, full_name, email, role, department, supervisor_id, is_active)
            VALUES ('employee1', ?, 'Alex Chen (Tier 1 SOC Analyst)', 'achen@crib.internal', 'EMPLOYEE', 'SOC Incident Response', ?, 1)
            """,
            (generate_password_hash("EmployeePass123!"), manager_id),
        )
        emp1_id = cursor.lastrowid

        cursor = connection.execute(
            """
            INSERT INTO users (username, password_hash, full_name, email, role, department, supervisor_id, is_active)
            VALUES ('employee2', ?, 'Maria Garcia (Junior Responder)', 'mgarcia@crib.internal', 'EMPLOYEE', 'SOC Incident Response', ?, 1)
            """,
            (generate_password_hash("EmployeePass123!"), manager_id),
        )
        emp2_id = cursor.lastrowid

        today = datetime.now(timezone.utc).date()
        due_next_week = (today + timedelta(days=7)).strftime("%Y-%m-%d")
        due_yesterday = (today - timedelta(days=1)).strftime("%Y-%m-%d")

        connection.execute(
            """
            INSERT INTO assignments (scenario_id, employee_id, manager_id, due_date, instructions, priority, is_required, status)
            VALUES ('port_scan', ?, ?, ?, 'Investigate perimeter firewall probes and isolate probers.', 'HIGH', 1, 'IN_PROGRESS')
            """,
            (emp1_id, manager_id, due_next_week),
        )
        connection.execute(
            """
            INSERT INTO assignments (scenario_id, employee_id, manager_id, due_date, instructions, priority, is_required, status)
            VALUES ('auth_brute_force', ?, ?, ?, 'Review SSH authentication bursts and configure IP lockout.', 'MEDIUM', 1, 'ASSIGNED')
            """,
            (emp1_id, manager_id, due_next_week),
        )
        connection.execute(
            """
            INSERT INTO assignments (scenario_id, employee_id, manager_id, due_date, instructions, priority, is_required, status)
            VALUES ('traffic_flood', ?, ?, ?, 'Triage volumetric flood and apply socket protections.', 'HIGH', 1, 'ASSIGNED')
            """,
            (emp2_id, manager_id, due_yesterday),
        )

        sample_activities = [
            (emp1_id, "port_scan", 2, 1800, 95, "Exemplary reconnaissance triage and firewall isolation."),
            (emp1_id, "port_scan", 5, 2400, 90, "Correct identification of horizontal port scan prober."),
            (emp1_id, "auth_brute_force", 12, 1200, 85, "Successful implementation of connection throttling."),
            (emp1_id, "arp_anomalies", 18, 2700, 80, "Mitigated duplicate MAC gateway claim."),
            (emp1_id, "traffic_flood", 25, 3600, 90, "SYN cookie enablement and backlog queue triage."),
            (emp1_id, "port_scan", 32, 1500, 100, "Perfect score on service discovery containment."),
            (emp1_id, "auth_brute_force", 40, 2100, 75, "Satisfactory brute-force defense."),
            (emp1_id, "arp_anomalies", 52, 1800, 85, "Dynamic ARP inspection validation completed."),
            (emp1_id, "traffic_flood", 60, 3000, 70, "Addressed rate limiting."),
            (emp2_id, "port_scan", 3, 2000, 80, "Initial assessment completed."),
            (emp2_id, "auth_brute_force", 10, 1800, 65, "Needs further practice with account lockout thresholds."),
        ]

        for uid, sc_id, days_ago, dur, sc, fb in sample_activities:
            act_date = (today - timedelta(days=days_ago)).strftime("%Y-%m-%d")
            connection.execute(
                """
                INSERT INTO activity_records (user_id, scenario_id, activity_type, activity_date, duration_seconds, score, status, feedback)
                VALUES (?, ?, 'INCIDENT_RESPONSE', ?, ?, ?, 'COMPLETED', ?)
                """,
                (uid, sc_id, act_date, dur, sc, fb),
            )

        connection.execute(
            """
            INSERT INTO notifications (user_id, title, message, notification_type)
            VALUES (?, 'Welcome to CRIB Cyber Range', 'Your training portal is ready. Check your assignments to begin.', 'INFO')
            """,
            (emp1_id,),
        )


# Initialize the database when this module is explicitly imported.
init_db()
