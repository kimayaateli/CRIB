
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


def create_incident(scenario_id, title):
    """Create an incident and return its database ID."""
    with database_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO incidents (scenario_id, title)
            VALUES (?, ?)
            """,
            (scenario_id, title),
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


# Initialize the database when this module is explicitly imported.
init_db()
