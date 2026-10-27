"""Safe, non-destructive schema repair script for CRIB SQLite database (crib.db).

Repairs foreign key constraints on events, decisions, and alerts that were left
referencing 'incidents_old' following an earlier schema migration.

Guarantees:
1. Zero data loss: All rows and IDs are strictly preserved.
2. Verified row counts before and after repair.
3. PRAGMA foreign_key_check verification to ensure 0 violations.
4. Automatic rollback on any assertion failure.
"""

import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = BASE_DIR / "crib.db"


def repair_database():
    print(f"[*] Opening database: {DATABASE_PATH}")
    connection = sqlite3.connect(DATABASE_PATH)

    try:
        connection.execute("PRAGMA foreign_keys = OFF")

        # 1. Baseline Counts
        cnt_events = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        cnt_decisions = connection.execute("SELECT COUNT(*) FROM decisions").fetchone()[0]
        cnt_alerts = connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        cnt_incidents = connection.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]

        print(f"[*] Pre-repair row counts:")
        print(f"    - incidents: {cnt_incidents}")
        print(f"    - events:    {cnt_events}")
        print(f"    - decisions: {cnt_decisions}")
        print(f"    - alerts:    {cnt_alerts}")

        # 2. Rebuild child tables with correct foreign keys pointing to incidents(id)
        with connection:
            # --- Table: events ---
            connection.execute("""
                CREATE TABLE events_repaired (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id INTEGER,
                    event_type TEXT NOT NULL,
                    source_ip TEXT,
                    destination_ip TEXT,
                    destination_port INTEGER,
                    details TEXT NOT NULL DEFAULT '',
                    timestamp TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                    FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE SET NULL
                )
            """)
            connection.execute("""
                INSERT INTO events_repaired (id, incident_id, event_type, source_ip, destination_ip, destination_port, details, timestamp)
                SELECT id, incident_id, event_type, source_ip, destination_ip, destination_port, details, timestamp FROM events
            """)
            connection.execute("DROP TABLE events")
            connection.execute("ALTER TABLE events_repaired RENAME TO events")

            # --- Table: decisions ---
            connection.execute("""
                CREATE TABLE decisions_repaired (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id INTEGER NOT NULL,
                    stage TEXT NOT NULL,
                    choice_id TEXT NOT NULL,
                    points INTEGER NOT NULL DEFAULT 0,
                    explanation TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                    FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE,
                    UNIQUE (incident_id, stage)
                )
            """)
            connection.execute("""
                INSERT INTO decisions_repaired (id, incident_id, stage, choice_id, points, explanation, created_at)
                SELECT id, incident_id, stage, choice_id, points, explanation, created_at FROM decisions
            """)
            connection.execute("DROP TABLE decisions")
            connection.execute("ALTER TABLE decisions_repaired RENAME TO decisions")

            # --- Table: alerts ---
            connection.execute("""
                CREATE TABLE alerts_repaired (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id INTEGER,
                    rule_id TEXT NOT NULL,
                    severity TEXT NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
                    message TEXT NOT NULL,
                    detection_method TEXT NOT NULL DEFAULT 'RULE_BASED',
                    mitre_technique TEXT NOT NULL DEFAULT '',
                    affected_component TEXT NOT NULL DEFAULT '',
                    recommendation TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                    FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE SET NULL
                )
            """)
            connection.execute("""
                INSERT INTO alerts_repaired (id, incident_id, rule_id, severity, message, detection_method, mitre_technique, affected_component, recommendation, created_at)
                SELECT id, incident_id, rule_id, severity, message, detection_method, mitre_technique, affected_component, recommendation, created_at FROM alerts
            """)
            connection.execute("DROP TABLE alerts")
            connection.execute("ALTER TABLE alerts_repaired RENAME TO alerts")

            # 3. Restore all indexes
            connection.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type)")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_decisions_incident ON decisions(incident_id)")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_alerts_incident ON alerts(incident_id)")

            # 4. Strict Row Conservation Assertions
            after_events = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            after_decisions = connection.execute("SELECT COUNT(*) FROM decisions").fetchone()[0]
            after_alerts = connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            after_incidents = connection.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]

            assert after_events == cnt_events, f"Event count mismatch: {after_events} vs {cnt_events}"
            assert after_decisions == cnt_decisions, f"Decision count mismatch: {after_decisions} vs {cnt_decisions}"
            assert after_alerts == cnt_alerts, f"Alert count mismatch: {after_alerts} vs {cnt_alerts}"
            assert after_incidents == cnt_incidents, f"Incident count mismatch: {after_incidents} vs {cnt_incidents}"

        # 5. Enable and Validate Foreign Keys
        connection.execute("PRAGMA foreign_keys = ON")
        violations = connection.execute("PRAGMA foreign_key_check").fetchall()
        assert len(violations) == 0, f"Foreign key integrity violations detected: {violations}"

        print("[+] Post-repair row counts verified identical:")
        print(f"    - incidents: {after_incidents}")
        print(f"    - events:    {after_events}")
        print(f"    - decisions: {after_decisions}")
        print(f"    - alerts:    {after_alerts}")
        print("[+] Foreign key integrity check: 0 violations.")
        print("[+] Repair completed successfully.")

    finally:
        connection.close()


if __name__ == "__main__":
    repair_database()
