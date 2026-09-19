from app.storage.database import initialize_database, get_connection
from app.storage.incident_store import save_incident, save_action


initialize_database()

incident = {
    "incident_id": "INC-TEST-001",
    "source_ip": "192.168.1.60",
    "severity": "CRITICAL",
    "status": "OPEN",
    "risk_score": 94,
    "risk_level": "CRITICAL",
    "confidence": 0.92,
    "created_at": "2026-09-13T23:00:00",
}

save_incident(incident)

save_action(
    "INC-TEST-001",
    "Investigating",
    "Analyst started investigation.",
)

connection = get_connection()

saved_incident = connection.execute(
    """
    SELECT *
    FROM incidents
    WHERE incident_id = ?
    """,
    ("INC-TEST-001",),
).fetchone()

saved_actions = connection.execute(
    """
    SELECT *
    FROM investigation_actions
    WHERE incident_id = ?
    """,
    ("INC-TEST-001",),
).fetchall()

connection.close()

print("\n=== DATABASE TEST ===")
print(dict(saved_incident))
print(f"Actions saved: {len(saved_actions)}")