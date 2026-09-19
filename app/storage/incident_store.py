from app.storage.database import get_connection


def save_incident(incident: dict) -> None:
    connection = get_connection()

    existing = connection.execute(
        """
        SELECT incident_id
        FROM incidents
        WHERE source_ip = ?
          AND severity = ?
          AND risk_score = ?
        ORDER BY created_at ASC
        LIMIT 1
        """,
        (
            incident.get("source_ip"),
            incident.get("severity"),
            incident.get("risk_score", 0),
        ),
    ).fetchone()

    if existing:
        connection.execute(
            """
            UPDATE incidents
            SET status = ?,
                risk_level = ?,
                confidence = ?
            WHERE incident_id = ?
            """,
            (
                incident.get("status", "OPEN"),
                incident.get("risk_level"),
                incident.get("confidence", 0.0),
                existing["incident_id"],
            ),
        )
    else:
        connection.execute(
            """
            INSERT INTO incidents (
                incident_id,
                source_ip,
                severity,
                status,
                risk_score,
                risk_level,
                confidence,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                incident["incident_id"],
                incident.get("source_ip"),
                incident.get("severity"),
                incident.get("status"),
                incident.get("risk_score", 0),
                incident.get("risk_level"),
                incident.get("confidence", 0.0),
                incident.get("created_at", ""),
            ),
        )

    connection.commit()
    connection.close()

def save_action(
    incident_id: str,
    action: str,
    note: str,
) -> None:
    connection = get_connection()

    connection.execute(
        """
        INSERT INTO investigation_actions (
            incident_id,
            action,
            note
        )
        VALUES (?, ?, ?)
        """,
        (
            incident_id,
            action,
            note,
        ),
    )

    connection.commit()
    connection.close()


def get_actions(incident_id: str) -> list[dict]:
    connection = get_connection()

    rows = connection.execute(
        """
        SELECT action, note, created_at
        FROM investigation_actions
        WHERE incident_id = ?
        ORDER BY id ASC
        """,
        (incident_id,),
    ).fetchall()

    connection.close()

    return [
        {
            "action": row["action"],
            "note": row["note"],
            "created_at": row["created_at"],
        }
        for row in rows
    ]
def get_incident(incident_id: str) -> dict | None:
    connection = get_connection()

    row = connection.execute(
        """
        SELECT *
        FROM incidents
        WHERE incident_id = ?
        """,
        (incident_id,),
    ).fetchone()

    connection.close()

    if row is None:
        return None

    return dict(row)
def get_all_incidents() -> list[dict]:
    connection = get_connection()

    rows = connection.execute(
        """
        SELECT *
        FROM incidents
        ORDER BY created_at DESC
        """
    ).fetchall()

    connection.close()

    return [dict(row) for row in rows]