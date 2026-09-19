import sqlite3
from pathlib import Path


DB_PATH = Path("data/cybersentinel.db")


def get_connection() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(DB_PATH)

    connection.row_factory = sqlite3.Row

    return connection


def initialize_database() -> None:
    connection = get_connection()

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS incidents (
            incident_id TEXT PRIMARY KEY,
            source_ip TEXT,
            severity TEXT,
            status TEXT,
            risk_score INTEGER,
            risk_level TEXT,
            confidence REAL,
            created_at TEXT
        )
        """
    )

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS investigation_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id TEXT NOT NULL,
            action TEXT NOT NULL,
            note TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    connection.commit()
    connection.close()