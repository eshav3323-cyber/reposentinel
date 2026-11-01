
import json
import os
import sqlite3
from pathlib import Path
from threading import RLock

MAX_STORED_SCANS = 50
_LOCK = RLock()


def _database_path() -> Path:
    configured_path = os.getenv("REPOSENTINEL_DB_PATH")

    if configured_path:
        path = Path(configured_path)
    else:
        # Local development default. On Render, configure a persistent
        # disk path through REPOSENTINEL_DB_PATH.
        path = Path(__file__).resolve().parents[2] / "data" / "reposentinel.db"

    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _connect():
    connection = sqlite3.connect(str(_database_path()), timeout=15)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_scan_storage():
    with _LOCK, _connect() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                result_json TEXT NOT NULL
            )
        """)
        connection.commit()


def save_scan(result: dict):
    """Persist a scan and keep only the 50 most recent scans."""
    serialized = json.dumps(result, ensure_ascii=False)

    with _LOCK, _connect() as connection:
        connection.execute(
            """
            INSERT INTO scans (scan_id, created_at, result_json)
            VALUES (?, ?, ?)
            ON CONFLICT(scan_id) DO UPDATE SET
                created_at = excluded.created_at,
                result_json = excluded.result_json
            """,
            (result["scan_id"], result["created_at"], serialized),
        )

        connection.execute("""
            DELETE FROM scans
            WHERE scan_id NOT IN (
                SELECT scan_id
                FROM scans
                ORDER BY created_at DESC, rowid DESC
                LIMIT ?
            )
        """, (MAX_STORED_SCANS,))

        connection.commit()


def get_scan(scan_id: str) -> dict | None:
    with _LOCK, _connect() as connection:
        row = connection.execute(
            "SELECT result_json FROM scans WHERE scan_id = ?",
            (scan_id,),
        ).fetchone()

    if row is None:
        return None

    return json.loads(row["result_json"])


def load_scans() -> dict[str, dict]:
    with _LOCK, _connect() as connection:
        rows = connection.execute("""
            SELECT scan_id, result_json
            FROM scans
            ORDER BY created_at ASC, rowid ASC
        """).fetchall()

    return {
        row["scan_id"]: json.loads(row["result_json"])
        for row in rows
    }
