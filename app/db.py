"""SQLite access. Every query is parameterized (no string-built SQL => no SQL injection)."""
import sqlite3
from contextlib import closing
from pathlib import Path

from .config import Settings


def connect(settings: Settings) -> sqlite3.Connection:
    Path(settings.db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(settings.db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(settings: Settings) -> None:
    with closing(connect(settings)) as conn, conn:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS users (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   username TEXT NOT NULL UNIQUE,
                   email TEXT NOT NULL UNIQUE,
                   password_hash TEXT NOT NULL,
                   created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
               )"""
        )


def create_user(settings: Settings, username: str, email: str, password_hash: str) -> bool:
    """Returns False if username/email already exists."""
    try:
        with closing(connect(settings)) as conn, conn:
            conn.execute(
                "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                (username, email, password_hash),
            )
        return True
    except sqlite3.IntegrityError:
        return False


def get_user(settings: Settings, username: str) -> sqlite3.Row | None:
    with closing(connect(settings)) as conn:
        return conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
