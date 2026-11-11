"""The corrected version of fixtures/vulnerable/sqli_demo.py."""
import os
import re
import sqlite3
import subprocess

DB_PASSWORD = os.environ.get("DB_PASSWORD", "")  # secret comes from the environment

_HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")


def find_user(conn: sqlite3.Connection, username: str):
    # Parameterized query: the driver keeps data and SQL separate
    return conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchall()


def ping(host: str):
    if not _HOST_RE.match(host):  # allow-list validation
        raise ValueError("invalid host")
    # argument list, no shell
    return subprocess.run(["ping", "-n", "1", host], shell=False, check=False)
