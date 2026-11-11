"""INTENTIONALLY VULNERABLE FIXTURE - scanner demo only. Never imported by the app,
never shipped in the Docker image (see .dockerignore), excluded from the normal scan."""
import sqlite3
import subprocess

DB_PASSWORD = "hunter2-demo-not-real"  # hard-coded secret (CWE-798)


def find_user(conn: sqlite3.Connection, username: str):
    # SQL injection (CWE-89): user input concatenated into the query
    return conn.execute("SELECT * FROM users WHERE username = '" + username + "'").fetchall()


def ping(host: str):
    # Command injection (CWE-78): shell=True with user input
    return subprocess.run("ping -n 1 " + host, shell=True)
