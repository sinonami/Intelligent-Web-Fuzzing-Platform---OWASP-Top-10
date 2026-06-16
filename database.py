# database.py
"""
database.py — SQLite backend for Intelligent Fuzzer
Replaces users.json + scans_history.json with a proper relational DB.

Tables:
  users       — id, username, password_hash, created_at
  scans       — id, user_id, target_url, scan_date, result_count
  scan_results— id, scan_id, type, owasp_category, payload, method,
                status_code, severity, details
"""

import sqlite3
import hashlib
import json
import os
from datetime import datetime
from contextlib import contextmanager

# ── DB file lives next to main.py inside the container ──────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH  = os.path.join(BASE_DIR, 'fuzzer.db')


# ── Connection helper ────────────────────────────────────────────────────────
@contextmanager
def get_db():
    """Yield a connection with foreign-keys on and row_factory set."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ── Schema creation (called once at app startup) ─────────────────────────────
def init_db():
    """Create all tables if they don't already exist."""
    with get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                username     TEXT    NOT NULL UNIQUE,
                password_hash TEXT   NOT NULL,
                created_at   TEXT    NOT NULL
            );

            CREATE TABLE IF NOT EXISTS scans (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                target_url   TEXT    NOT NULL,
                scan_date    TEXT    NOT NULL,
                result_count INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS scan_results (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id        INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                type           TEXT,
                owasp_category TEXT,
                payload        TEXT,
                method         TEXT,
                status_code    INTEGER,
                severity       TEXT,
                details        TEXT
            );
        """)
    print("[DB] Database initialised at:", DB_PATH)


# ── Password hashing ─────────────────────────────────────────────────────────
def _hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


# ── Auth functions (called by main.py) ──────────────────────────────────────
def register_user(username: str, password: str):
    """
    Register a new user.
    Returns (True, success_msg) or (False, error_msg).
    """
    if not username or not password:
        return False, "Username and password are required."
    if len(password) < 6:
        return False, "Password must be at least 6 characters."

    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                (username.strip(), _hash_password(password), datetime.now().isoformat())
            )
        return True, f"Account created for {username}. You can now sign in."
    except sqlite3.IntegrityError:
        return False, "Username already taken. Please choose another."
    except Exception as e:
        return False, f"Registration failed: {e}"


def login_user(username: str, password: str):
    """
    Verify credentials.
    Returns (True, success_msg) or (False, error_msg).
    """
    if not username or not password:
        return False, "Please enter both username and password."

    try:
        with get_db() as conn:
            row = conn.execute(
                "SELECT password_hash FROM users WHERE username = ?",
                (username.strip(),)
            ).fetchone()

        if row and row["password_hash"] == _hash_password(password):
            return True, f"Welcome back, {username}!"
        return False, "Incorrect username or password."
    except Exception as e:
        return False, f"Login error: {e}"


# ── Scan persistence (called by main.py) ────────────────────────────────────
def save_scan_to_user(username: str, target_url: str, results: list):
    """
    Save a completed scan and all its findings for a given user.
    Silently does nothing if the user is not found.
    """
    try:
        with get_db() as conn:
            user = conn.execute(
                "SELECT id FROM users WHERE username = ?", (username,)
            ).fetchone()
            if not user:
                return

            cur = conn.execute(
                "INSERT INTO scans (user_id, target_url, scan_date, result_count) VALUES (?, ?, ?, ?)",
                (user["id"], target_url, datetime.now().strftime("%Y-%m-%d %H:%M"), len(results))
            )
            scan_id = cur.lastrowid

            conn.executemany(
                """INSERT INTO scan_results
                   (scan_id, type, owasp_category, payload, method, status_code, severity, details)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                [(
                    scan_id,
                    r.get("type", ""),
                    r.get("owasp_category", ""),
                    r.get("payload", ""),
                    r.get("method", "GET"),
                    r.get("status_code", 200),
                    r.get("severity", "LOW"),
                    r.get("details", "")
                ) for r in results]
            )
    except Exception as e:
        print(f"[DB] save_scan_to_user error: {e}")


def get_user_scans(username: str) -> list:
    """
    Return a list of scan summaries for history.html.
    Each item: { date, target, count }
    Ordered newest-first.
    """
    try:
        with get_db() as conn:
            user = conn.execute(
                "SELECT id FROM users WHERE username = ?", (username,)
            ).fetchone()
            if not user:
                return []

            rows = conn.execute(
                """SELECT scan_date, target_url, result_count
                   FROM scans
                   WHERE user_id = ?
                   ORDER BY id DESC""",
                (user["id"],)
            ).fetchall()

        return [{"date": r["scan_date"], "target": r["target_url"], "count": r["result_count"]} for r in rows]
    except Exception as e:
        print(f"[DB] get_user_scans error: {e}")
        return []


def delete_user_scan(username: str, scan_index: int):
    """
    Delete a single scan by its position in the user's scan list (0-based, newest-first).
    Returns (True, 1) on success, (False, 0) on failure.
    """
    try:
        with get_db() as conn:
            user = conn.execute(
                "SELECT id FROM users WHERE username = ?", (username,)
            ).fetchone()
            if not user:
                return False, 0

            # Fetch all scan IDs ordered newest-first, pick the one at scan_index
            rows = conn.execute(
                "SELECT id FROM scans WHERE user_id = ? ORDER BY id DESC",
                (user["id"],)
            ).fetchall()

            if scan_index < 0 or scan_index >= len(rows):
                return False, 0

            target_id = rows[scan_index]["id"]
            conn.execute("DELETE FROM scans WHERE id = ?", (target_id,))

        return True, 1
    except Exception as e:
        print(f"[DB] delete_user_scan error: {e}")
        return False, 0


def delete_user_scans_batch(username: str, scan_indices: list):
    """
    Delete multiple scans by their positions (0-based, newest-first).
    Returns (True, deleted_count) or (False, 0).
    """
    try:
        with get_db() as conn:
            user = conn.execute(
                "SELECT id FROM users WHERE username = ?", (username,)
            ).fetchone()
            if not user:
                return False, 0

            rows = conn.execute(
                "SELECT id FROM scans WHERE user_id = ? ORDER BY id DESC",
                (user["id"],)
            ).fetchall()

            ids_to_delete = []
            for idx in scan_indices:
                if 0 <= idx < len(rows):
                    ids_to_delete.append(rows[idx]["id"])

            if not ids_to_delete:
                return False, 0

            conn.execute(
                f"DELETE FROM scans WHERE id IN ({','.join('?' * len(ids_to_delete))})",
                ids_to_delete
            )

        return True, len(ids_to_delete)
    except Exception as e:
        print(f"[DB] delete_user_scans_batch error: {e}")
        return False, 0


# ── Auto-init on import ──────────────────────────────────────────────────────
init_db()