"""SQLite-backed local account and audit helpers."""

import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DB_PATH = PROJECT_ROOT / "data" / "dashboard.sqlite3"
PASSWORDS = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)
MAX_LOGIN_FAILURES = 5
LOCKOUT_SECONDS = 15 * 60


@contextmanager
def _connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def init_db():
    with _connect() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('admin', 'operator', 'viewer')),
                active INTEGER NOT NULL DEFAULT 1,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY,
                created_at TEXT NOT NULL,
                actor TEXT,
                action TEXT NOT NULL,
                target TEXT,
                result TEXT NOT NULL,
                detail TEXT
            );
            CREATE TABLE IF NOT EXISTS scan_jobs (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                requested_by TEXT NOT NULL,
                providers TEXT NOT NULL,
                status TEXT NOT NULL,
                message TEXT,
                result TEXT
            );
            CREATE TABLE IF NOT EXISTS passkey_credentials (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                credential_id TEXT NOT NULL UNIQUE,
                public_key BLOB NOT NULL,
                sign_count INTEGER NOT NULL DEFAULT 0,
                transports TEXT NOT NULL DEFAULT '[]',
                name TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_used_at TEXT
            );
            CREATE INDEX IF NOT EXISTS audit_created_idx ON audit_events(created_at DESC);
        """)
        columns = {row["name"] for row in db.execute("PRAGMA table_info(scan_jobs)")}
        if "result" not in columns:
            db.execute("ALTER TABLE scan_jobs ADD COLUMN result TEXT")


def list_passkeys(user_id):
    with _connect() as db:
        rows = db.execute(
            "SELECT id,name,created_at,last_used_at FROM passkey_credentials WHERE user_id=? ORDER BY id",
            (user_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def passkey_credentials(user_id):
    with _connect() as db:
        rows = db.execute(
            "SELECT id,credential_id,public_key,sign_count,transports,name FROM passkey_credentials WHERE user_id=? ORDER BY id",
            (user_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def get_passkey(user_id, credential_id):
    with _connect() as db:
        row = db.execute(
            "SELECT * FROM passkey_credentials WHERE user_id=? AND credential_id=?",
            (user_id, credential_id),
        ).fetchone()
    return dict(row) if row else None


def save_passkey(user_id, credential_id, public_key, sign_count, transports, name):
    with _connect() as db:
        db.execute(
            "INSERT INTO passkey_credentials(user_id,credential_id,public_key,sign_count,transports,name,created_at) VALUES(?,?,?,?,?,?,?)",
            (user_id, credential_id, public_key, sign_count, transports, name, datetime.now(timezone.utc).isoformat()),
        )


def update_passkey_usage(credential_id, sign_count):
    with _connect() as db:
        db.execute(
            "UPDATE passkey_credentials SET sign_count=?,last_used_at=? WHERE credential_id=?",
            (sign_count, datetime.now(timezone.utc).isoformat(), credential_id),
        )


def validate_password(password):
    if len(password) < 12:
        raise ValueError("Use a password with at least 12 characters.")
    if len(password) > 256:
        raise ValueError("Password is too long.")


def create_user(username, password, role="admin"):
    username = username.strip().lower()
    if not 3 <= len(username) <= 80:
        raise ValueError("Username must be between 3 and 80 characters.")
    if role not in {"admin", "operator", "viewer"}:
        raise ValueError("Choose admin, operator, or viewer.")
    validate_password(password)
    try:
        with _connect() as db:
            db.execute(
                "INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
                (username, PASSWORDS.hash(password), role, datetime.now(timezone.utc).isoformat()),
            )
    except sqlite3.IntegrityError as error:
        raise ValueError("That username already exists.") from error
    audit(username, "account.created", username, "success", f"role={role}")


def user_count():
    with _connect() as db:
        return db.execute("SELECT COUNT(*) FROM users WHERE active=1").fetchone()[0]


def get_user(user_id):
    with _connect() as db:
        row = db.execute(
            "SELECT id,username,role,active FROM users WHERE id=?", (user_id,)
        ).fetchone()
    return dict(row) if row else None


def list_users():
    with _connect() as db:
        rows = db.execute(
            "SELECT id,username,role,active,created_at FROM users ORDER BY id"
        ).fetchall()
    return [dict(row) for row in rows]


def authenticate(username, password):
    username = username.strip().lower()
    now = int(time.time())
    with _connect() as db:
        row = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if not row or not row["active"]:
            return None, "Invalid username or password."
        if row["locked_until"] > now:
            return None, "Account is temporarily locked. Try again later."
        try:
            valid = PASSWORDS.verify(row["password_hash"], password)
        except (VerifyMismatchError, InvalidHashError, TypeError):
            valid = False
        if not valid:
            failures = row["failed_attempts"] + 1
            locked_until = now + LOCKOUT_SECONDS if failures >= MAX_LOGIN_FAILURES else 0
            db.execute(
                "UPDATE users SET failed_attempts=?,locked_until=? WHERE id=?",
                (0 if locked_until else failures, locked_until, row["id"]),
            )
            return None, "Account is temporarily locked. Try again later." if locked_until else "Invalid username or password."
        db.execute(
            "UPDATE users SET failed_attempts=0,locked_until=0 WHERE id=?", (row["id"],)
        )
        return {"id": row["id"], "username": row["username"], "role": row["role"]}, None


def verify_user_password(user_id, password):
    with _connect() as db:
        row = db.execute("SELECT password_hash,active FROM users WHERE id=?", (user_id,)).fetchone()
    if not row or not row["active"]:
        return False
    try:
        return PASSWORDS.verify(row["password_hash"], password)
    except (VerifyMismatchError, InvalidHashError, TypeError):
        return False


def audit(actor, action, target=None, result="success", detail=None):
    with _connect() as db:
        db.execute(
            "INSERT INTO audit_events(created_at,actor,action,target,result,detail) VALUES(?,?,?,?,?,?)",
            (datetime.now(timezone.utc).isoformat(), actor, action, target, result, detail),
        )


def recent_audit(limit=100):
    with _connect() as db:
        rows = db.execute(
            "SELECT created_at,actor,action,target,result,detail FROM audit_events ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def create_scan_job(job_id, username, providers):
    now = datetime.now(timezone.utc).isoformat()
    with _connect() as db:
        db.execute(
            "INSERT INTO scan_jobs(id,created_at,updated_at,requested_by,providers,status,message,result) VALUES(?,?,?,?,?,'queued','Waiting to start',NULL)",
            (job_id, now, now, username, ",".join(providers)),
        )


def update_scan_job(job_id, status, message, result=None):
    with _connect() as db:
        db.execute(
            "UPDATE scan_jobs SET updated_at=?,status=?,message=?,result=? WHERE id=?",
            (datetime.now(timezone.utc).isoformat(), status, message, result, job_id),
        )


def get_scan_job(job_id):
    with _connect() as db:
        row = db.execute("SELECT * FROM scan_jobs WHERE id=?", (job_id,)).fetchone()
    return dict(row) if row else None


def recent_scan_jobs(limit=30):
    with _connect() as db:
        rows = db.execute(
            "SELECT id,created_at,updated_at,requested_by,providers,status,message FROM scan_jobs ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]
