"""
SentinelKey Database Access Layer
Supports dual-mode execution:
  - Local Zero-Config Engine: SQLite3 (default for local lab testing & offline evaluations)
  - Cloud Production Engine: PostgreSQL / Supabase (enabled via DATABASE_URL or SUPABASE_DB_URL)
"""

import sqlite3
import os
import json
from datetime import datetime, timezone

DB_FILE = os.path.join(os.path.dirname(__file__), "sentinelkey.db")
DATABASE_URL = os.environ.get("DATABASE_URL") or os.environ.get("SUPABASE_DB_URL")


class PostgresCursorWrapper:
    def __init__(self, raw_cursor):
        self._cursor = raw_cursor

    def fetchone(self):
        return self._cursor.fetchone()

    def fetchall(self):
        return self._cursor.fetchall()

    def fetchmany(self, size=None):
        return self._cursor.fetchmany(size) if size else self._cursor.fetchmany()

    @property
    def rowcount(self):
        return self._cursor.rowcount

    @property
    def lastrowid(self):
        return getattr(self._cursor, "lastrowid", None)

    def execute(self, query, params=None):
        pg_query = query.replace("?", "%s")
        if params is not None:
            self._cursor.execute(pg_query, params)
        else:
            self._cursor.execute(pg_query)
        return self

    def __iter__(self):
        return iter(self._cursor)


class PostgresConnectionWrapper:
    def __init__(self, raw_conn):
        self._conn = raw_conn

    def execute(self, query, params=None):
        cur = self._conn.cursor()
        pg_query = query.replace("?", "%s")
        if params is not None:
            cur.execute(pg_query, params)
        else:
            cur.execute(pg_query)
        return PostgresCursorWrapper(cur)

    def cursor(self):
        cur = self._conn.cursor()
        return PostgresCursorWrapper(cur)

    def commit(self):
        return self._conn.commit()

    def rollback(self):
        return self._conn.rollback()

    def close(self):
        return self._conn.close()


def get_db_connection():
    """Returns a database connection configured with row access (SQLite or PostgreSQL)."""
    if DATABASE_URL and DATABASE_URL.startswith("postgres"):
        try:
            import psycopg2
            import psycopg2.extras
            raw_conn = psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)
            raw_conn.autocommit = True
            return PostgresConnectionWrapper(raw_conn)
        except ImportError:
            print("[WARN] psycopg2 not installed. Falling back to local SQLite.")
        except Exception as e:
            print(f"[WARN] Cloud PostgreSQL connection failed ({e}). Falling back to local SQLite.")

    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initializes schema tables and indexes."""
    if DATABASE_URL and DATABASE_URL.startswith("postgres"):
        schema_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), "cloud", "supabase_schema.sql")
        if os.path.exists(schema_file):
            conn = get_db_connection()
            with open(schema_file, "r") as f:
                conn.execute(f.read())
            conn.close()
            return

    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Users table (students, faculty, administrators)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        roll_or_emp_id TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('student', 'faculty', 'admin')),
        password_hash TEXT NOT NULL,
        department TEXT DEFAULT 'ECE',
        semester TEXT DEFAULT 'IV B.Tech-I',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 2. Devices table (SentinelKey tokens - strictly bound 1-to-1 to faculty members)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS devices (
        device_id TEXT PRIMARY KEY,
        user_id INTEGER UNIQUE NOT NULL,
        helper_mask TEXT NOT NULL, -- JSON array of stable bit indices
        public_verifier TEXT NOT NULL, -- ECC Public Key Q (Option B) or SHA-256 verifier
        mac_address TEXT,              -- Factory-burned physical eFuse MAC address
        status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK(status IN ('ACTIVE', 'REVOKED', 'SUSPENDED')),
        enrolled_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    """)

    # Schema migration: ensure mac_address column exists if table was previously created
    cursor.execute("PRAGMA table_info(devices);")
    existing_cols = [row[1] for row in cursor.fetchall()]
    if "mac_address" not in existing_cols:
        cursor.execute("ALTER TABLE devices ADD COLUMN mac_address TEXT;")

    # 3. Challenges table (single-use nonces with 60s TTL)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS challenges (
        nonce TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP NOT NULL,
        used BOOLEAN DEFAULT 0,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    """)

    # 4. Attendance sessions (created by faculty, hardware-signed with non-repudiation)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS attendance_sessions (
        session_id TEXT PRIMARY KEY,
        faculty_id INTEGER NOT NULL,
        branch TEXT NOT NULL,
        year TEXT NOT NULL,
        section TEXT NOT NULL,
        subject TEXT NOT NULL,
        period INTEGER NOT NULL,
        session_date TEXT NOT NULL,
        attendance_digest TEXT, -- SHA-256 canonical hash of attendance roster
        hardware_signature TEXT, -- Hardware signature computed by ESP32 PUF key
        device_id TEXT,
        total_present INTEGER DEFAULT 0,
        total_students INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (faculty_id) REFERENCES users(id)
    );
    """)

    # 5. Attendance records (individual student presence per session)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS attendance_records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT NOT NULL,
        student_id INTEGER NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('PRESENT', 'ABSENT')),
        FOREIGN KEY (session_id) REFERENCES attendance_sessions(session_id) ON DELETE CASCADE,
        FOREIGN KEY (student_id) REFERENCES users(id)
    );
    """)

    # 6. Lost-Token Recovery & Emergency OTP Requests
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS recovery_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        reason TEXT NOT NULL,
        otp_code TEXT,
        status TEXT DEFAULT 'PENDING' CHECK(status IN ('PENDING', 'APPROVED', 'REJECTED', 'USED')),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    );
    """)

    # 7. Audit logs (immutable security event stream)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        actor_id INTEGER,
        action TEXT NOT NULL,
        details TEXT,
        ip_address TEXT DEFAULT '127.0.0.1',
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # Fast lookup indexes
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_challenges_user ON challenges(user_id, nonce);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_devices_user ON devices(user_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_att_records_session ON attendance_records(session_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_att_records_student ON attendance_records(student_id);")

    conn.commit()
    conn.close()


def log_event(action, actor_id=None, details=None, ip="127.0.0.1"):
    """Records security events into audit trail."""
    try:
        conn = get_db_connection()
        conn.execute(
            "INSERT INTO audit_logs (actor_id, action, details, ip_address) VALUES (?, ?, ?, ?)",
            (actor_id, action, details, ip)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[AUDIT LOG ERROR] {e}")


if __name__ == "__main__":
    init_db()
    print("Database schema initialized successfully at:", DB_FILE)

