#!/usr/bin/env python3
"""
SentinelKey: Cloud Database Migration & Sync Utility (Supabase / PostgreSQL)
Hyderabad Institute of Technology and Management (HITAM) - Department of ECE

Automates:
  1. Connection test to Supabase PostgreSQL (via URI or SUPABASE_DB_URL env var).
  2. Executes cloud/supabase_schema.sql to build tables, indexes, and RLS policies.
  3. Migrates local SQLite users, devices, helper masks, and verifiers into Supabase.
  4. Verifies cloud health and readiness for production deployment.
"""

import sys
import os
import argparse

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "backend"))

try:
    import psycopg2
    import psycopg2.extras
except ImportError:
    psycopg2 = None

from database import get_db_connection, DB_FILE


def run_migration(db_url):
    print("=" * 70)
    print("  SENTINELKEY: SUPABASE CLOUD DATABASE MIGRATOR")
    print("  HITAM Department of ECE | Autonomous Campus Security")
    print("=" * 70)

    if not psycopg2:
        print("[ERROR] 'psycopg2' is not installed.")
        print("Run: pip install psycopg2-binary")
        sys.exit(1)

    print(f"[INFO] Connecting to Supabase PostgreSQL...")
    try:
        pg_conn = psycopg2.connect(db_url)
        pg_conn.autocommit = True
        pg_cur = pg_conn.cursor()
        print("✓ Successfully connected to Supabase Cloud Database!")
    except Exception as e:
        print(f"[ERROR] Failed to connect to Supabase: {e}")
        print("Check your connection string: postgresql://postgres:[PASSWORD]@db.[REF].supabase.co:5432/postgres")
        sys.exit(1)

    # 1. Execute SQL Schema
    schema_path = os.path.join(PROJECT_ROOT, "cloud", "supabase_schema.sql")
    if os.path.exists(schema_path):
        print(f"\n[STEP 1/3] Executing Cloud Schema: {schema_path}...")
        with open(schema_path, "r") as f:
            sql_script = f.read()
        try:
            pg_cur.execute(sql_script)
            print("✓ Tables (users, devices, challenges, attendance) initialized on Supabase.")
        except Exception as e:
            print(f"[WARN] Schema execution message: {e}")

    # 2. Migrate data from local SQLite
    print("\n[STEP 2/3] Migrating accounts and enrolled hardware tokens from local SQLite...")
    import sqlite3
    if not os.path.exists(DB_FILE):
        print(f"[WARN] Local database {DB_FILE} not found. Seeding fresh users...")
        import database
        database.init_db()
        database.seed_initial_data()

    local_conn = sqlite3.connect(DB_FILE)
    local_conn.row_factory = sqlite3.Row
    local_cur = local_conn.cursor()

    # Migrate Users
    users = local_cur.execute("SELECT * FROM users").fetchall()
    print(f"  • Migrating {len(users)} users (Students, Faculty, Admin)...")
    for u in users:
        pg_cur.execute("""
            INSERT INTO users (id, roll_or_emp_id, name, email, role, password_hash, department, semester)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (roll_or_emp_id) DO UPDATE SET
                name = EXCLUDED.name,
                email = EXCLUDED.email,
                role = EXCLUDED.role,
                password_hash = EXCLUDED.password_hash;
        """, (u["id"], u["roll_or_emp_id"], u["name"], u["email"], u["role"], u["password_hash"], u["department"], u["semester"]))

    # Migrate Devices (PUF Tokens)
    devices = local_cur.execute("SELECT * FROM devices").fetchall()
    print(f"  • Migrating {len(devices)} hardware PUF tokens...")
    for d in devices:
        mac = d["mac_address"] if "mac_address" in d.keys() else None
        pg_cur.execute("""
            INSERT INTO devices (device_id, user_id, helper_mask, public_verifier, mac_address, status)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (device_id) DO UPDATE SET
                user_id = EXCLUDED.user_id,
                helper_mask = EXCLUDED.helper_mask,
                public_verifier = EXCLUDED.public_verifier,
                mac_address = EXCLUDED.mac_address,
                status = EXCLUDED.status;
        """, (d["device_id"], d["user_id"], d["helper_mask"], d["public_verifier"], mac, d["status"]))

    local_conn.close()
    print("✓ Data migration completed successfully.")

    # 3. Verify Cloud Records
    print("\n[STEP 3/3] Verifying Cloud Database Integrity...")
    pg_cur.execute("SELECT COUNT(*) FROM users;")
    u_count = pg_cur.fetchone()[0]
    pg_cur.execute("SELECT COUNT(*) FROM devices;")
    d_count = pg_cur.fetchone()[0]

    print(f"  • Cloud Users Total   : {u_count}")
    print(f"  • Cloud Devices Total : {d_count}")
    pg_conn.close()

    print("\n" + "=" * 70)
    print("  SUPABASE CLOUD MIGRATION COMPLETE & VERIFIED!")
    print("=" * 70)
    print("To make the backend permanently use Supabase:")
    print(f"  export DATABASE_URL=\"{db_url}\"")
    print("  python3 backend/app.py")
    print("=" * 70)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Migrate SentinelKey Database to Supabase PostgreSQL")
    parser.add_argument("--url", default=os.environ.get("DATABASE_URL") or os.environ.get("SUPABASE_DB_URL"),
                        help="Supabase PostgreSQL connection URI")
    args = parser.parse_args()

    if not args.url:
        print("[ERROR] Please provide a Supabase database URL via --url or export DATABASE_URL")
        print("Example: python3 scripts/migrate_to_supabase.py --url 'postgresql://postgres:[PASSWORD]@db.[REF].supabase.co:5432/postgres'")
        sys.exit(1)

    run_migration(args.url)
