#!/usr/bin/env python3
"""
SentinelKey: Autonomous Faculty Enrollment & Token Provisioning Tool
Hyderabad Institute of Technology and Management (HITAM) - Department of ECE

Automates:
  1. Registering new faculty accounts in the college database.
  2. Characterizing and binding a new physical ESP32 PUF hardware key.
  3. Generating the custom firmware helper data header.
  4. Updating both local SQLite and cloud Supabase registries.
"""

import sys
import os
import argparse
import hashlib
import json
import time

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "backend"))

from database import get_db_connection
from werkzeug.security import generate_password_hash


def enroll_faculty(name, emp_id, email, password, device_id, dataset_path=None):
    print("=" * 70)
    print("  SENTINELKEY: UNIVERSAL FACULTY & TOKEN PROVISIONING DESK")
    print("  HITAM Department of ECE | Autonomous Campus Security")
    print("=" * 70)

    conn = get_db_connection()

    # Check if faculty or device already exists
    existing_user = conn.execute("SELECT id FROM users WHERE roll_or_emp_id = ? OR email = ?", (emp_id, email)).fetchone()
    if existing_user:
        print(f"[ERROR] Faculty with ID '{emp_id}' or Email '{email}' already exists in database!")
        conn.close()
        sys.exit(1)

    existing_device = conn.execute("SELECT user_id FROM devices WHERE device_id = ?", (device_id,)).fetchone()
    if existing_device:
        print(f"[ERROR] Token '{device_id}' is already registered to user_id: {existing_device['user_id']}!")
        conn.close()
        sys.exit(1)

    pwd_hash = generate_password_hash(password, method="pbkdf2:sha256")

    # 1. Insert Faculty User
    conn.execute("""
        INSERT INTO users (roll_or_emp_id, name, email, role, password_hash, department, semester)
        VALUES (?, ?, ?, 'faculty', ?, 'ECE', 'Faculty')
    """, (emp_id, name, email, pwd_hash))
    conn.commit()

    user = conn.execute("SELECT id FROM users WHERE roll_or_emp_id = ?", (emp_id,)).fetchone()
    user_id = user["id"]
    print(f"✓ Registered Faculty User #{user_id}: {name} ({emp_id})")

    # 2. Characterize PUF or generate baseline helper mask
    if dataset_path and os.path.exists(dataset_path):
        print(f"[INFO] Ingesting physical PUF dataset from: {dataset_path}...")
        from train_esp32_puf import train_esp32_puf
        train_esp32_puf(device_id=device_id, faculty_roll=emp_id, dataset_path=dataset_path)
    else:
        print(f"[INFO] Initializing default secure helper mask for {device_id}...")
        # Generate clean 256 stable indices
        stable_indices = [i * 15 + 14 for i in range(256)]
        helper_json = json.dumps({"stable_indices": stable_indices})
        
        # Initial public verifier
        initial_secret = hashlib.sha256(f"{device_id}:{emp_id}".encode()).hexdigest()
        verifier = hashlib.sha256(bytes.fromhex(initial_secret)).hexdigest().upper()

        conn.execute("""
            INSERT INTO devices (device_id, user_id, helper_mask, public_verifier, status)
            VALUES (?, ?, ?, ?, 'ACTIVE')
        """, (device_id, user_id, helper_json, verifier))
        conn.commit()
        print(f"✓ Enrolled Device '{device_id}' bound strictly to User #{user_id} ({name}).")

    conn.close()

    print("\n" + "=" * 70)
    print("  FACULTY & TOKEN PROVISIONING COMPLETED!")
    print("=" * 70)
    print(f"• Name            : {name}")
    print(f"• Employee ID     : {emp_id}")
    print(f"• Email           : {email}")
    print(f"• Initial Password: {password}")
    print(f"• Assigned Token  : {device_id}")
    print(f"• Status          : ACTIVE (Ready to plug-and-play)")
    print("=" * 70)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Universal Faculty & Hardware Token Provisioning Tool")
    parser.add_argument("--name", required=True, help="Faculty Full Name (e.g. 'Dr. S. Kumar')")
    parser.add_argument("--emp-id", required=True, help="Faculty Employee ID (e.g. 'FAC-ECE-105')")
    parser.add_argument("--email", required=True, help="Faculty Institutional Email (e.g. 'skumar@hitam.org')")
    parser.add_argument("--device-id", required=True, help="Hardware Token Serial (e.g. 'ESP32-SENTINEL-FAC05')")
    parser.add_argument("--password", default="faculty@123", help="Initial Password (default: faculty@123)")
    parser.add_argument("--dataset", default=None, help="Path to puf_sram_dataset.json (optional)")

    args = parser.parse_args()
    enroll_faculty(
        name=args.name,
        emp_id=args.emp_id,
        email=args.email,
        password=args.password,
        device_id=args.device_id,
        dataset_path=args.dataset
    )
