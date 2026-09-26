#!/usr/bin/env python3
"""
Full API Multi-Role & Lost-Token Recovery Test Suite
SentinelKey Major Project - HITAM Department of ECE
"""

import unittest
import json
import hmac
import hashlib
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../backend")))
from database import get_db_connection, init_db
from seed_data import seed_database
from app import app, FACULTY_GOLDEN_KEYS


class TestSentinelKeyAPI(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        seed_database()

    def setUp(self):
        self.client = app.test_client()
        self.client.testing = True

    def test_student_direct_login_flow(self):
        """Student enters password -> immediate login (NO hardware token required)."""
        p_resp = self.client.post("/api/auth/login-pass", json={
            "identifier": "23E51A0417",
            "password": "Sri@7254"
        })
        self.assertEqual(p_resp.status_code, 200)
        p_data = p_resp.get_json()
        self.assertEqual(p_data["status"], "SUCCESS")
        self.assertEqual(p_data["role"], "student")
        self.assertIn("session_token", p_data)

    def test_faculty_hardware_login_flow(self):
        """Faculty enters password -> receives challenge -> signs with silicon PUF -> enters."""
        # Step 1: Password
        p_resp = self.client.post("/api/auth/login-pass", json={
            "identifier": "FAC-ECE-101",
            "password": "faculty@123"
        })
        self.assertEqual(p_resp.status_code, 200)
        p_data = p_resp.get_json()
        self.assertEqual(p_data["status"], "REQUIRE_HARDWARE_TOKEN")
        self.assertEqual(p_data["device_id"], "ESP32-SENTINEL-FAC01")
        user_id = p_data["user_id"]

        # Step 2: Challenge
        c_resp = self.client.get(f"/api/auth/challenge?user_id={user_id}")
        self.assertEqual(c_resp.status_code, 200)
        nonce = c_resp.get_json()["nonce"]

        # Step 3: Silicon Signature
        golden_key = bytes.fromhex(FACULTY_GOLDEN_KEYS["ESP32-SENTINEL-FAC01"])
        sig = hmac.new(golden_key, nonce.encode(), hashlib.sha256).hexdigest().upper()

        v_resp = self.client.post("/api/auth/verify-token", json={
            "user_id": user_id,
            "nonce": nonce,
            "signature": sig,
            "device_id": "ESP32-SENTINEL-FAC01"
        })
        self.assertEqual(v_resp.status_code, 200)
        v_data = v_resp.get_json()
        self.assertEqual(v_data["status"], "SUCCESS")
        self.assertEqual(v_data["role"], "faculty")
        self.assertIn("session_token", v_data)

    def test_faculty_attendance_flow(self):
        """Faculty fetches roster and submits hardware-signed attendance session."""
        # 1. Fetch class roster
        roster_resp = self.client.get("/api/faculty/roster?branch=ECE&year=IV&section=A")
        self.assertEqual(roster_resp.status_code, 200)
        roster_data = roster_resp.get_json()
        self.assertGreaterEqual(len(roster_data["students"]), 5)

        # 2. Submit attendance with hardware signature
        sub_resp = self.client.post("/api/faculty/submit-attendance", json={
            "faculty_id": 2,
            "branch": "ECE",
            "year": "IV",
            "section": "A",
            "subject": "Hardware Security & Cryptography",
            "period": 2,
            "session_date": "2026-09-15",
            "records": [{"student_id": s["id"], "status": "PRESENT"} for s in roster_data["students"]],
            "hardware_signature": "SIG-HW-FAB9837492817492837498237489237489237489237489237489237489237489"
        })
        self.assertEqual(sub_resp.status_code, 200)
        self.assertEqual(sub_resp.get_json()["status"], "SUCCESS")

    def test_lost_token_and_emergency_otp_recovery(self):
        """Faculty reports lost token -> Admin revokes device and issues OTP -> Faculty logs in."""
        emp_id = "FAC-ECE-102"  # Dr. P. Sunitha
        
        # 1. Faculty reports lost token
        req_resp = self.client.post("/api/auth/lost-token-request", json={
            "identifier": emp_id,
            "reason": "Lost ESP32 token during commute"
        })
        self.assertEqual(req_resp.status_code, 200)

        # 2. Admin revokes lost token
        conn = get_db_connection()
        user = conn.execute("SELECT id FROM users WHERE roll_or_emp_id = ?", (emp_id,)).fetchone()
        u_id = user["id"]
        conn.close()

        rev_resp = self.client.post("/api/admin/revoke-device", json={
            "device_id": "ESP32-SENTINEL-FAC02"
        })
        self.assertEqual(rev_resp.status_code, 200)

        # 3. Trying to login with password now warns token revoked
        lp_resp = self.client.post("/api/auth/login-pass", json={
            "identifier": emp_id,
            "password": "faculty@123"
        })
        self.assertEqual(lp_resp.status_code, 403)
        self.assertEqual(lp_resp.get_json()["status"], "TOKEN_REVOKED")

        # 4. Admin issues emergency OTP
        otp_resp = self.client.post("/api/admin/issue-recovery-otp", json={
            "user_id": u_id
        })
        self.assertEqual(otp_resp.status_code, 200)
        otp_code = otp_resp.get_json()["otp_code"]
        self.assertEqual(len(otp_code), 6)

        # 5. Faculty logs in with emergency OTP
        verify_otp_resp = self.client.post("/api/auth/verify-recovery-otp", json={
            "identifier": emp_id,
            "otp_code": otp_code
        })
        self.assertEqual(verify_otp_resp.status_code, 200)
        v_otp_data = verify_otp_resp.get_json()
        self.assertEqual(v_otp_data["status"], "SUCCESS")
        self.assertEqual(v_otp_data["security_mode"], "EMERGENCY_TEMPORARY_ACCESS")


if __name__ == "__main__":
    unittest.main()
