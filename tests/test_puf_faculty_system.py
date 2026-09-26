#!/usr/bin/env python3
"""
Comprehensive Test Suite for Faculty-Only PUF Hardware Gating & Attestation
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


class TestPUFFacultySystem(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Fresh database seed before tests
        seed_database()

    def setUp(self):
        self.client = app.test_client()
        self.client.testing = True

    def test_01_student_direct_login_no_hardware(self):
        """Verify students log in directly with credentials—NO hardware prompt."""
        resp = self.client.post("/api/auth/login-pass", json={
            "identifier": "23E51A0417",
            "password": "Sri@7254"
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "SUCCESS")
        self.assertEqual(data["role"], "student")
        self.assertIn("session_token", data)
        self.assertEqual(data["user"]["roll_or_emp_id"], "23E51A0417")

    def test_02_admin_direct_login_no_hardware(self):
        """Verify admin logs in directly with credentials—NO hardware prompt."""
        resp = self.client.post("/api/auth/login-pass", json={
            "identifier": "admin@hitam.org",
            "password": "admin@123"
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "SUCCESS")
        self.assertEqual(data["role"], "admin")
        self.assertIn("session_token", data)

    def test_03_all_4_faculty_strictly_gated_by_hardware(self):
        """Verify all 4 faculty members are strictly required to use their assigned USB token."""
        faculty_bindings = [
            ("FAC-ECE-101", "faculty@123", "ESP32-SENTINEL-FAC01"),
            ("FAC-ECE-102", "faculty@123", "ESP32-SENTINEL-FAC02"),
            ("FAC-ECE-103", "faculty@123", "ESP32-SENTINEL-FAC03"),
            ("FAC-ECE-104", "faculty@123", "ESP32-SENTINEL-FAC04"),
        ]

        for emp_id, pwd, expected_device in faculty_bindings:
            resp = self.client.post("/api/auth/login-pass", json={
                "identifier": emp_id,
                "password": pwd
            })
            self.assertEqual(resp.status_code, 200)
            data = resp.get_json()
            self.assertEqual(data["status"], "REQUIRE_HARDWARE_TOKEN")
            self.assertEqual(data["role"], "faculty")
            self.assertEqual(data["device_id"], expected_device)

    def test_04_token_mismatch_rejection(self):
        """Verify that faculty attempting to use an unassigned or foreign token is blocked (403)."""
        # Step 1: Login password for FAC-ECE-101 (Assigned to FAC01)
        resp = self.client.post("/api/auth/login-pass", json={
            "identifier": "FAC-ECE-101",
            "password": "faculty@123"
        })
        data = resp.get_json()
        user_id = data["user_id"]

        # Step 2: Request Challenge Nonce
        c_resp = self.client.get(f"/api/auth/challenge?user_id={user_id}")
        nonce = c_resp.get_json()["nonce"]

        # Step 3: Present token FAC02 instead of FAC01
        v_resp = self.client.post("/api/auth/verify-token", json={
            "user_id": user_id,
            "nonce": nonce,
            "signature": "DEADBEEFCAFE0000000000000000000000000000000000000000000000000000",
            "device_id": "ESP32-SENTINEL-FAC02"
        })
        self.assertEqual(v_resp.status_code, 403)
        v_data = v_resp.get_json()
        self.assertIn("Hardware Token Mismatch", v_data["error"])

    def test_05_cryptographic_hmac_verification_and_replay_prevention(self):
        """Verify successful HMAC-SHA256 signature verification and replay prevention."""
        # 1. Login password for FAC-ECE-101
        resp = self.client.post("/api/auth/login-pass", json={
            "identifier": "FAC-ECE-101",
            "password": "faculty@123"
        })
        data = resp.get_json()
        user_id = data["user_id"]
        device_id = data["device_id"]  # ESP32-SENTINEL-FAC01

        # 2. Challenge
        c_resp = self.client.get(f"/api/auth/challenge?user_id={user_id}")
        nonce = c_resp.get_json()["nonce"]

        # 3. Compute genuine HMAC-SHA256 using golden key
        golden_key_hex = FACULTY_GOLDEN_KEYS[device_id]
        genuine_sig = hmac.new(
            bytes.fromhex(golden_key_hex),
            nonce.encode("utf-8"),
            hashlib.sha256
        ).hexdigest().upper()

        # 4. Verify Token
        v_resp = self.client.post("/api/auth/verify-token", json={
            "user_id": user_id,
            "nonce": nonce,
            "signature": genuine_sig,
            "device_id": device_id
        })
        self.assertEqual(v_resp.status_code, 200)
        v_data = v_resp.get_json()
        self.assertEqual(v_data["status"], "SUCCESS")
        self.assertEqual(v_data["role"], "faculty")
        self.assertIn("session_token", v_data)

        # 5. REPLAY ATTACK TEST: Submitting the same nonce must fail immediately
        replay_resp = self.client.post("/api/auth/verify-token", json={
            "user_id": user_id,
            "nonce": nonce,
            "signature": genuine_sig,
            "device_id": device_id
        })
        self.assertEqual(replay_resp.status_code, 403)
        self.assertIn("Replay attack detected", replay_resp.get_json()["error"])

    def test_06_detect_token_plug_and_play(self):
        """Verify plug-and-play token discovery endpoint."""
        # Known faculty token
        resp = self.client.post("/api/auth/detect-token", json={"device_id": "ESP32-SENTINEL-FAC01"})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "REGISTERED")
        self.assertEqual(data["user"]["roll_or_emp_id"], "FAC-ECE-101")
        self.assertIn("Dr. K. Ramesh", data["user"]["name"])

        # Unknown token
        unknown_resp = self.client.post("/api/auth/detect-token", json={"device_id": "ESP32-UNKNOWN-999"})
        self.assertEqual(unknown_resp.status_code, 200)
        self.assertEqual(unknown_resp.get_json()["status"], "UNKNOWN_DEVICE")

    def test_07_faculty_attendance_signing_with_canonical_digest(self):
        """Verify faculty submits attendance with canonical SHA-256 digest and token signature."""
        # Fetch ECE IV-A roster
        roster_resp = self.client.get("/api/faculty/roster?branch=ECE&year=IV&section=A")
        self.assertEqual(roster_resp.status_code, 200)
        students = roster_resp.get_json()["students"]
        self.assertGreaterEqual(len(students), 5)

        # Mark first 8 present
        records = [{"student_id": s["id"], "status": "PRESENT" if idx < 8 else "ABSENT"} 
                   for idx, s in enumerate(students)]
        present_rolls = sorted([s["roll_no"] for idx, s in enumerate(students) if idx < 8])
        canonical_str = ",".join(present_rolls)
        attendance_digest = hashlib.sha256(canonical_str.encode("utf-8")).hexdigest().upper()

        # Sign digest with Dr. K. Ramesh's token key (FAC01)
        golden_key = bytes.fromhex(FACULTY_GOLDEN_KEYS["ESP32-SENTINEL-FAC01"])
        hw_sig = hmac.new(golden_key, attendance_digest.encode("utf-8"), hashlib.sha256).hexdigest().upper()

        # Submit attendance
        sub_resp = self.client.post("/api/faculty/submit-attendance", json={
            "faculty_id": 2, # Dr. K. Ramesh
            "branch": "ECE",
            "year": "IV",
            "section": "A",
            "subject": "VLSI Design",
            "period": 3,
            "session_date": "2026-09-19",
            "records": records,
            "attendance_digest": attendance_digest,
            "hardware_signature": hw_sig
        })
        self.assertEqual(sub_resp.status_code, 200)
        self.assertEqual(sub_resp.get_json()["status"], "SUCCESS")

        # Verify history reflects the signed session
        hist_resp = self.client.get("/api/faculty/history?faculty_id=2")
        self.assertEqual(hist_resp.status_code, 200)
        sessions = hist_resp.get_json().get("sessions", [])
        self.assertGreater(len(sessions), 0)
        latest = sessions[0]
        self.assertEqual(latest["subject"], "VLSI Design")
        self.assertEqual(latest["attendance_digest"], attendance_digest)
        self.assertEqual(latest["hardware_signature"], hw_sig)

    def test_08_public_hacker_challenge_api(self):
        """Verify the Global Public Hacker Challenge API endpoints."""
        # 1. Telemetry stats
        stats_resp = self.client.get("/api/challenge/public-stats")
        self.assertEqual(stats_resp.status_code, 200)
        s_data = stats_resp.get_json()
        self.assertEqual(s_data["status"], "ONLINE")
        self.assertEqual(s_data["cryptographic_parameters"]["entropy_pool_bits"], 2048)

        # 2. Public Nonce Generation
        nonce_resp = self.client.get("/api/challenge/generate-public-nonce?device_id=ESP32-SENTINEL-FAC01")
        self.assertEqual(nonce_resp.status_code, 200)
        nonce = nonce_resp.get_json()["nonce"]
        self.assertEqual(len(nonce), 64)

        # 3. Forgery Attempt with invalid signature -> Must be rejected (403)
        fake_sig = "DEADBEEF" * 8
        atk_resp = self.client.post("/api/challenge/attempt-forgery", json={
            "device_id": "ESP32-SENTINEL-FAC01",
            "nonce": nonce,
            "signature": fake_sig
        })
        self.assertEqual(atk_resp.status_code, 403)
        atk_data = atk_resp.get_json()
        self.assertEqual(atk_data["result"], "FORGERY_REJECTED")
        self.assertIn("bitwise_hamming_error", atk_data["analysis"])

        # 4. Genuine signature -> Accepted (200)
        golden_key = bytes.fromhex(FACULTY_GOLDEN_KEYS["ESP32-SENTINEL-FAC01"])
        real_sig = hmac.new(golden_key, nonce.encode("utf-8"), hashlib.sha256).hexdigest().upper()
        gen_resp = self.client.post("/api/challenge/attempt-forgery", json={
            "device_id": "ESP32-SENTINEL-FAC01",
            "nonce": nonce,
            "signature": real_sig
        })
        self.assertEqual(gen_resp.status_code, 200)
        self.assertEqual(gen_resp.get_json()["result"], "CRACKED_IMPOSSIBLE")

    def test_09_option_b_asymmetric_ecdsa_attestation(self):
        """Verify Option B Asymmetric ECDSA: Keypair generation, signing, and server-side public key verification."""
        from cryptography.hazmat.primitives.asymmetric import ec, utils
        from cryptography.hazmat.primitives import hashes

        # 1. Simulate hardware PUF deriving private scalar d
        puf_secret_bytes = bytes.fromhex("7F609B5A3045C6E2A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4")
        priv_key = ec.derive_private_key(int.from_bytes(puf_secret_bytes, "big"), ec.SECP256R1())
        pub_nums = priv_key.public_key().public_numbers()
        pub_hex = f"04{pub_nums.x:064X}{pub_nums.y:064X}"

        # 2. Enroll device with Option B Public Key in database
        conn = get_db_connection()
        conn.execute("""
            UPDATE devices 
            SET public_verifier = ?, mac_address = 'B0:A7:32:1A:4C:80'
            WHERE device_id = 'ESP32-SENTINEL-FAC01'
        """, (f"ECDSA:{pub_hex}",))
        conn.commit()
        conn.close()

        # 3. Faculty login step 1
        resp = self.client.post("/api/auth/login-pass", json={
            "identifier": "FAC-ECE-101",
            "password": "faculty@123"
        })
        user_id = resp.get_json()["user_id"]

        # 4. Request challenge nonce
        c_resp = self.client.get(f"/api/auth/challenge?user_id={user_id}")
        nonce = c_resp.get_json()["nonce"]

        # 5. Compute ECDSA signature (r, s) using PUF private scalar d
        nonce_hash = hashlib.sha256(nonce.encode("utf-8")).digest()
        der_sig = priv_key.sign(nonce_hash, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        r, s = utils.decode_dss_signature(der_sig)
        raw_ecdsa_sig = f"{r:064X}{s:064X}"

        # 6. Verify with server using Public Key (Server NEVER holds private key d)
        v_resp = self.client.post("/api/auth/verify-token", json={
            "user_id": user_id,
            "nonce": nonce,
            "signature": raw_ecdsa_sig,
            "device_id": "ESP32-SENTINEL-FAC01",
            "mac_address": "B0:A7:32:1A:4C:80"
        })
        self.assertEqual(v_resp.status_code, 200)
        self.assertEqual(v_resp.get_json()["status"], "SUCCESS")

        # 7. Forged signature must be rejected (403)
        fake_ecdsa_sig = "F" * 128
        c_resp2 = self.client.get(f"/api/auth/challenge?user_id={user_id}")
        nonce2 = c_resp2.get_json()["nonce"]
        bad_resp = self.client.post("/api/auth/verify-token", json={
            "user_id": user_id,
            "nonce": nonce2,
            "signature": fake_ecdsa_sig,
            "device_id": "ESP32-SENTINEL-FAC01"
        })
        self.assertEqual(bad_resp.status_code, 403)

    def test_10_mac_address_hardware_binding(self):
        """Verify plug-and-play discovery and rejection of spoofed MAC addresses."""
        # Test detection by MAC
        resp = self.client.post("/api/auth/detect-token", json={"mac_address": "B0:A7:32:1A:4C:80"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["status"], "REGISTERED")
        self.assertEqual(resp.get_json()["user"]["roll_or_emp_id"], "FAC-ECE-101")

        # MAC mismatch rejection on verification
        resp_login = self.client.post("/api/auth/login-pass", json={
            "identifier": "FAC-ECE-101",
            "password": "faculty@123"
        })
        user_id = resp_login.get_json()["user_id"]
        c_resp = self.client.get(f"/api/auth/challenge?user_id={user_id}")
        nonce = c_resp.get_json()["nonce"]

        mismatch_resp = self.client.post("/api/auth/verify-token", json={
            "user_id": user_id,
            "nonce": nonce,
            "signature": "DEADBEEF" * 8,
            "device_id": "ESP32-SENTINEL-FAC01",
            "mac_address": "FF:FF:FF:FF:FF:FF"  # Foreign MAC
        })
        self.assertEqual(mismatch_resp.status_code, 403)
        self.assertIn("Hardware MAC Address Mismatch", mismatch_resp.get_json()["error"])


if __name__ == "__main__":
    unittest.main()
