#!/usr/bin/env python3
"""
Cryptographic Integrity & Anti-Replay Test Suite
SentinelKey Major Project - HITAM Department of ECE
"""

import unittest
import hmac
import hashlib
import secrets
import time
import os
import sys

# Ensure backend module is discoverable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../backend")))
from database import get_db_connection, init_db
from seed_data import seed_database
from app import app


class TestSentinelKeyCrypto(unittest.TestCase):

    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True
        seed_database()
        conn = get_db_connection()
        user = conn.execute("SELECT id FROM users WHERE roll_or_emp_id = 'FAC-ECE-101'").fetchone()
        self.user_id = user["id"]
        conn.close()

    def test_nonce_generation_entropy(self):
        """Verify server nonces are 64 hex characters with high entropy."""
        resp = self.app.get(f"/api/auth/challenge?user_id={self.user_id}")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        nonce = data["nonce"]
        self.assertEqual(len(nonce), 64)
        self.assertTrue(all(c in "0123456789ABCDEF" for c in nonce))

    def test_valid_signature_acceptance(self):
        """Verify valid HMAC signature generated with Golden Key is accepted."""
        # 1. Challenge
        resp = self.app.get(f"/api/auth/challenge?user_id={self.user_id}")
        nonce = resp.get_json()["nonce"]

        # 2. Golden Key for FAC01
        golden_key = bytes.fromhex("a4f839c0e2b1754890d937c8e9fa014389025cb48e910243bfae840291437801")
        expected_sig = hmac.new(golden_key, nonce.encode("utf-8"), hashlib.sha256).hexdigest().upper()

        # 3. Verify
        verify_resp = self.app.post("/api/auth/verify-token", json={
            "user_id": self.user_id,
            "nonce": nonce,
            "signature": expected_sig,
            "device_id": "ESP32-SENTINEL-FAC01"
        })
        self.assertEqual(verify_resp.status_code, 200)
        v_data = verify_resp.get_json()
        self.assertEqual(v_data["status"], "SUCCESS")
        self.assertEqual(v_data["role"], "faculty")

    def test_replay_attack_prevention(self):
        """Verify that reusing the same nonce a second time is rejected."""
        # 1. Challenge
        resp = self.app.get(f"/api/auth/challenge?user_id={self.user_id}")
        nonce = resp.get_json()["nonce"]

        golden_key = bytes.fromhex("a4f839c0e2b1754890d937c8e9fa014389025cb48e910243bfae840291437801")
        sig = hmac.new(golden_key, nonce.encode("utf-8"), hashlib.sha256).hexdigest().upper()

        # First use -> Success
        r1 = self.app.post("/api/auth/verify-token", json={
            "user_id": self.user_id,
            "nonce": nonce,
            "signature": sig,
            "device_id": "ESP32-SENTINEL-FAC01"
        })
        self.assertEqual(r1.status_code, 200)

        # Replay attempt (second use) -> Must be blocked with 403
        r2 = self.app.post("/api/auth/verify-token", json={
            "user_id": self.user_id,
            "nonce": nonce,
            "signature": sig,
            "device_id": "ESP32-SENTINEL-FAC01"
        })
        self.assertEqual(r2.status_code, 403)
        self.assertIn("Replay attack detected", r2.get_json()["error"])


if __name__ == "__main__":
    unittest.main()
