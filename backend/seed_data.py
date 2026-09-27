"""
Seed Data Generator for HITAM College Portal & SentinelKey Database
Configures:
  - Admin (Exam / Office Administrator)
  - 4 Distinct Faculty Members (Strictly bound to SentinelKey PUF USB Tokens FAC01 - FAC04)
  - Students (Challa Srinath & classmates - Standard Password Login, NO PUF required)
  - Historical classroom attendance sessions with cryptographic signatures
"""

import os
import json
import hashlib
from werkzeug.security import generate_password_hash
from database import get_db_connection, init_db


def seed_database():
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()

    # Clear existing data to allow idempotent seeding
    cursor.execute("DELETE FROM attendance_records")
    cursor.execute("DELETE FROM attendance_sessions")
    cursor.execute("DELETE FROM challenges")
    cursor.execute("DELETE FROM devices")
    cursor.execute("DELETE FROM recovery_requests")
    cursor.execute("DELETE FROM audit_logs")
    cursor.execute("DELETE FROM users")
    try:
        cursor.execute("DELETE FROM sqlite_sequence")
    except Exception:
        pass

    # Sample stable helper mask (256 indices across 2048-bit SRAM pool)
    sample_helper_mask = [
        0, 7, 13, 19, 26, 31, 38, 44, 51, 57, 63, 70, 76, 82, 89, 95,
        101, 108, 114, 120, 127, 133, 139, 146, 152, 158, 165, 171, 177, 184, 190, 196,
        203, 209, 215, 222, 228, 234, 241, 247, 253, 260, 266, 272, 279, 285, 291, 298,
        304, 310, 317, 323, 329, 336, 342, 348, 355, 361, 367, 374, 380, 386, 393, 399
    ]
    while len(sample_helper_mask) < 256:
        sample_helper_mask.append((len(sample_helper_mask) * 7) % 2048)

    # 1. System Administrator
    cursor.execute("""
        INSERT INTO users (roll_or_emp_id, name, email, role, password_hash, department, semester)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        "ADMIN-001",
        "Dr. C. R. Rao (Principal & Exam Branch)",
        "admin@hitam.org",
        "admin",
        generate_password_hash("admin@123", method="pbkdf2:sha256"),
        "Administration",
        "Staff"
    ))
    admin_id = cursor.lastrowid

    # 1.1 System Administrator Physical SentinelKey Hardware Token
    cursor.execute("""
        INSERT INTO devices (device_id, user_id, helper_mask, public_verifier, mac_address, status)
        VALUES (?, ?, ?, ?, ?, 'ACTIVE')
    """, (
        "ESP32-SENTINEL-ADMIN01",
        admin_id,
        json.dumps(sample_helper_mask),
        "ECDSA:04E650ECD5D1F21BC0241E7591C321C2829BA40ADF383C3D7D4AF71609E1B0A5FC5B22CDB7EB99249C2677A7D65087A531996CE1889215F98DF2F933B056626508",
        "FC:E8:C0:E1:3D:08"
    ))

    # 2. Four (4) Distinct Faculty Members with SentinelKey PUF Tokens
    faculty_profiles = [
        {
            "emp_id": "FAC-ECE-101",
            "name": "Dr. K. Ramesh",
            "title": "Professor & HOD (ECE)",
            "email": "kramesh@hitam.org",
            "subject": "Hardware Security & Cryptography",
            "device_id": "ESP32-SENTINEL-FAC01",
            "golden_key": "a4f839c0e2b1754890d937c8e9fa014389025cb48e910243bfae840291437801",
        },
        {
            "emp_id": "FAC-ECE-102",
            "name": "Dr. P. Sunitha",
            "title": "Associate Professor (ECE)",
            "email": "psunitha@hitam.org",
            "subject": "Embedded Systems & IoT",
            "device_id": "ESP32-SENTINEL-FAC02",
            "golden_key": "b5f940d1f3c2865901e048d9fa0b125490136dc59f021354c0bf951302548902",
        },
        {
            "emp_id": "FAC-ECE-103",
            "name": "Dr. V. Rajesh",
            "title": "Associate Professor (ECE)",
            "email": "vrajesh@hitam.org",
            "subject": "VLSI Design & Testing",
            "device_id": "ESP32-SENTINEL-FAC03",
            "golden_key": "c60a51e204d3976a12f159e00b1c236501247ed6a0132465d1c0a62413659a03",
        },
        {
            "emp_id": "FAC-ECE-104",
            "name": "Dr. M. Anitha",
            "title": "Assistant Professor (ECE)",
            "email": "manitha@hitam.org",
            "subject": "Wireless & Cellular Comms",
            "device_id": "ESP32-SENTINEL-FAC04",
            "golden_key": "d71b62f315e4a87b23026af11c2d347612358fe7b1243576e2d1b7352476ab04",
        }
    ]

    faculty_ids = []
    for fac in faculty_profiles:
        cursor.execute("""
            INSERT INTO users (roll_or_emp_id, name, email, role, password_hash, department, semester)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            fac["emp_id"],
            f"{fac['name']} ({fac['title']})",
            fac["email"],
            "faculty",
            generate_password_hash("faculty@123", method="pbkdf2:sha256"),
            "ECE",
            "Staff"
        ))
        f_id = cursor.lastrowid
        faculty_ids.append((f_id, fac))

        # Derive verifier: use physical ECDSA P-256 verifier for FAC01
        if fac["device_id"] == "ESP32-SENTINEL-FAC01":
            verifier = "ECDSA:04E650ECD5D1F21BC0241E7591C321C2829BA40ADF383C3D7D4AF71609E1B0A5FC5B22CDB7EB99249C2677A7D65087A531996CE1889215F98DF2F933B056626508"
            mac = "FC:E8:C0:E1:3D:08"
        else:
            verifier = hashlib.sha256(bytes.fromhex(fac["golden_key"])).hexdigest()
            mac = None

        # Strictly bind 1-to-1: Faculty Account <-> SentinelKey USB Token
        cursor.execute("""
            INSERT INTO devices (device_id, user_id, helper_mask, public_verifier, mac_address, status)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            fac["device_id"],
            f_id,
            json.dumps(sample_helper_mask),
            verifier,
            mac,
            "ACTIVE"
        ))

    # 3. Student Team & Classmates (NO PUF TOKENS - Standard secure credentials)
    students = [
        ("23E51A0417", "CHALLA SRINATH", "23E51A0417@hitam.org"),
        ("23E51A0404", "A. VAISHNAVI", "23E51A0404@hitam.org"),
        ("23E51A0413", "B. SASIKALA", "23E51A0413@hitam.org"),
        ("23E51A0462", "V. MANASA", "23E51A0462@hitam.org"),
        ("23E51A0401", "A. SAI KIRAN", "23E51A0401@hitam.org"),
        ("23E51A0405", "B. NAVEEN KUMAR", "23E51A0405@hitam.org"),
        ("23E51A0410", "D. ROHITH", "23E51A0410@hitam.org"),
        ("23E51A0422", "G. HARSHAVARDHAN", "23E51A0422@hitam.org"),
        ("23E51A0435", "K. SRAVANI", "23E51A0435@hitam.org"),
        ("23E51A0449", "M. TEJASWINI", "23E51A0449@hitam.org"),
    ]

    student_user_ids = []
    for roll, name, email in students:
        pwd = "Sri@7254" if roll == "23E51A0417" else "hitam@123"
        cursor.execute("""
            INSERT INTO users (roll_or_emp_id, name, email, role, password_hash, department, semester)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            roll,
            name,
            email,
            "student",
            generate_password_hash(pwd, method="pbkdf2:sha256"),
            "ECE",
            "IV B.Tech-I"
        ))
        u_id = cursor.lastrowid
        student_user_ids.append((u_id, roll, name))
        # Note: No row inserted in devices table for students!

    # 4. Historical Attendance Sessions across all 4 Faculty Members
    sample_sessions = [
        ("SESS-2026-0901-P1", faculty_ids[0][0], "Hardware Security & Cryptography", 1, "2026-09-01", faculty_ids[0][1]["device_id"]),
        ("SESS-2026-0902-P2", faculty_ids[1][0], "Embedded Systems & IoT", 2, "2026-09-02", faculty_ids[1][1]["device_id"]),
        ("SESS-2026-0905-P3", faculty_ids[2][0], "VLSI Design & Testing", 3, "2026-09-05", faculty_ids[2][1]["device_id"]),
        ("SESS-2026-0908-P1", faculty_ids[3][0], "Wireless & Cellular Comms", 1, "2026-09-08", faculty_ids[3][1]["device_id"]),
        ("SESS-2026-0912-P4", faculty_ids[0][0], "Major Project Review & Security Audit", 4, "2026-09-12", faculty_ids[0][1]["device_id"]),
    ]

    for sess_id, fac_id, subj, period, s_date, dev_id in sample_sessions:
        # Construct realistic attendance digest
        present_rolls = [r for _, r, _ in student_user_ids if r != "23E51A0410"]
        digest_input = f"{sess_id}:{fac_id}:{subj}:{s_date}:{period}:{','.join(present_rolls)}"
        att_digest = hashlib.sha256(digest_input.encode()).hexdigest()
        hw_sig = "SIG-PUF-" + hashlib.sha256((att_digest + dev_id).encode()).hexdigest()

        cursor.execute("""
            INSERT INTO attendance_sessions (
                session_id, faculty_id, branch, year, section, subject, period,
                session_date, attendance_digest, hardware_signature, device_id, total_present, total_students
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            sess_id,
            fac_id,
            "ECE",
            "IV",
            "A",
            subj,
            period,
            s_date,
            att_digest,
            hw_sig,
            dev_id,
            len(present_rolls),
            len(student_user_ids)
        ))

        for u_id, roll, _ in student_user_ids:
            status = "PRESENT"
            if roll == "23E51A0410" and sess_id in ["SESS-2026-0902-P2", "SESS-2026-0905-P3"]:
                status = "ABSENT"
            elif roll == "23E51A0405" and sess_id == "SESS-2026-0908-P1":
                status = "ABSENT"

            cursor.execute("""
                INSERT INTO attendance_records (session_id, student_id, status)
                VALUES (?, ?, ?)
            """, (sess_id, u_id, status))

    # 5. Audit logs for security monitor
    cursor.execute("""
        INSERT INTO audit_logs (actor_id, action, details, ip_address)
        VALUES (?, ?, ?, ?)
    """, (
        faculty_ids[0][0],
        "HARDWARE_SIGNED_ATTENDANCE",
        "Dr. K. Ramesh verified attendance for IV B.Tech ECE-A using token ESP32-SENTINEL-FAC01",
        "192.168.1.45"
    ))

    conn.commit()
    conn.close()

    print("[SUCCESS] SentinelKey Database seeded successfully!")
    print("==================================================================")
    print("ADMIN LOGIN:    admin@hitam.org / admin@123")
    print("STUDENT LOGIN:  23E51A0417 / Sri@7254 (No USB required)")
    print("                23E51A0404 / hitam@123 (No USB required)")
    print("FACULTY LOGINS (Strict PUF USB Required):")
    for _, fac in faculty_ids:
        print(f"  - {fac['name']}: {fac['emp_id']} or {fac['email']} / faculty@123")
        print(f"    Token: {fac['device_id']} (Golden Key: {fac['golden_key'][:16]}...)")
    print("==================================================================")


if __name__ == "__main__":
    seed_database()

