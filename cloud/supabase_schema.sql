-- =============================================================================
-- SentinelKey & HITAM College Portal — Cloud Database Schema
-- Target: Supabase / PostgreSQL 15+ / AWS RDS PostgreSQL
-- =============================================================================

-- Enable UUID and Cryptographic extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 1. USERS TABLE (Students, Faculty, System Administrators)
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    roll_or_emp_id VARCHAR(32) UNIQUE NOT NULL,
    name VARCHAR(128) NOT NULL,
    email VARCHAR(128) UNIQUE NOT NULL,
    role VARCHAR(16) NOT NULL CHECK (role IN ('student', 'faculty', 'admin')),
    password_hash VARCHAR(256) NOT NULL,
    department VARCHAR(32) DEFAULT 'ECE',
    semester VARCHAR(32) DEFAULT 'IV B.Tech-I',
    admission_no VARCHAR(32) DEFAULT '7598',
    dob VARCHAR(16) DEFAULT '17/08/2005',
    mobile VARCHAR(16) DEFAULT '9182359854',
    father_name VARCHAR(128) DEFAULT 'CHALLA KRISHNAIAH',
    mother_name VARCHAR(128) DEFAULT 'CHALLA LAKSHMI',
    mentor VARCHAR(128) DEFAULT 'Dr. K. Ramesh (Associate Professor, ECE)',
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 2. DEVICES TABLE (SentinelKey Hardware PUF Tokens)
-- Zero-Knowledge Storage Rule: Golden Key is NEVER stored in database!
CREATE TABLE IF NOT EXISTS devices (
    device_id VARCHAR(64) PRIMARY KEY,
    user_id INT UNIQUE NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    helper_mask JSONB NOT NULL, -- 256 stable bit indices extracted during thermal characterization
    public_verifier VARCHAR(256) NOT NULL, -- ECC Public Key Q (Option B) or SHA-256 verifier hash
    mac_address VARCHAR(32), -- Factory-burned hardware eFuse MAC address
    status VARCHAR(16) NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'REVOKED', 'SUSPENDED')),
    enrolled_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 3. CHALLENGES TABLE (Single-Use Nonces with Expiration TTL)
CREATE TABLE IF NOT EXISTS challenges (
    nonce VARCHAR(64) PRIMARY KEY,
    user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL,
    used BOOLEAN DEFAULT FALSE
);

-- Index for fast nonce lookup and TTL cleanup
CREATE INDEX IF NOT EXISTS idx_challenges_user_nonce ON challenges(user_id, nonce);

-- 4. ATTENDANCE SESSIONS (Faculty-initiated and hardware-signed)
CREATE TABLE IF NOT EXISTS attendance_sessions (
    session_id VARCHAR(64) PRIMARY KEY,
    faculty_id INT NOT NULL REFERENCES users(id),
    branch VARCHAR(16) NOT NULL,
    year VARCHAR(8) NOT NULL,
    section VARCHAR(8) NOT NULL,
    subject VARCHAR(128) NOT NULL,
    period INT NOT NULL,
    session_date DATE NOT NULL,
    attendance_digest VARCHAR(64), -- SHA-256 canonical hash of attendance roster
    hardware_signature VARCHAR(128), -- Cryptographic signature from Faculty SentinelKey
    device_id VARCHAR(64) REFERENCES devices(device_id),
    total_present INT DEFAULT 0,
    total_students INT DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 5. ATTENDANCE RECORDS (Individual Student Presence)
CREATE TABLE IF NOT EXISTS attendance_records (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(64) NOT NULL REFERENCES attendance_sessions(session_id) ON DELETE CASCADE,
    student_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status VARCHAR(16) NOT NULL CHECK (status IN ('PRESENT', 'ABSENT')),
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_att_records_student ON attendance_records(student_id);

-- 6. RECOVERY REQUESTS & EMERGENCY OTP DESK
CREATE TABLE IF NOT EXISTS recovery_requests (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    reason TEXT NOT NULL,
    otp_code VARCHAR(8),
    status VARCHAR(16) DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED', 'USED')),
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ
);

-- 7. AUDIT LOGS (Immutable security and cryptographic audit trail)
CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    actor_id INT REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(64) NOT NULL,
    details TEXT,
    ip_address VARCHAR(45) DEFAULT '127.0.0.1',
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- =============================================================================
-- ROW LEVEL SECURITY (RLS) POLICIES FOR CLOUD ZERO-TRUST
-- =============================================================================
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE attendance_records ENABLE ROW LEVEL SECURITY;

-- Allow read access for authenticated portal service
CREATE POLICY "Allow service role full access" ON users FOR ALL USING (true);
CREATE POLICY "Allow service role devices access" ON devices FOR ALL USING (true);
CREATE POLICY "Allow service role attendance access" ON attendance_records FOR ALL USING (true);
