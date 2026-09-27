-- =============================================================================
-- SentinelKey & HITAM College Portal — Cloud Database Schema (HARDENED)
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
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 2. DEVICES TABLE (SentinelKey Hardware PUF Tokens)
-- Zero-Knowledge Storage Rule: Golden Key is NEVER stored in database!
-- Only the ECDSA Public Key Q is stored for signature verification.
CREATE TABLE IF NOT EXISTS devices (
    device_id VARCHAR(64) PRIMARY KEY,
    user_id INT UNIQUE NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    helper_mask JSONB NOT NULL,       -- 256 stable bit indices from thermal characterization
    public_verifier VARCHAR(256) NOT NULL, -- Uncompressed ECDSA Public Key Q (130 hex chars)
    mac_address VARCHAR(32),          -- Factory-burned hardware eFuse MAC address
    status VARCHAR(16) NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'REVOKED', 'SUSPENDED')),
    enrolled_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 3. CHALLENGES TABLE (Single-Use Nonces with Action Type Binding)
-- SECURITY: action_type prevents cross-purpose nonce reuse
-- (a nonce issued for 'login' cannot be replayed for 'attendance')
CREATE TABLE IF NOT EXISTS challenges (
    nonce VARCHAR(64) PRIMARY KEY,
    user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    action_type VARCHAR(32) NOT NULL DEFAULT 'login' CHECK (action_type IN ('login', 'attendance', 'admin_mutation')),
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL,
    used BOOLEAN DEFAULT FALSE
);

-- Composite index for fast nonce lookup with user binding
CREATE INDEX IF NOT EXISTS idx_challenges_user_nonce ON challenges(user_id, nonce);
-- Index for expired nonce cleanup
CREATE INDEX IF NOT EXISTS idx_challenges_expires ON challenges(expires_at) WHERE used = FALSE;

-- 4. ATTENDANCE SESSIONS (Faculty-initiated and ECDSA hardware-signed)
CREATE TABLE IF NOT EXISTS attendance_sessions (
    session_id VARCHAR(64) PRIMARY KEY,
    faculty_id INT NOT NULL REFERENCES users(id),
    branch VARCHAR(16) NOT NULL,
    year VARCHAR(8) NOT NULL,
    section VARCHAR(8) NOT NULL,
    subject VARCHAR(128) NOT NULL,
    period INT NOT NULL,
    session_date DATE NOT NULL,
    attendance_digest VARCHAR(64),     -- SHA-256 canonical hash of attendance roster
    hardware_signature VARCHAR(256),   -- ECDSA signature from Faculty SentinelKey
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
CREATE INDEX IF NOT EXISTS idx_att_records_session ON attendance_records(session_id);

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

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp DESC);

-- =============================================================================
-- ROW LEVEL SECURITY (RLS) POLICIES — RESTRICTIVE
-- =============================================================================
-- Enable RLS on sensitive tables
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE attendance_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE recovery_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;

-- Drop any existing permissive policies
DROP POLICY IF EXISTS "Allow service role full access" ON users;
DROP POLICY IF EXISTS "Allow service role devices access" ON devices;
DROP POLICY IF EXISTS "Allow service role attendance access" ON attendance_records;

-- Service role (backend) has full access — enforced by Supabase service_role key
-- These policies restrict direct Supabase client access (anon key) while allowing
-- the backend (which connects via DATABASE_URL with service role) full control.
CREATE POLICY "service_role_users" ON users FOR ALL
    USING (current_setting('request.jwt.claim.role', true) = 'service_role' OR current_user = 'postgres');

CREATE POLICY "service_role_devices" ON devices FOR ALL
    USING (current_setting('request.jwt.claim.role', true) = 'service_role' OR current_user = 'postgres');

CREATE POLICY "service_role_challenges" ON challenges FOR ALL
    USING (current_setting('request.jwt.claim.role', true) = 'service_role' OR current_user = 'postgres');

CREATE POLICY "service_role_attendance" ON attendance_records FOR ALL
    USING (current_setting('request.jwt.claim.role', true) = 'service_role' OR current_user = 'postgres');

CREATE POLICY "service_role_recovery" ON recovery_requests FOR ALL
    USING (current_setting('request.jwt.claim.role', true) = 'service_role' OR current_user = 'postgres');

CREATE POLICY "service_role_audit" ON audit_logs FOR ALL
    USING (current_setting('request.jwt.claim.role', true) = 'service_role' OR current_user = 'postgres');

-- =============================================================================
-- SCHEMA MIGRATION: Add action_type to challenges if missing
-- =============================================================================
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'challenges' AND column_name = 'action_type'
    ) THEN
        ALTER TABLE challenges ADD COLUMN action_type VARCHAR(32) NOT NULL DEFAULT 'login';
        ALTER TABLE challenges ADD CONSTRAINT chk_action_type CHECK (action_type IN ('login', 'attendance', 'admin_mutation'));
    END IF;
END $$;

-- =============================================================================
-- AUTOMATIC NONCE CLEANUP (Expired + Used nonces older than 1 hour)
-- Run this as a scheduled Supabase Edge Function or pg_cron job
-- =============================================================================
-- DELETE FROM challenges WHERE used = TRUE OR expires_at < NOW() - INTERVAL '1 hour';
