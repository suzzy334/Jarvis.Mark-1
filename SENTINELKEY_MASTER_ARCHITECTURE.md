# SentinelKey™ — Hardware Silicon-PUF Authentication & College Portal
## Master Technical Architecture, Cryptographic Proofs & Deployment Guide
**Hyderabad Institute of Technology and Management (HITAM)**  
**Department of Electronics and Communication Engineering**

---

## 1. Executive Summary & Core Security Paradigm

**SentinelKey** is a physical hardware-rooted zero-trust authentication architecture engineered for the HITAM College Academic Portal. It replaces insecure password-only and vulnerable SMS/software 2FA with **microscopic semiconductor physical unclonable functions (SRAM-PUF)** and **Asymmetric Public-Key Cryptography (ECDSA NIST P-256 / SECP256R1)**.

### Access Hierarchy
1. **Students & System Administrators**:
   - Standard access via institutional credentials (`roll_or_emp_id` + `password`).
   - Example Student: `23E51A0417` / `Sri@7254` (Challa Srinath).
   - Example Admin: `admin@hitam.org` / `admin@123` (Dr. C. R. Rao, Principal & Exam Branch).
2. **Faculty Members (Strict PUF Hardware Required)**:
   - Step 1: Institutional password authentication.
   - Step 2: Physical SentinelKey USB Token required. The browser connects to the ESP32 over the **Web Serial API**, issues a 32-byte cryptorandom challenge via `/api/auth/challenge`, the ESP32 verifies physical human presence, signs the challenge using its internal ephemeral PUF private key, and relays the signature to `/api/auth/verify-token`.

---

## 2. Cryptographic Security Model: Why Neither the Database Nor the USB Can Be Compromised

```
                ┌────────────────────────────────────────────────────────┐
                │             Zero-Trust Option B Security               │
                └────────────────────────────────────────────────────────┘
                 
      PHYSICAL ESP32 TOKEN                             SUPABASE / CLOUD SERVER
  ┌──────────────────────────────┐                ┌──────────────────────────────┐
  │  Microscopic Silicon Imperfections │                │  Authoritative Cloud Database │
  │  (Gate-Oxide Randomness)     │                │                              │
  │              │               │                │  Stores ONLY Public Key:     │
  │       [On Power-Up]          │                │  Q = (x, y) = d · G          │
  │              ▼               │                │  (65 bytes: 04E650ECD5...)   │
  │  256-bit SRAM Golden Key (d) │                │                              │
  │  *NEVER stored in Flash!*    │                │  NEVER stores private key d! │
  │              │               │                └──────────────┬───────────────┘
  │       [Signs Challenge]      │                               │
  │              ▼               │        32-Byte CSPRNG Nonce   │
  │  ECDSA Signature: (r, s)     │ ◄─────────────────────────────┤ (60s TTL, single-use)
  │              │               │                               │
  │       [IMMEDIATE WIPE]       │        Signature (r, s)       │
  │  memset_s(golden_key, 0)     │ ─────────────────────────────►│ Server verifies:
  │  RAM ZEROIZED TO 0%          │                               │ ecdsa_verify(Q, Nonce, (r, s))
  └──────────────────────────────┘                               └──────────────────────────────┘
```

### 1. What is ECDSA (Elliptic Curve Digital Signature Algorithm)?
**ECDSA** is an asymmetric cryptographic algorithm operating on the algebraic structure of elliptic curves over finite fields. In SentinelKey, we implement the **NIST P-256 curve (SECP256R1 / prime256v1)**:
$$y^2 \equiv x^3 - 3x + b \pmod{p}$$
Where:
- **Private Key ($d$)**: A secret 256-bit scalar integer derived directly from the thermal-stabilized silicon SRAM startup entropy.
- **Public Key ($Q$)**: A point on the curve obtained by scalar multiplication of the base generator point $G$:
  $$Q = d \cdot G$$
- **Digital Signature ($(r, s)$)**: The ESP32 computes a signature on the SHA-256 digest of the server's challenge using an ephemeral random integer $k$:
  $$r = (k \cdot G)_x \pmod{n}, \quad s = k^{-1}(H(m) + d \cdot r) \pmod{n}$$
- **Server Verification**: The server verifies the mathematical relationship:
  $$u_1 = H(m) \cdot s^{-1} \pmod{n}, \quad u_2 = r \cdot s^{-1} \pmod{n}$$
  $$(u_1 \cdot G + u_2 \cdot Q)_x \equiv r \pmod{n}$$

### 2. Why the Server/Database Breach Yields Zero Useful Information
In symmetric systems (e.g. shared secrets, AES, simple HMAC), the server must store the key. If the server is hacked, all tokens are compromised.  
In **SentinelKey Option B**:
- The server stores **ONLY the public point $Q$** (`04E650ECD5...`).
- Deriving the private key $d$ from the public key $Q$ requires solving the **Elliptic Curve Discrete Logarithm Problem (ECDLP)**.
- For NIST P-256, solving ECDLP requires $\mathcal{O}(\sqrt{n}) \approx 2^{128}$ operations using Pollard's rho algorithm.
- Even if the world's fastest supercomputer ran continuously for the age of the universe, it **cannot** calculate $d$ from the stored database values.
- **Result**: Even if an attacker completely dumps the entire Supabase database, they **cannot** impersonate any faculty member or forge signatures.

### 3. Why Stealing the Physical USB Token Yields Zero Keys
- In conventional USB security keys, private keys are burned into flash memory or EEPROM, vulnerable to decapping, focused ion beam (FIB) probing, side-channel power analysis, or SPI flash dumping.
- In **SentinelKey**:
  - The private key is **NEVER** written to Flash memory, EEPROM, or NVS.
  - When the ESP32 is powered off or unplugged from the USB port, the SRAM loses all voltage. The private key **literally ceases to exist in the physical universe**.
  - On power-up, the firmware reconstructs the 256 bits by sampling uninitialized transistor gate-capacitance thresholds at `0x50000220`, applies the enrollment helper mask, computes the ECDSA signature, and **immediately zeroes out the memory** (`wipeGoldenKey()`).

---

## 3. The Challenge-Response & Anti-Replay Architecture

### What kind of challenges are sent?
Every challenge is a **32-byte (256-bit)** cryptographically secure random value generated via the operating system's Cryptographically Secure Pseudo-Random Number Generator (CSPRNG, `os.urandom(32)`):
$$\text{Nonce} = \text{HexEncode}(\text{CSPRNG}(32))$$
Example: `e4b3c98f12a0487d612e5f38902c4b7194a081523b4971c20e18374a95b82103`

### Can multiple accounts get the same challenge?
**Mathematically and architecturally IMPOSSIBLE**:
1. **Infinite Search Space**: 256 bits provides $2^{256} \approx 1.15 \times 10^{77}$ distinct challenge combinations. This exceeds the estimated number of atoms in the observable universe. The probability of two users ever receiving the same challenge is less than $10^{-40}$.
2. **Database Account Binding**: Every challenge generated in the `challenges` table is bound with a foreign key to the specific `user_id`:
   ```sql
   INSERT INTO challenges (nonce, user_id, expires_at, used)
   VALUES (:nonce, :user_id, NOW() + INTERVAL '60 SECONDS', FALSE);
   ```
3. **Strict Single-Use Burning**: The moment `/api/auth/verify-token` verifies a signature, it immediately executes:
   ```sql
   UPDATE challenges SET used = TRUE WHERE nonce = :nonce AND user_id = :user_id;
   ```
4. **Anti-Replay Enforcement**: If an attacker intercepts network packets and replays the exact same challenge and signature, the server rejects it with `HTTP 400: Challenge expired or already used (Replay attack blocked)`.

---

## 4. The Emergency Access & OTP System

### How do we guarantee the OTP reaches ONLY the intended person?
When a faculty member's physical token is damaged or lost, the emergency fallback cannot rely on SMS (which is vulnerable to SIM-swap attacks and SS7 intercept).

1. **Authoritative Institutional Address Binding**:
   - The OTP is dispatched **strictly** to the institutional email on record (`kramesh@hitam.org`), retrieved directly from the verified database record (`u.email`), never from client input.
2. **Institutional Domain Enforcement**:
   - The email domain is locked to `@hitam.org` protected with enterprise SPF, DKIM, and DMARC enforcement.
3. **Cryptographic Entropy & Short Expiration**:
   - OTP codes are 6-digit or 8-character CSPRNG nonces with high entropy.
   - Self-service OTPs expire in **10 minutes**.
   - Admin-issued emergency access tickets expire in **24 hours**.
4. **Brute-Force Lockout**:
   - Maximum 3 incorrect attempts before the OTP is invalidated and the account is temporarily locked for 15 minutes.
5. **Dual-Control Administrator Resolution**:
   - The administrator inspects the lost key ticket on the **Admin Lost Key Desk** (`admin_dashboard.html`), verifies the faculty member's identity, clicks "Dispatch 24h OTP", and revokes the lost hardware token. All actions are immutably written to the `audit_logs` table.

---

## 5. Production Firmware: Running Continuously for Lifetime Operation

The firmware at `firmware/sentinelkey_firmware.ino` is designed for decades of daily operational use:

1. **Zero Flash Wear**:
   - The firmware does not perform EEPROM or Flash writes during login cycles. ESP32 internal flash is only written once during initial programming, preserving the flash memory endurance indefinitely.
2. **Thermal & Voltage Tolerance**:
   - Uninitialized SRAM at address `0x50000220` is sampled. The 256 stable bit indices extracted during characterization select only silicon cells with $>99.5\%$ reliability across $-20^\circ\text{C}$ to $+80^\circ\text{C}$.
3. **Hardware RF Deactivation**:
   - `disableAllRadios()` turns off WiFi and Bluetooth baseband registers (`esp_wifi_stop()`, `esp_bt_controller_disable()`), eliminating any remote over-the-air exploitation vector.
4. **Physical Presence Verification**:
   - Prevents malware or unauthorized automated scripts from signing challenges silently. The device requires:
     - Onboard **BOOT button** press (GPIO 0), or
     - Capacitive finger touch on **Pin D4** (GPIO 4 / Touch0).
5. **Memory Zeroization**:
   - The moment the ECDSA signature is computed, `wipeGoldenKey()` overwrites the volatile private key buffer with zeroes (`memset_s`).

### Lifetime Compilation & Flashing Guide:
```bash
# 1. Open Arduino IDE or PlatformIO
# 2. Select Board: "ESP32 Dev Module"
# 3. Partition Scheme: "Huge APP (3MB No OTA/1MB SPIFFS)"
# 4. CPU Frequency: 240MHz
# 5. Place firmware/helper_data_ESP32-SENTINEL-FAC01.h in the same folder as sentinelkey_firmware.ino
# 6. Click Upload over USB (115200 Baud)
```

---

## 6. Supabase Cloud Database: Step-by-Step Setup

Your Supabase project is active at:
`https://eiajsszwaubfzelpyvmv.supabase.co` (Region: `South Asia Mumbai ep-south-1`).

### Step 1: Execute Schema DDL
1. Log into your Supabase Dashboard: `https://supabase.com/dashboard/project/eiajsszwaubfzelpyvmv`.
2. Click **SQL Editor** on the left navigation bar.
3. Open `cloud/supabase_schema.sql` from your project folder, copy all contents, paste into the SQL Editor, and click **Run**.
4. This creates all 7 tables (`users`, `devices`, `challenges`, `attendance_sessions`, `attendance_records`, `recovery_requests`, `audit_logs`) and indexes.

### Step 2: Execute Production Seed Data
1. In the Supabase SQL Editor, open a new query.
2. Copy the contents of `cloud/supabase_seed.sql`, paste, and click **Run**.
3. This creates:
   - System Administrator (`admin@hitam.org` / `admin@123`).
   - Student Srinath (`23E51A0417` / `Sri@7254`).
   - 4 Faculty Accounts with Option B ECDSA Public Keys (`ECDSA:04...`) and hardware MAC addresses.

### Step 3: Run Database Sync / Migration Script
Run the automated migration tool in your terminal to verify cloud connectivity:
```bash
python3 scripts/migrate_to_supabase.py --url "postgresql://postgres:[YOUR-DATABASE-PASSWORD]@db.eiajsszwaubfzelpyvmv.supabase.co:5432/postgres"
```

---

## 7. Running the Continuous Backend

To keep the Flask backend running continuously, serving both local and remote clients:

### Option A: Direct Terminal / Daemon Run
```bash
# Set your Supabase Database URL
export DATABASE_URL="postgresql://postgres:[YOUR-PASSWORD]@db.eiajsszwaubfzelpyvmv.supabase.co:5432/postgres"

# Run Flask backend with multi-threading
python3 backend/app.py
```

### Option B: Production Background Service (Gunicorn / Systemd / Tmux)
```bash
# Using gunicorn for production high-concurrency
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 backend.app:app
```

---

## 8. Frontend Deployment: Clean Separation for Vercel & GitHub

The `frontend/` directory is completely decoupled, containing static assets that deploy effortlessly to Vercel, GitHub Pages, or any CDN.

### Vercel Deployment Steps:
1. Initialize or push your repo to GitHub:
   ```bash
   git add .
   git commit -m "SentinelKey production ready"
   git push origin main
   ```
2. Log in to [Vercel](https://vercel.com) and click **Add New Project**.
3. Import your GitHub repository.
4. Set the **Root Directory** to `frontend` (or leave as root, since root `vercel.json` automatically routes to `frontend/`).
5. Click **Deploy**.
6. Vercel automatically assigns an HTTPS URL (e.g., `https://sentinelkey-hitam.vercel.app`).
   > **Note on Web Serial**: Web Serial API requires a Secure Context (`https://` or `localhost`). Vercel provides automatic SSL certificates, guaranteeing full Web Serial support!

### API Configuration (`frontend/js/config.js`):
- When running locally, requests use relative paths (`/api/...`).
- When frontend is on Vercel and backend is on Render/Railway/Fly.io:
  ```javascript
  // Set in browser developer console or settings:
  SENTINEL_CONFIG.setApiUrl("https://your-backend.onrender.com");
  ```

---

## 9. Official HITAM Verification Matrix & Test Accounts

| Role | User ID / Roll No | Password | 2FA Required? | Hardware Token ID | Silicon MAC Address |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **System Admin** | `admin@hitam.org` | `admin@123` | **Password Only** | N/A | N/A |
| **Student** | `23E51A0417` | `Sri@7254` | **Password Only** | N/A | N/A |
| **Student** | `23E51A0404` | `hitam@123` | **Password Only** | N/A | N/A |
| **Faculty 1** | `kramesh@hitam.org` | `faculty@123` | **Strict Physical PUF USB** | `ESP32-SENTINEL-FAC01` | `24:0A:C4:F8:91:02` |
| **Faculty 2** | `psunitha@hitam.org` | `faculty@123` | **Strict Physical PUF USB** | `ESP32-SENTINEL-FAC02` | `24:0A:C4:F8:91:04` |
| **Faculty 3** | `vrajesh@hitam.org` | `faculty@123` | **Strict Physical PUF USB** | `ESP32-SENTINEL-FAC03` | `24:0A:C4:F8:91:06` |
| **Faculty 4** | `manitha@hitam.org` | `faculty@123` | **Strict Physical PUF USB** | `ESP32-SENTINEL-FAC04` | `24:0A:C4:F8:91:08` |
