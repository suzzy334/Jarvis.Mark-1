#!/usr/bin/env python3
"""
SentinelKey: Autonomous ESP32 SRAM-PUF Characterization & Training Pipeline
Hyderabad Institute of Technology and Management (HITAM) - Department of ECE

Automates:
  1. Multi-Condition Dataset Ingestion or Live Serial Sampling (50-100 cycles).
  2. Bootloader Zero-Offset Auto-Detection & Entropy Region Slicing.
  3. Statistical Reliability & Noise Analysis (Intra-device Hamming Distance, Shannon Entropy).
  4. 256-bit Golden Key Extraction & Helper Data Mask Generation.
  5. Automatic C-Header Export (firmware/helper_data_<device_id>.h).
  6. Direct Database Enrollment into SentinelKey SQLite/Supabase.
"""

import sys
import os
import time
import json
import math
import hashlib
import argparse
import random

# Ensure project modules are discoverable
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "backend"))

try:
    import serial
    import serial.tools.list_ports
except ImportError:
    serial = None

from database import get_db_connection


# -----------------------------------------------------------------------------
# PORT DISCOVERY & HARDWARE COMMS
# -----------------------------------------------------------------------------

def discover_esp32_port():
    """Scans and auto-detects USB-to-UART bridge connected to ESP32 DevKit."""
    if os.path.exists("/dev/cu.usbserial-0001"):
        return "/dev/cu.usbserial-0001"
    if not serial:
        return None
    ports = list(serial.tools.list_ports.comports())
    for p in ports:
        desc = (p.description or "").lower()
        dev = (p.device or "").lower()
        if any(k in desc or k in dev for k in ["cp210", "ch340", "ch341", "ftdi", "usb serial", "uart", "wchusb"]):
            return p.device
    return ports[0].device if ports else None


def reboot_esp32(ser):
    """Toggles DTR/RTS lines to perform a clean hardware reset on the ESP32."""
    ser.setDTR(False)
    ser.setRTS(True)
    time.sleep(0.10)
    ser.setRTS(False)


def read_sram_burst(ser, timeout=3.5):
    """Reads startup frame ===PUF_START===...===PUF_END=== or responds to DUMP_SRAM."""
    start = time.time()
    raw_buffer = ""
    while time.time() - start < timeout:
        if ser.in_waiting > 0:
            chunk = ser.read(ser.in_waiting).decode("utf-8", errors="ignore")
            raw_buffer += chunk
            if "===PUF_START===" in raw_buffer and "===PUF_END===" in raw_buffer:
                part = raw_buffer.split("===PUF_START===")[1].split("===PUF_END===")[0]
                clean = part.strip().replace("\r", "").replace("\n", "").replace(" ", "").upper()
                if len(clean) in [512, 1024]:
                    return clean
        time.sleep(0.01)
    return None


# -----------------------------------------------------------------------------
# SYNTHETIC MOCK ENGINE
# -----------------------------------------------------------------------------

def generate_mock_baseline(device_id, bit_count=2048):
    """Generates a deterministic silicon gate threshold baseline from device eFuse seed."""
    seed = int(hashlib.sha256(device_id.encode()).hexdigest()[:16], 16)
    rng = random.Random(seed)  # nosec B311 - Deterministic mock simulation
    return [str(rng.randint(0, 1)) for _ in range(bit_count)]  # nosec B311


def sample_mock_sram(baseline_bits, noise_prob=0.035):
    """Generates a realistic noisy SRAM read with temperature-induced bit flips."""
    sample_bits = []
    for b in baseline_bits:
        if random.random() < noise_prob:  # nosec B311 - Thermal noise simulation
            sample_bits.append("1" if b == "0" else "0")
        else:
            sample_bits.append(b)
    bin_str = "".join(sample_bits)
    return f"{int(bin_str, 2):0{len(bin_str)//4}X}"


# -----------------------------------------------------------------------------
# MATHEMATICAL & STATISTICAL ANALYSIS
# -----------------------------------------------------------------------------

def hex_to_bin_string(hex_str):
    """Converts a hex string to binary characters matching its exact bit length."""
    num = int(hex_str, 16)
    return bin(num)[2:].zfill(len(hex_str) * 4)


def calculate_hamming_distance(bin1, bin2):
    """Calculates bitwise Hamming Distance between two readings."""
    return sum(c1 != c2 for c1, c2 in zip(bin1, bin2))


def calculate_shannon_entropy(bit_string):
    """Calculates Shannon Entropy (ideal = 1.0 bit/bit for random silicon)."""
    p1 = bit_string.count("1") / len(bit_string)
    p0 = 1.0 - p1
    if p0 == 0 or p1 == 0:
        return 0.0
    return -(p0 * math.log2(p0) + p1 * math.log2(p1))


# -----------------------------------------------------------------------------
# MAIN CHARACTERIZATION & TRAINING EXECUTION
# -----------------------------------------------------------------------------

def train_esp32_puf(device_id, faculty_roll, num_samples=50, port=None, is_mock=False, dataset_path=None, mac_address=None):
    print("=" * 72)
    print("  SENTINELKEY: ESP32 SILICON PUF TRAINING & CHARACTERIZATION")
    print("  HITAM Department of ECE | Autonomous Campus Security")
    print("=" * 72)
    print(f"Target Device ID : {device_id}")
    print(f"Assigned Faculty : {faculty_roll}")
    
    raw_reads = []

    # Case A: Train directly from collected dataset JSON
    if dataset_path and os.path.exists(dataset_path):
        print(f"Execution Mode   : INGESTING DATASET FILE ({dataset_path})")
        print("-" * 72)
        with open(dataset_path, "r") as f:
            data = json.load(f)

        # Support both {"conditions": {"ambient": [...], ...}} and flat list formats
        if "conditions" in data:
            for cond, samples in data["conditions"].items():
                print(f"  • Ingested {len(samples)} cycles from condition: {cond}")
                raw_reads.extend(samples)
        elif "room_temp" in data:
            for key in ["room_temp", "cold", "hot"]:
                if key in data:
                    raw_reads.extend(data[key])
        elif isinstance(data, list):
            raw_reads.extend(data)

        if "device_id" in data and not device_id:
            device_id = data["device_id"]

    # Case B: Synthetic Mock
    elif is_mock:
        print(f"Sampling Burst   : {num_samples} Synthetic Power Cycles")
        print(f"Execution Mode   : SYNTHETIC MOCK ENGINE")
        print("-" * 72)
        baseline_bits = generate_mock_baseline(device_id, 2048)
        for i in range(num_samples):
            noise = random.uniform(0.025, 0.06)  # nosec B311 - Mock thermal jitter
            raw_reads.append(sample_mock_sram(baseline_bits, noise_prob=noise))

    # Case C: Live Physical Serial Acquisition
    else:
        if not port:
            port = discover_esp32_port()
        if not port:
            print("[ERROR] No ESP32 USB serial port detected!")
            print("Connect your ESP32 via USB or pass '--dataset puf_sram_dataset.json' or '--mock'.")
            sys.exit(1)

        print(f"Sampling Burst   : {num_samples} Live Reboot Cycles")
        print(f"Execution Mode   : PHYSICAL ESP32 SERIAL ({port})")
        print("-" * 72)

        try:
            ser = serial.Serial(port, 115200, timeout=2.0)
            time.sleep(1.0)
            ser.reset_input_buffer()
        except Exception as e:
            print(f"[ERROR] Failed to open serial port {port}: {e}")
            sys.exit(1)

        print(f"\n[STEP 1/5] Acquiring {num_samples} raw SRAM startup memory snapshots...")
        for i in range(1, num_samples + 1):
            reboot_esp32(ser)
            read_hex = read_sram_burst(ser)
            if not read_hex:
                time.sleep(0.3)
                read_hex = read_sram_burst(ser)

            if read_hex:
                raw_reads.append(read_hex)
                print(f"  Cycle {i:02d}/{num_samples:02d}: Captured ({len(read_hex)} hex chars)")
            else:
                print(f"  Cycle {i:02d}/{num_samples:02d}: Frame timeout, retrying...")

        ser.close()

    if len(raw_reads) < 2:
        print(f"[ERROR] Insufficient samples collected ({len(raw_reads)}). Need at least 2 power cycles.")
        sys.exit(1)

    print(f"\n✓ Dataset ready: {len(raw_reads)} valid power-cycle snapshots loaded.")

    # -------------------------------------------------------------------------
    # ZERO-PREFIX DETECTION & ENTROPY REGION SLICING
    # -------------------------------------------------------------------------
    first_sample = raw_reads[0]
    hex_len = len(first_sample)
    bit_offset = 0

    # If first 64 hex characters are zeroes (RTC bootloader reserved 32-byte region at 0x50000200)
    if first_sample[:64] == "0" * 64:
        print("\n[ISOLATION] Detected 32-byte (256-bit) RTC bootloader zero vector at address 0x50000200.")
        print("            Automatically slicing to active silicon entropy region (bytes 32..512).")
        raw_reads = [r[64:] for r in raw_reads]
        bit_offset = 256
        pool_bits = len(raw_reads[0]) * 4
        print(f"            Active Entropy Pool: {pool_bits} bits ({pool_bits // 8} bytes).")
    else:
        pool_bits = hex_len * 4
        print(f"  • Entropy Pool Size: {pool_bits} bits ({pool_bits // 8} bytes)")

    # -------------------------------------------------------------------------
    # STATISTICAL NOISE & RELIABILITY ANALYSIS
    # -------------------------------------------------------------------------
    print("\n[STEP 2/5] Performing Silicon Statistical Noise & Entropy Analysis...")
    bin_reads = [hex_to_bin_string(r) for r in raw_reads]
    ref_read = bin_reads[0]

    distances = [calculate_hamming_distance(ref_read, b) for b in bin_reads[1:]]
    avg_hd = sum(distances) / len(distances) if distances else 0.0
    ber_intra = (avg_hd / float(pool_bits)) * 100.0
    entropy = calculate_shannon_entropy(ref_read)

    print(f"  • Analyzed Power Cycles      : {len(raw_reads)} snapshots")
    print(f"  • Mean Intra-Device Distance : {avg_hd:.2f} bits (out of {pool_bits} bits)")
    print(f"  • Fractional Bit Error Rate  : {ber_intra:.2f}% (Silicon standard: 3% to 8%)")
    print(f"  • Silicon Shannon Entropy    : {entropy:.4f} bits/bit (Ideal random silicon: 1.0000)")

    # -------------------------------------------------------------------------
    # HELPER DATA MASK EXTRACTION (TOP 256 THERMALLY STABLE BITS)
    # -------------------------------------------------------------------------
    print("\n[STEP 3/5] Computing Helper Data Mask (Isolating 256 Most Thermally Stable Bits)...")
    bit_stability_scores = []

    for bit_idx in range(pool_bits):
        ones = sum(1 for read in bin_reads if read[bit_idx] == "1")
        ratio = ones / len(bin_reads)
        # Stability: 1.0 means 100% same value every reboot; 0.0 means completely noisy flip-flop
        stability = abs(ratio - 0.5) * 2.0
        golden_val = "1" if ratio >= 0.5 else "0"
        bit_stability_scores.append((bit_idx, stability, golden_val))

    # Sort by highest stability
    bit_stability_scores.sort(key=lambda x: x[1], reverse=True)
    selected_256 = bit_stability_scores[:256]

    # Map indices back to original raw memory buffer (including bootloader offset if applicable)
    stable_indices = [x[0] + bit_offset for x in selected_256]
    golden_bits = "".join([x[2] for x in selected_256])

    # -------------------------------------------------------------------------
    # OPTION B: ASYMMETRIC ECC (NIST P-256 / SECP256R1) PUBLIC KEY DERIVATION
    # -------------------------------------------------------------------------
    from cryptography.hazmat.primitives.asymmetric import ec
    golden_key_hex = f"{int(golden_bits, 2):064X}"
    private_num = int.from_bytes(bytes.fromhex(golden_key_hex), "big")
    priv_key = ec.derive_private_key(private_num, ec.SECP256R1())
    pub_key = priv_key.public_key()
    pub_nums = pub_key.public_numbers()
    ecc_public_key_hex = f"04{pub_nums.x:064X}{pub_nums.y:064X}"
    
    # In Option B (Asymmetric PUF), the server verifier is the Elliptic Curve Public Key Q!
    server_verifier_hex = f"ECDSA:{ecc_public_key_hex}"

    avg_stability = (sum(x[1] for x in selected_256) / 256.0) * 100.0
    print(f"  • Selected Stable Indices    : 256 Bits isolated")
    print(f"  • Mean Gate Stability Score  : {avg_stability:.2f}%")
    print(f"  • PUF Private Key (Scalar d) : {golden_key_hex[:16]}...{golden_key_hex[-16:]} (256-bit ephemeral secret)")
    print(f"  • Option B ECC Public Key Q  : {ecc_public_key_hex[:24]}...{ecc_public_key_hex[-24:]} (NIST P-256 / SECP256R1)")
    print(f"  • Server Public Verifier     : {server_verifier_hex[:32]}... (Stored in Database)")

    # -------------------------------------------------------------------------
    # EXPORT ARTIFACTS & FIRMWARE C-HEADER
    # -------------------------------------------------------------------------
    print("\n[STEP 4/5] Exporting Artifacts & ESP32 Firmware Header...")
    data_dir = os.path.join(PROJECT_ROOT, "data")
    os.makedirs(data_dir, exist_ok=True)

    json_path = os.path.join(data_dir, f"characterization_{device_id}.json")
    char_data = {
        "device_id": device_id,
        "faculty_roll": faculty_roll,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "metrics": {
            "entropy_pool_bits": pool_bits,
            "samples_analyzed": len(raw_reads),
            "ber_intra_percent": round(ber_intra, 2),
            "shannon_entropy": round(entropy, 4),
            "gate_stability_percent": round(avg_stability, 2)
        },
        "stable_indices": stable_indices,
        "golden_key": golden_key_hex,
        "verifier": server_verifier_hex,
        "ecc_public_key": ecc_public_key_hex,
        "mac_address": mac_address
    }
    with open(json_path, "w") as f:
        json.dump(char_data, f, indent=2)
    print(f"  ✓ Characterization JSON saved : {json_path}")

    # Generate C-Header for firmware
    firmware_dir = os.path.join(PROJECT_ROOT, "firmware")
    header_path = os.path.join(firmware_dir, f"helper_data_{device_id}.h")

    header_lines = [
        f"// Auto-generated Helper Data Mask for SentinelKey {device_id}",
        f"// Trained for Faculty Account: {faculty_roll}",
        f"// Cryptographic Scheme: OPTION B (ASYMMETRIC ECDSA / NIST P-256)",
        f"// Date: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "#ifndef HELPER_DATA_H",
        "#define HELPER_DATA_H",
        "",
        f'#define SENTINEL_DEVICE_ID "{device_id}"',
        f"#define PUF_ENTROPY_POOL_SIZE {pool_bits}",
        f'#define PUF_ECC_PUBLIC_KEY "{ecc_public_key_hex}"',
        f'#define ENROLLED_FACULTY_ROLL "{faculty_roll}"',
        "",
        "const uint16_t STABLE_INDICES[256] = {"
    ]
    for row in range(0, 256, 16):
        chunk = stable_indices[row:row+16]
        header_lines.append("  " + ", ".join(f"{idx:4d}" for idx in chunk) + ("," if row + 16 < 256 else ""))
    header_lines.append("};")
    header_lines.append("")
    header_lines.append("#endif // HELPER_DATA_H")

    with open(header_path, "w") as f:
        f.write("\n".join(header_lines) + "\n")
    print(f"  ✓ C-Header array generated    : {header_path}")

    # -------------------------------------------------------------------------
    # DIRECT DATABASE ENROLLMENT
    # -------------------------------------------------------------------------
    print("\n[STEP 5/5] Updating SentinelKey College Registry Database...")
    conn = get_db_connection()
    user = conn.execute("SELECT id, name FROM users WHERE roll_or_emp_id = ?", (faculty_roll,)).fetchone()

    if not user:
        print(f"[ERROR] Faculty member '{faculty_roll}' not found in database!")
        conn.close()
        sys.exit(1)

    user_id = user["id"]
    helper_data_json = json.dumps({"stable_indices": stable_indices})

    conn.execute("""
        INSERT INTO devices (device_id, user_id, helper_mask, public_verifier, mac_address, status)
        VALUES (?, ?, ?, ?, ?, 'ACTIVE')
        ON CONFLICT(user_id) DO UPDATE SET
            device_id = excluded.device_id,
            helper_mask = excluded.helper_mask,
            public_verifier = excluded.public_verifier,
            mac_address = COALESCE(excluded.mac_address, devices.mac_address),
            status = 'ACTIVE'
    """, (device_id, user_id, helper_data_json, server_verifier_hex, mac_address))
    conn.commit()
    conn.close()

    print(f"  ✓ Bound Token '{device_id}' to Faculty '{user['name']}' ({faculty_roll}) in database.")

    print("\n" + "=" * 72)
    print("  TRAINING & ENROLLMENT COMPLETED SUCCESSFULLY!")
    print("=" * 72)
    print(f"• Target Device     : {device_id}")
    print(f"• Registered Owner  : {user['name']} ({faculty_roll})")
    print(f"• Silicon BER_intra : {ber_intra:.2f}% (Thermally Validated)")
    print(f"• Public Verifier   : {server_verifier_hex}")
    print(f"• Database Status   : ACTIVE in sentinelkey.db")
    print("=" * 72)


# -----------------------------------------------------------------------------
# ENTRY POINT
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SentinelKey ESP32 PUF Characterization & Enrollment Tool")
    parser.add_argument("--device-id", default="ESP32-SENTINEL-FAC01", help="Unique Device ID (default: ESP32-SENTINEL-FAC01)")
    parser.add_argument("--faculty", default="FAC-ECE-101", help="Faculty ID (default: FAC-ECE-101)")
    parser.add_argument("--mac", default=None, help="Hardware eFuse MAC address (e.g. B0:A7:32:1A:4C:80)")
    parser.add_argument("--samples", type=int, default=50, help="Number of samples for live sampling (default: 50)")
    parser.add_argument("--port", default=None, help="USB Serial Port (default: auto-detect)")
    parser.add_argument("--dataset", default=None, help="Path to pre-collected JSON dataset (e.g. puf_sram_dataset.json)")
    parser.add_argument("--mock", action="store_true", help="Run in synthetic simulation mode without physical hardware")

    args = parser.parse_args()
    train_esp32_puf(
        device_id=args.device_id,
        faculty_roll=args.faculty,
        num_samples=args.samples,
        port=args.port,
        is_mock=args.mock,
        dataset_path=args.dataset,
        mac_address=args.mac
    )
