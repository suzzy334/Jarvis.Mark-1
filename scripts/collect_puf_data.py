#!/usr/bin/env python3
"""
SentinelKey: Autonomous ESP32 SRAM-PUF Characterization Collector
Hyderabad Institute of Technology and Management (HITAM) - Department of ECE

Automates multi-condition PUF data collection across power cycles:
  - 30 cycles @ Room Temperature (Ambient ~25°C)
  - 30 cycles @ Cold Stress (Fridge/Freezer 0°C - 5°C)
  - 30 cycles @ Thermal Stress (Gentle Warm Air ~50°C)

Features:
  1. Auto Port Unlocker: Automatically detects and releases dangling serial port locks (Errno 16).
  2. Single & Multi-line Frame Parser: Bulletproof capture of ===PUF_START===...===PUF_END===.
  3. Zero-Latency DTR/RTS Reset: Toggles EN pin without missing fast ESP32 startup frames.
  4. Live Silicon Noise Telemetry: Displays intra-device Hamming Distance and BER on each cycle.
"""

import os
import sys
import time
import json
import re
import argparse
import subprocess

try:
    import serial
    import serial.tools.list_ports
except ImportError:
    serial = None


# -----------------------------------------------------------------------------
# PORT MANAGEMENT & AUTO-UNLOCK
# -----------------------------------------------------------------------------

def unlock_serial_port(port):
    """Detects if another process is locking the serial port and safely releases it."""
    if not os.path.exists(port):
        return
    try:
        res = subprocess.run(["lsof", port], capture_output=True, text=True)
        lines = res.stdout.strip().split("\n")
        if len(lines) > 1:
            for line in lines[1:]:
                parts = line.split()
                if len(parts) >= 2:
                    pid = parts[1]
                    cmd = parts[0]
                    # Don't kill self
                    if pid != str(os.getpid()):
                        print(f"[PORT LOCK] Port '{port}' held by PID {pid} ({cmd}). Terminating stale lock...")
                        subprocess.run(["kill", "-9", pid], capture_output=True)
                        time.sleep(0.6)
    except Exception as e:
        print(f"[WARN] Port unlock check: {e}")


def find_esp32_port():
    """Auto-detects ESP32 USB-to-UART bridge on macOS/Linux/Windows."""
    if not serial:
        return None
    # Check default common macOS path first
    if os.path.exists("/dev/cu.usbserial-0001"):
        return "/dev/cu.usbserial-0001"

    ports = list(serial.tools.list_ports.comports())
    for p in ports:
        desc = (p.description or "").lower()
        dev = (p.device or "").lower()
        if any(k in desc or k in dev for k in ["cp210", "ch340", "ch341", "usbserial", "ftdi", "uart", "esp32"]):
            return p.device
    return ports[0].device if ports else None


# -----------------------------------------------------------------------------
# HARDWARE RESET & PUF DUMP CAPTURE
# -----------------------------------------------------------------------------

def reset_esp32_and_capture(ser, timeout=4.0):
    """
    Pulses ESP32 EN pin via RTS to trigger a cold boot,
    then immediately streams incoming UART bytes to capture ===PUF_START===...===PUF_END===.
    """
    ser.reset_input_buffer()
    
    # Assert reset (EN LOW)
    ser.setDTR(False)
    ser.setRTS(True)
    time.sleep(0.10)
    
    # Release reset (EN HIGH -> bootloader executes)
    ser.setRTS(False)
    
    # Stream serial immediately without artificial sleep
    start_time = time.time()
    raw_buffer = ""
    
    while time.time() - start_time < timeout:
        if ser.in_waiting > 0:
            chunk = ser.read(ser.in_waiting).decode("utf-8", errors="ignore")
            raw_buffer += chunk
            
            # Check if complete frame arrived
            if "===PUF_START===" in raw_buffer and "===PUF_END===" in raw_buffer:
                match = re.search(r"===PUF_START===(.*?)===PUF_END===", raw_buffer, re.DOTALL)
                if match:
                    hex_dump = match.group(1).strip().replace("\r", "").replace("\n", "").replace(" ", "").upper()
                    if len(hex_dump) in [512, 1024]:
                        return hex_dump
        time.sleep(0.01)
        
    return None


def hex_to_bin(hex_str):
    """Converts hex string to binary bit string."""
    return bin(int(hex_str, 16))[2:].zfill(len(hex_str) * 4)


def compute_hamming_distance(bin_a, bin_b):
    """Computes bitwise Hamming Distance between two readings."""
    return sum(ca != cb for ca, cb in zip(bin_a, bin_b))


# -----------------------------------------------------------------------------
# MULTI-PHASE COLLECTION ENGINE
# -----------------------------------------------------------------------------

def collect_batch(ser, condition_name, target_count=30, auto=False):
    samples = []
    print("\n" + "=" * 65)
    print(f"  CONDITION: {condition_name.upper()} ({target_count} REBOOT CYCLES)")
    print("=" * 65)
    if not auto:
        input(f"Position your ESP32 for '{condition_name}' and press ENTER to start...")
    else:
        print(f"[AUTO] Starting '{condition_name}' collection automatically...")

    ref_bin = None
    zero_prefix_warned = False

    for i in range(1, target_count + 1):
        retries = 0
        hex_dump = None
        while retries < 3 and not hex_dump:
            hex_dump = reset_esp32_and_capture(ser)
            retries += 1
            if not hex_dump:
                time.sleep(0.2)

        if hex_dump:
            samples.append(hex_dump)
            current_bin = hex_to_bin(hex_dump)

            # Check if first 32 bytes (64 hex chars) are bootloader zeroes
            if not zero_prefix_warned and hex_dump[:64] == "0" * 64:
                print("\n  [NOTICE] Leading 32 bytes (256 bits) are RTC bootloader zeroes (0x50000200).")
                print("           Active silicon entropy starts at byte 32 (3840 bits).")
                print("           (Tip: Update firmware to 0x50000220 to capture 100% pure entropy)")
                zero_prefix_warned = True

            # Silicon noise metrics vs Reference Cycle 01
            if ref_bin is None:
                ref_bin = current_bin
                print(f"  [{condition_name}] Run {i:02d}/{target_count:02d}: Captured {len(hex_dump)} hex chars ({len(current_bin)} bits) [Baseline]")
            else:
                hd = compute_hamming_distance(ref_bin, current_bin)
                ber = (hd / len(current_bin)) * 100.0
                print(f"  [{condition_name}] Run {i:02d}/{target_count:02d}: Captured | HD: {hd:3d} bits | BER: {ber:5.2f}%")
        else:
            print(f"  [{condition_name}] Run {i:02d}/{target_count:02d}: FAILED frame capture after 3 retries.")

        time.sleep(0.25)  # Discharge stabilization time

    return samples


# -----------------------------------------------------------------------------
# MAIN CLI
# -----------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="SentinelKey ESP32 SRAM-PUF Characterization Collector")
    parser.add_argument("--port", default="/dev/cu.usbserial-0001", help="Serial port (default: /dev/cu.usbserial-0001)")
    parser.add_argument("--baud", type=int, default=115200, help="Baud rate (default: 115200)")
    parser.add_argument("--cycles", type=int, default=30, help="Cycles per condition (default: 30)")
    parser.add_argument("--device", default="ESP32-SENTINEL-FAC01", help="Device identifier (default: ESP32-SENTINEL-FAC01)")
    parser.add_argument("--output", default="puf_sram_dataset.json", help="Output JSON filename (default: puf_sram_dataset.json)")
    parser.add_argument("--auto", action="store_true", help="Run without manual pause between conditions")
    parser.add_argument("--phase", choices=["all", "ambient", "cold", "hot"], default="all", help="Collect specific phase or all (default: all)")
    args = parser.parse_args()

    print("=" * 65)
    print("  SENTINELKEY: HARDWARE SRAM-PUF DATASET COLLECTOR")
    print("  HITAM Department of ECE - Major Project 2026")
    print("=" * 65)

    if not serial:
        print("[ERROR] pyserial is not installed! Run: pip install pyserial")
        sys.exit(1)

    port = args.port
    if not os.path.exists(port):
        detected = find_esp32_port()
        if detected:
            port = detected
        else:
            print(f"[ERROR] Port '{port}' not found. Please connect your ESP32.")
            sys.exit(1)

    # 1. Clear any dangling locks
    unlock_serial_port(port)

    # 2. Open serial connection
    print(f"[INFO] Opening serial port {port} at {args.baud} baud...")
    ser = None
    try:
        ser = serial.Serial(port, args.baud, timeout=2.0)
        time.sleep(1.0)
    except Exception as e:
        print(f"[ERROR] Failed to open port {port}: {e}")
        if "Resource busy" in str(e):
            print("\n>>> CAUSE: Arduino IDE Serial Monitor or another terminal is holding the port!")
            print(">>> ACTION: Close the Serial Monitor window in Arduino IDE and run again.")
        sys.exit(1)

    dataset = {
        "device_id": args.device,
        "sample_bytes": 512,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "conditions": {}
    }

    try:
        # Phase 1: Room Temperature (Ambient)
        if args.phase in ["all", "ambient"]:
            dataset["conditions"]["ambient"] = collect_batch(ser, "ambient (room temp)", args.cycles, auto=args.auto)

        # Phase 2: Cold Temperature
        if args.phase in ["all", "cold"]:
            print("\n[PREPARATION] Place ESP32 in a moisture-sealed bag in the freezer for 5 minutes.")
            dataset["conditions"]["cold"] = collect_batch(ser, "cold (fridge/ice)", args.cycles, auto=args.auto)

        # Phase 3: Hot Temperature
        if args.phase in ["all", "hot"]:
            print("\n[PREPARATION] Gently warm the chip with a hairdryer or warm air for 20-30 seconds.")
            dataset["conditions"]["hot"] = collect_batch(ser, "hot (hairdryer/warm)", args.cycles, auto=args.auto)

        total_captured = sum(len(v) for v in dataset["conditions"].values())
        with open(args.output, "w") as f:
            json.dump(dataset, f, indent=2)

        print("\n" + "=" * 65)
        print(f"  SUCCESS! {total_captured} POWER CYCLES SAVED TO: {args.output}")
        print("=" * 65)
        print("NEXT STEP: Train and enroll your physical ESP32 token into the database:")
        print(f"  python3 scripts/train_esp32_puf.py --dataset {args.output} --faculty FAC-ECE-101")
        print("=" * 65)

    finally:
        if ser and ser.is_open:
            ser.close()
            print("[INFO] Serial port safely released.")


if __name__ == "__main__":
    main()
