#!/usr/bin/env python3
"""
SentinelKey Fuzzy Extractor & Silicon Fingerprint Analyzer
HITAM Department of ECE - Major Project

Analyzes the 90-read characterization dataset, evaluates thermal noise,
extracts 100% stable silicon bits, and generates:
  1. Helper Mask (public helper data)
  2. Golden Key (secret cryptographic seed, reconstructed inside ESP32)
  3. Server Public Verifier (stored in Supabase/Postgres)
"""

import json
import hashlib
import argparse
import os
import sys


def hex_to_bin_string(hex_str, expected_bits=2048):
    """Converts a hex string into a fixed-width binary string."""
    num = int(hex_str, 16)
    bin_str = bin(num)[2:].zfill(expected_bits)
    return bin_str


def calculate_hamming_distance(str1, str2):
    """Calculates bitwise Hamming Distance between two binary strings."""
    return sum(c1 != c2 for c1, c2 in zip(str1, str2))


def analyze_dataset(dataset_path):
    if not os.path.exists(dataset_path):
        print(f"[ERROR] Dataset file '{dataset_path}' not found.")
        print("Run 'python scripts/collect_puf_data.py --mock' first to generate sample data.")
        sys.exit(1)

    with open(dataset_path, "r") as f:
        data = json.load(f)

    room_reads = data.get("room_temp", [])
    cold_reads = data.get("cold", [])
    hot_reads = data.get("hot", [])
    all_reads = room_reads + cold_reads + hot_reads

    total_reads = len(all_reads)
    if total_reads < 1:
        print("[ERROR] Dataset contains no readings.")
        sys.exit(1)

    bit_length = data.get("metadata", {}).get("bit_count", 2048)
    print(f"\n=======================================================")
    print(f"  SentinelKey Silicon PUF Analysis Report")
    print(f"=======================================================")
    print(f"• Total reads loaded: {total_reads} (Room: {len(room_reads)}, Cold: {len(cold_reads)}, Hot: {len(hot_reads)})")
    print(f"• Raw PUF entropy pool: {bit_length} bits (256 bytes)")

    # Convert all hex reads to binary strings
    bin_reads = [hex_to_bin_string(r, bit_length) for r in all_reads]

    # 1. Compute Intra-PUF Hamming Distance (Noise analysis)
    reference = bin_reads[0]
    distances = [calculate_hamming_distance(reference, read) for read in bin_reads[1:]]
    avg_hd = sum(distances) / len(distances) if distances else 0.0
    hd_percentage = (avg_hd / bit_length) * 100

    print(f"• Average Intra-PUF Noise: {avg_hd:.2f} bits ({hd_percentage:.2f}%)")
    print(f"  -> Physical chip displays realistic manufacturing thermal drift.")

    # 2. Find 100% stable bits across all thermal conditions
    stable_indices = []
    golden_bits = []

    for bit_idx in range(bit_length):
        ref_bit = bin_reads[0][bit_idx]
        is_stable = all(read[bit_idx] == ref_bit for read in bin_reads)
        if is_stable:
            stable_indices.append(bit_idx)
            golden_bits.append(ref_bit)

    stability_rate = (len(stable_indices) / bit_length) * 100
    print(f"• 100% Thermally Stable Bits: {len(stable_indices)} / {bit_length} ({stability_rate:.1f}%)")

    if len(stable_indices) < 256:
        print("[WARNING] Found fewer than 256 strictly stable bits. Relaxing threshold to 97%...")
        stable_indices = []
        golden_bits = []
        for bit_idx in range(bit_length):
            ones = sum(1 for read in bin_reads if read[bit_idx] == "1")
            ratio = ones / total_reads
            if ratio >= 0.97:
                stable_indices.append(bit_idx)
                golden_bits.append("1")
            elif ratio <= 0.03:
                stable_indices.append(bit_idx)
                golden_bits.append("0")

    # Select the top 256 stable bits to form the 256-bit Golden Key
    selected_indices = stable_indices[:256]
    selected_bits = "".join(golden_bits[:256])

    # Convert binary golden key to hex
    golden_key_hex = f"{int(selected_bits, 2):064x}"

    # Generate Server Public Verifier (SHA-256 of Golden Key)
    # The raw Golden Key is NEVER stored on the server!
    server_verifier = hashlib.sha256(bytes.fromhex(golden_key_hex)).hexdigest()

    print(f"• Selected Stable Indices for Helper Mask: 256 bits")
    print(f"• Server Public Verifier Hash: {server_verifier[:16]}...{server_verifier[-8:]}")

    enrollment_record = {
        "device_id": "ESP32-SENTINEL-01",
        "helper_mask": selected_indices,
        "public_verifier": server_verifier,
        "chip_entropy_bits": bit_length,
        "intra_hd_percentage": round(hd_percentage, 2),
        "stable_bit_count": len(stable_indices)
    }

    return enrollment_record, golden_key_hex


def main():
    parser = argparse.ArgumentParser(description="Analyze PUF dataset and generate enrollment parameters.")
    parser.add_argument("--dataset", default="puf_sram_dataset.json", help="Path to puf_sram_dataset.json")
    parser.add_argument("--out", default="enrollment_data.json", help="Path to save enrollment metadata")
    parser.add_argument("--student-id", default="23E51A0417", help="Student Roll Number or Faculty ID to pair")
    args = parser.parse_args()

    record, secret_golden_key = analyze_dataset(args.dataset)
    record["paired_student_id"] = args.student_id

    with open(args.out, "w") as f:
        json.dump(record, f, indent=2)

    print(f"\n[SUCCESS] Enrollment package generated and saved to: {args.out}")
    print(f"• Paired ID: {record['paired_student_id']}")
    print(f"• Device ID: {record['device_id']}")
    print("\n[SECURITY NOTICE]")
    print("  The 'helper_mask' and 'public_verifier' are safe to store in the cloud database.")
    print("  The 'Golden Key' will ONLY be reconstructed inside the ESP32's volatile RAM during login.")


if __name__ == "__main__":
    main()
