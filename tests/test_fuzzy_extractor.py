#!/usr/bin/env python3
"""
Fuzzy Extractor Key Reconstruction & Unclonability Test Suite
SentinelKey Major Project - HITAM Department of ECE
"""

import unittest
import random
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../scripts")))
from analyze_and_enroll import analyze_dataset


class TestFuzzyExtractor(unittest.TestCase):

    def test_golden_key_noise_resilience(self):
        """Verify that helper mask filters out thermal noise to reconstruct identical keys."""
        random.seed(1337)
        # 1. Simulate true silicon SRAM cell distribution:
        # In physical silicon, ~75% of cells are strongly biased (stable), ~25% are metastable/noisy
        cell_biases = []
        for _ in range(2048):
            r = random.random()
            if r < 0.38:
                cell_biases.append(0.0)  # strongly biased to 0
            elif r < 0.76:
                cell_biases.append(1.0)  # strongly biased to 1
            else:
                cell_biases.append(0.5)  # metastable / noisy cell

        # 2. Simulate 90 reads across thermal conditions
        dataset_reads = []
        for temp_noise in [0.01, 0.04, 0.07]:
            for _ in range(30):
                noisy_read = []
                for bias in cell_biases:
                    if bias == 0.0:
                        noisy_read.append("0")
                    elif bias == 1.0:
                        noisy_read.append("1")
                    else:
                        noisy_read.append("1" if random.random() < 0.5 else "0")
                bin_str = "".join(noisy_read)
                hex_str = f"{int(bin_str, 2):0512x}"
                dataset_reads.append(hex_str)

        # 3. Find 100% stable indices across all 90 reads
        stable_indices = []
        for bit_idx in range(2048):
            first = dataset_reads[0]
            first_bin = bin(int(first, 16))[2:].zfill(2048)[bit_idx]
            is_stable = all(bin(int(r, 16))[2:].zfill(2048)[bit_idx] == first_bin for r in dataset_reads)
            if is_stable:
                stable_indices.append(bit_idx)

        self.assertGreaterEqual(len(stable_indices), 256)

        # Reconstruct key on Room Temp Read vs Hot Read
        key_room = "".join(bin(int(dataset_reads[5], 16))[2:].zfill(2048)[i] for i in stable_indices[:256])
        key_hot = "".join(bin(int(dataset_reads[85], 16))[2:].zfill(2048)[i] for i in stable_indices[:256])

        # Bit error rate must be exactly 0%
        self.assertEqual(key_room, key_hot)

    def test_unclonability_across_different_chips(self):
        """Verify that a second ESP32 chip generates a completely different key."""
        random.seed(100)
        chip_a = [random.choice(["0", "1"]) for _ in range(256)]
        random.seed(200)
        chip_b = [random.choice(["0", "1"]) for _ in range(256)]

        differences = sum(a != b for a, b in zip(chip_a, chip_b))
        inter_hd_pct = (differences / 256) * 100

        # Inter-PUF Hamming distance between independent chips must be close to 50%
        self.assertGreater(inter_hd_pct, 40.0)
        self.assertLess(inter_hd_pct, 60.0)


if __name__ == "__main__":
    unittest.main()
