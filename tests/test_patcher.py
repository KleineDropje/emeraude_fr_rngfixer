"""Tests sans ROM : invariants et portée exacte des écritures."""

import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

import emerald_fr_rng_fix as patcher  # noqa: E402


class PatchDefinitionTests(unittest.TestCase):
    def test_internal_definition_is_valid(self):
        patcher.validate_patch_definition()

    def test_expected_pointer_is_thumb_address(self):
        value = patcher.POINTER_PATCHED_FIRST_THREE + patcher.POINTER_ORIGINAL[3:]
        self.assertEqual(int.from_bytes(value, "little"), 0x089C4F71)

    def test_exactly_three_non_overlapping_write_ranges(self):
        ranges = [
            set(range(offset, offset + len(replacement)))
            for offset, replacement in patcher.PATCH_WRITES
        ]
        self.assertEqual(len(ranges), 3)
        self.assertFalse(ranges[0] & ranges[1])
        self.assertFalse(ranges[0] & ranges[2])
        self.assertFalse(ranges[1] & ranges[2])
        self.assertEqual(sum(map(len, ranges)), 76)

    def test_apply_changes_only_declared_ranges(self):
        source = bytes(patcher.ROM_SIZE)
        result = patcher.apply_patch_writes(source)
        expected = bytearray(source)
        for offset, replacement in patcher.PATCH_WRITES:
            expected[offset : offset + len(replacement)] = replacement
        self.assertEqual(result, bytes(expected))
        self.assertEqual(len(result), patcher.ROM_SIZE)

    def test_output_name_never_matches_source(self):
        source = Path("Pokemon - Version Emeraude (France).gba")
        self.assertNotEqual(patcher.numbered_output_path(source, 0), source)
        self.assertNotEqual(patcher.numbered_output_path(source, 1), source)


if __name__ == "__main__":
    unittest.main()
