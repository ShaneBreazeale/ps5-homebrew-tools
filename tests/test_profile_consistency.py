"""Static consistency checks for every kernel-offset profile; no console, SDK or dump.

Complements test_kernel_offset.py: that suite proves the parser/guard LOGIC on
synthetic fixtures, but says nothing about the real per-firmware profile DATA on
disk. This suite loads every docs/debugger/profiles/*.json through the real
load_profile() validator and asserts cross-profile invariants, so a malformed or
colliding profile (e.g. a future 11.0 draft) fails here without a real dump or
console. It does NOT prove a profile's signatures/offsets match real hardware;
that still needs a hash-checked kernel dump per firmware.
"""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'host'))
from kernel_offset import DEFAULT_PROFILE, load_profile

PROFILE_DIR = DEFAULT_PROFILE.parent


def discover_profiles():
    return sorted(PROFILE_DIR.glob('*.json'))


class ProfileConsistencyTests(unittest.TestCase):
    def test_profiles_present(self):
        profiles = discover_profiles()
        self.assertTrue(profiles, f'no profiles found under {PROFILE_DIR}')

    def test_each_profile_loads(self):
        # load_profile already enforces schema, id format, dump size/sha256,
        # anchor monotonicity (text==0, data==size), and per-site signature vs
        # instruction_length. Any profile that cannot pass it is malformed.
        for path in discover_profiles():
            with self.subTest(profile=path.name):
                load_profile(path)

    def test_cross_profile_invariants(self):
        profiles = [load_profile(p) for p in discover_profiles()]
        # TODO(shane): define the cross-profile invariants. This is the decision
        # that shapes the test — pick what makes two profiles mutually valid.
        #
        # Meaningful choices to assert over `profiles` (each is a dict from
        # load_profile; relevant keys: 'id', 'firmware', 'firmware_mask',
        # 'soc_id', 'dump_sha256'):
        #   1. ids are unique                  -> two profiles can't collide by name
        #   2. no two profiles resolve the SAME (firmware & mask, soc_id) target
        #      -> otherwise validate_probe() can't tell which profile a live
        #         console matches: silent ambiguity, the dangerous case here
        #   3. dump_sha256 values are distinct -> catches a copy-paste 11.0 draft
        #      that forgot to re-hash its own dump
        #
        # GATING POLICY (the call I asked you to make):
        #   - hard-fail: assert here; a half-written new-firmware profile breaks
        #     CI until fixed. Safer, stricter — adding firmwares is gated.
        #   - skip-with-warn: self.skipTest(...) on a draft so WIP profiles don't
        #     block the suite. Permissive — trades CI noise for velocity.
        #
        # Implement ~5-10 lines below. Example starting point for invariant #2:
        #
        #   targets = [(p['firmware'] & p['firmware_mask'], p['soc_id']) for p in profiles]
        #   self.assertEqual(len(set(targets)), len(targets),
        #                    'two profiles resolve the same firmware/model target')
        self.skipTest('cross-profile invariants not yet defined — see TODO')


if __name__ == '__main__':
    unittest.main()
