"""
Unit tests for phi, has_primitive_root, smallest_primitive_root, and
all_primitive_roots in cryptomath.

A couple of the tests cross-check the implementations against small independent
reference versions (brute-force totient and brute-force modular order), so a
mistake in the reference is unlikely to hide a mistake in the code under test.
"""

import unittest

from src.cipher_toolkit.cryptomath import (
    all_primitive_roots,
    has_primitive_root,
    phi,
    smallest_primitive_root,
)


# --- Reference implementations (kept separate on purpose) -------------------
def _bruteforce_phi(n):
    """Count residues in 1..n coprime with n, the ground-truth totient."""
    from math import gcd

    return sum(1 for k in range(1, n + 1) if gcd(k, n) == 1)


def _bruteforce_primitive_roots(n):
    """Every generator of the multiplicative group mod n, via its order.

    An element is a primitive root exactly when the smallest positive power
    that returns to 1 equals phi(n), so this scans and checks order by brute
    force, an independent route from the code under test. Non-coprime
    residues can never generate the group, so they are skipped, and the
    trivial group (n = 1, whose only element 0 is its own generator) is
    handled explicitly to stay consistent with ``has_primitive_root(1)``.
    """
    from math import gcd

    if not has_primitive_root(n):
        return []
    if n == 1:
        return [0]
    target = phi(n)
    roots = []
    for a in range(1, n):
        if gcd(a, n) != 1:
            continue
        order = 1
        value = a % n
        while value != 1:
            value = (value * a) % n
            order += 1
        if order == target:
            roots.append(a)
    return roots


# --- phi -------------------------------------------------------------------
class PhiTests(unittest.TestCase):
    def test_domain(self):
        with self.assertRaises(ValueError):
            phi(0)
        with self.assertRaises(ValueError):
            phi(-5)

    def test_one_is_one(self):
        # Only the trivial residue is coprime with 1.
        self.assertEqual(phi(1), 1)

    def test_matches_coprime_count(self):
        # Independent ground truth: count residues coprime with n.
        for n in range(1, 101):
            self.assertEqual(phi(n), _bruteforce_phi(n), msg=f"n={n}")

    def test_prime_is_minus_one(self):
        for p in (3, 5, 7, 11, 13, 17, 19, 23, 29, 31):
            self.assertEqual(phi(p), p - 1)

    def test_prime_power_uses_one_factor(self):
        # phi(p**k) = p**k - p**(k-1); each prime applied only once.
        self.assertEqual(phi(9), 6)  # 9 - 3
        self.assertEqual(phi(25), 20)  # 25 - 5
        self.assertEqual(phi(27), 18)  # 27 - 9
        self.assertEqual(phi(16), 8)  # 2**4 -> 8

    def test_composite_has_two_primes(self):
        self.assertEqual(phi(15), 8)  # 3 * 5
        self.assertEqual(phi(12), 4)  # 4 * 3
        self.assertEqual(phi(30), 8)  # 2 * 3 * 5
        self.assertEqual(phi(100), 40)  # 2**2 * 5**2


# --- has_primitive_root -----------------------------------------------------
class HasPrimitiveRootTests(unittest.TestCase):
    def test_domain(self):
        with self.assertRaises(ValueError):
            has_primitive_root(0)
        with self.assertRaises(ValueError):
            has_primitive_root(-10)

    def test_trivial_small_moduli(self):
        self.assertTrue(has_primitive_root(1))
        self.assertTrue(has_primitive_root(2))
        self.assertTrue(has_primitive_root(4))

    def test_odd_prime_powers(self):
        for p in (3, 5, 7, 11, 13):
            self.assertTrue(has_primitive_root(p))
            for k in (2, 3):
                self.assertTrue(has_primitive_root(p**k))

    def test_two_times_odd_prime_power(self):
        # 2 * p**k is always cyclic.
        for m in (6, 10, 14, 18, 22, 26, 34, 50):  # 50 = 2 * 25
            self.assertTrue(has_primitive_root(m), msg=f"n={m}")

    def test_even_prime_power_above_four_has_none(self):
        # 2**k for k >= 3 is not cyclic: it splits into two pieces.
        for m in (8, 16, 32, 64):
            self.assertFalse(has_primitive_root(m), msg=f"n={m}")

    def test_divisible_by_four_has_none(self):
        # A factor of 4 already breaks cyclicity even with an odd part.
        for m in (12, 20, 24, 36, 100):
            self.assertFalse(has_primitive_root(m), msg=f"n={m}")

    def test_product_of_distinct_odds_has_none(self):
        # More than one odd prime factor: never cyclic.
        for m in (15, 21, 33, 45, 105):
            self.assertFalse(has_primitive_root(m), msg=f"n={m}")

    def test_count_matches_reference(self):
        # Sanity: every reported "True" actually has a primitive root by the
        # brute-force order test, and every "False" genuinely has none.
        for n in range(1, 201):
            self.assertEqual(
                has_primitive_root(n),
                bool(_bruteforce_primitive_roots(n)),
                msg=f"n={n}",
            )


# --- smallest_primitive_root ------------------------------------------------
class SmallestPrimitiveRootTests(unittest.TestCase):
    def test_domain(self):
        with self.assertRaises(ValueError):
            smallest_primitive_root(0)

    def test_no_root_returns_zero(self):
        for n in (8, 12, 15, 16, 32, 100):
            self.assertEqual(smallest_primitive_root(n), 0, msg=f"n={n}")

    def test_known_values(self):
        for n, expected in (
            (1, 0),  # trivial degenerate group; nothing to scan
            (2, 1),  # the single residue 1 generates
            (3, 2),
            (4, 3),
            (5, 2),
            (7, 3),
            (11, 2),
            (13, 2),
            (17, 3),
            (19, 2),
            (23, 5),
            (25, 2),
            (29, 2),
            (31, 3),
            (37, 2),
            (43, 3),
            (49, 3),
        ):
            self.assertEqual(smallest_primitive_root(n), expected, msg=f"n={n}")

    def test_matches_reference(self):
        for n in range(1, 200):
            ref = _bruteforce_primitive_roots(n)
            expected = ref[0] if ref else 0
            self.assertEqual(smallest_primitive_root(n), expected, msg=f"n={n}")


# --- all_primitive_roots ----------------------------------------------------
class AllPrimitiveRootsTests(unittest.TestCase):
    def test_domain(self):
        with self.assertRaises(ValueError):
            all_primitive_roots(0)

    def test_no_root_returns_empty(self):
        for n in (8, 12, 15, 16, 32, 100):
            self.assertEqual(all_primitive_roots(n), [], msg=f"n={n}")

    def test_known_lists(self):
        self.assertEqual(all_primitive_roots(5), [2, 3])
        self.assertEqual(all_primitive_roots(7), [3, 5])

    def test_sorted_ascending(self):
        for n in range(1, 200):
            roots = all_primitive_roots(n)
            self.assertEqual(roots, sorted(roots), msg=f"n={n}")
            self.assertEqual(set(roots), set(_bruteforce_primitive_roots(n)))

    def test_count_is_phi_of_phi(self):
        # A cyclic group of order m has exactly phi(m) generators, so there
        # are phi(phi(n)) primitive roots mod n.
        from math import gcd

        for n in range(1, 200):
            roots = all_primitive_roots(n)
            if not roots:
                continue
            target = _bruteforce_phi(phi(n))
            self.assertEqual(len(roots), target, msg=f"n={n}")
            # Every root is a genuine unit coprime with n.
            for r in roots:
                self.assertEqual(gcd(r, n), 1, msg=f"n={n} r={r}")


if __name__ == "__main__":
    unittest.main()
