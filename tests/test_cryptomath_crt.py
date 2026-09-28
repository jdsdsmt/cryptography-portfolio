"""
Unit tests for solve_crt, the Chinese Remainder Theorem in cryptomath.

These tests follow our usual style (import the function and assert on the
result). They use the standard-library ``unittest`` so no new dependency needs
to be installed, run them with ``uv run python -m unittest`` from the project
root.
"""

import unittest

from src.cipher_toolkit.cryptomath import find_mod_inverse, gcd, solve_crt


def all_residues_match(x, residues, moduli):
    """Whether ``x`` satisfies every congruence in the system."""
    return all(x % n == r % n for r, n in zip(residues, moduli))


class SolveCrtBasicTests(unittest.TestCase):
    def test_classic_example(self):
        # x = 2 (mod 3), 3 (mod 5), 2 (mod 7): the classic puzzle.
        x, m = solve_crt([2, 3, 2], [3, 5, 7])
        self.assertEqual(m, 105)
        self.assertEqual(x, 23)
        self.assertTrue(all_residues_match(x, [2, 3, 2], [3, 5, 7]))

    def test_two_moduli(self):
        # x = 2 (mod 3), 3 (mod 4)
        x, m = solve_crt([2, 3], [3, 4])
        self.assertEqual(m, 12)
        self.assertEqual(x, 11)

    def test_moduli_are_product(self):
        x, m = solve_crt([0, 1, 1], [2, 3, 5])
        self.assertEqual(m, 30)

    def test_result_in_canonical_range(self):
        x, m = solve_crt([2, 3, 2], [3, 5, 7])
        self.assertTrue(0 <= x < m)

    def test_solution_is_unique_modulo_product(self):
        # Every integer satisfying the system is congruent to x modulo m, so
        # exactly one solution lives in each run of m consecutive integers.
        residues, moduli = [2, 3, 2], [3, 5, 7]
        x, m = solve_crt(residues, moduli)
        # Scan a wide window; collect every integer that hits all residues.
        matches = [
            cand
            for cand in range(-10 * m, 11 * m)
            if all_residues_match(cand, residues, moduli)
        ]
        # Every match is congruent to x modulo m, which is the uniqueness
        # claim, so
        # they must all land in the single class of x.
        for candidate in matches:
            self.assertEqual((candidate - x) % m, 0)
        # Within one window of length m there is exactly one match: x itself.
        window = list(range(x, x + m))
        self.assertEqual(
            [c for c in window if all_residues_match(c, residues, moduli)], [x]
        )

    def test_all_zero(self):
        x, m = solve_crt([0, 0, 0], [3, 5, 7])
        self.assertEqual(x, 0)
        self.assertEqual(m, 105)

    def test_single_modulus(self):
        x, m = solve_crt([5], [7])
        self.assertEqual((x, m), (5, 7))


class SolveCrtErrorTests(unittest.TestCase):
    def test_empty_moduli_raises(self):
        with self.assertRaises(ValueError):
            solve_crt([], [])

    def test_moduli_length_mismatch_raises(self):
        with self.assertRaises(ValueError):
            solve_crt([1, 2], [3])

    def test_non_coprime_moduli_raise(self):
        with self.assertRaises(ValueError):
            solve_crt([0, 0], [4, 6])

    def test_non_coprime_moduli_prime_factor(self):
        with self.assertRaises(ValueError):
            solve_crt([0, 0], [6, 9])

    def test_modulus_below_two_raises(self):
        with self.assertRaises(ValueError):
            solve_crt([0, 0], [3, 1])

    def test_modulus_below_two_single(self):
        with self.assertRaises(ValueError):
            solve_crt([0], [1])


class SolveCrtEdgeTests(unittest.TestCase):
    def test_large_values(self):
        x, m = solve_crt([1, 2, 3], [101, 103, 107])
        self.assertEqual(m, 101 * 103 * 107)
        self.assertTrue(all_residues_match(x, [1, 2, 3], [101, 103, 107]))
        self.assertTrue(0 <= x < m)

    def test_zero_and_one_residues(self):
        x, m = solve_crt([0, 1, 1], [2, 3, 5])
        self.assertTrue(all_residues_match(x, [0, 1, 1], [2, 3, 5]))
        self.assertEqual(x % 2, 0)
        self.assertEqual(x % 3, 1)
        self.assertEqual(x % 5, 1)


if __name__ == "__main__":
    unittest.main()
