"""Tests for the Vigenere cipher.

Covers the round-trip (encrypt -> decrypt recovers the plaintext) and the
key-recovery path: crack() should identify the key length and recover each of
a handful of keywords from English prose.
"""

import unittest

from src.cipher_toolkit import vigenere
from src.cipher_toolkit.ciphers import InvalidParameterError

TEXT = (
    "It is a truth universally acknowledged that a single man in possession of "
    "a good fortune must be in want of a wife. However little known the feelings "
    "or views of such a man may be on his first entering a neighbourhood this "
    "truth is so well fixed in the minds of the surrounding families that he is "
    "considered the rightful property of some one or other of their daughters."
)


class TestVigenere(unittest.TestCase):
    def test_encrypt_roundtrip(self):
        cipher = vigenere.vigenere
        for key in ("LEMON", "SECRET", "MATH", "a"):
            config = vigenere.Config(key=key)
            ciphertext = cipher.encrypt(TEXT, config)
            recovered = cipher.decrypt(ciphertext, config)
            self.assertEqual(recovered, TEXT)

    def test_encrypt_is_deterministic(self):
        config = vigenere.Config(key="LEMON")
        self.assertEqual(vigenere.vigenere.encrypt(TEXT, config), vigenere.vigenere.encrypt(TEXT, config))

    def test_encrypt_uses_different_shifts_per_letter(self):
        # Vigenere shifts each letter by the corresponding keyword letter, so
        # the plaintext and ciphertext should differ at positions where the
        # keyword letter is not 'A'/'a'.
        config = vigenere.Config(key="LEMON")
        ciphertext = vigenere.vigenere.encrypt(TEXT, config)
        self.assertNotEqual(ciphertext, TEXT)

    def test_crack_recovers_keyword(self):
        cipher = vigenere.vigenere
        for key in ("LEMON", "SECRET", "MATH"):
            config = vigenere.Config(key=key)
            ciphertext = cipher.encrypt(TEXT, config)
            candidates = cipher.crack(ciphertext)
            self.assertTrue(candidates)
            best_key = candidates[0][1].parameters["key"]
            self.assertEqual(best_key.upper(), key.upper())

    def test_crack_returns_candidates_ordered_best_first(self):
        cipher = vigenere.vigenere
        config = vigenere.Config(key="LEMON")
        ciphertext = cipher.encrypt(TEXT, config)
        candidates = cipher.crack(ciphertext)
        best_key = candidates[0][1].parameters["key"]
        self.assertEqual(best_key.upper(), "LEMON")
        self.assertNotEqual(candidates[0][0], TEXT[:10].lower())

    def test_invalid_key(self):
        with self.assertRaises(InvalidParameterError):
            vigenere.vigenere.encrypt(TEXT, vigenere.Config(key="123 !"))


if __name__ == "__main__":
    unittest.main()
