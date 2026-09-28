"""
Caesar cipher.

Each letter is shifted by a fixed amount (``key``) within the alphabet. The
same shift in reverse recovers the plaintext.

Cracking works because a Caesar key is just a shift, so every possible
plaintext is the ciphertext rotated by some amount. We score each of the 26
rotations against the normal English letter frequencies and return the best
match. With one letter or fewer we can't compare distributions, so every shift
is shown instead.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence

from .ciphers import Cipher, CipherConfig, CipherConfigImpl, InvalidParameterError
from .frequency import ELF_FREQUENCIES

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ALPHA_LEN = len(ALPHABET)


class Config(CipherConfigImpl):
    """
    Caesar cipher parameters.

    Attributes
    key: int
        The shift amount (0-25). Negative and out-of-range values are
        normalized into that range.
    """

    def __init__(self, key: int = 3) -> None:
        if isinstance(key, dict):
            key = key.get("key", 3)
        if not isinstance(key, int) or isinstance(key, bool):
            raise InvalidParameterError("Caesar key must be an integer")
        super().__init__({"key": key % ALPHA_LEN})


class CaesarCipher(Cipher):
    """Caesar cipher implementation."""

    name = "Caesar"
    description = "Shift each letter by a fixed amount within the alphabet."

    def encrypt(self, plaintext: str, config: CipherConfig) -> str:
        cfg = config if isinstance(config, Config) else Config(config.parameters)
        shift = cfg.get("key", 0)
        return self._shift(plaintext, shift)

    def decrypt(self, ciphertext: str, config: CipherConfig) -> str:
        cfg = config if isinstance(config, Config) else Config(config.parameters)
        shift = cfg.get("key", 0)
        return self._shift(ciphertext, -shift)

    @staticmethod
    def _shift(text: str, shift: int) -> str:
        shift %= ALPHA_LEN
        shifted = ALPHABET[shift:] + ALPHABET[:shift]
        table = str.maketrans(
            ALPHABET + ALPHABET.lower(),
            shifted + shifted.lower(),
        )
        return text.translate(table)

    def can_crack(self) -> bool:
        return True

    def crack(self, ciphertext: str) -> Sequence[tuple[str, CipherConfig]]:
        # A Caesar key is a shift, so every plaintext is the ciphertext
        # rotated by some amount. Score each rotation against the reference
        # English letter distribution and return the best match. A single letter
        # or fewer is not enough to compare distributions, so show all shifts in
        # that case.
        counts = Counter(c for c in ciphertext.upper() if c in ALPHABET)
        if len(counts) < 2:
            return [
                (self._shift(ciphertext, -s), Config(key=s)) for s in range(ALPHA_LEN)
            ]
        best_shift = _shift_scores(counts)
        return [(self._shift(ciphertext, -best_shift), Config(key=best_shift))]


def _shift_scores(counts: Counter[str]) -> int:
    """
    Return the Caesar ``shift`` whose rotation best matches English.

    We compare the letter distribution of each rotated plaintext against the
    normal English frequencies and pick the shift that gives the smallest
    difference. The best match is the rotation closest to real English.
    """
    observed = [counts.get(letter, 0) for letter in ALPHABET]
    expected = [ELF_FREQUENCIES[letter] for letter in ALPHABET]
    return min(
        range(ALPHA_LEN),
        key=lambda shift: sum(
            (observed[(i + shift) % ALPHA_LEN] - expected[i]) ** 2
            for i in range(ALPHA_LEN)
        ),
    )


# The instance the registry imports.
caesar = CaesarCipher()
