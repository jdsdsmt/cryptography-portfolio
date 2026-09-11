"""
Affine cipher — encrypts each letter as ``(ax + b) mod 26``.

The alphabet is mapped with a multiplicative key ``a`` and an additive key ``b``.
``a`` must be coprime with 26 for the cipher to be invertible. Cracking solves
the key from a frequency analysis: the two most common ciphertext letters are
matched to the two most common English letters, which gives a 2x2 system that
is solved for ``a`` then ``b``. When the ranking is not decisive the brute
force over the full key space is used instead.
"""

from __future__ import annotations

from collections import Counter
from itertools import permutations
from collections.abc import Sequence

from .ciphers import Cipher, CipherConfig, CipherConfigImpl, InvalidParameterError
from .cryptomath import find_mod_inverse, gcd

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ALPHA_LEN = len(ALPHABET)

# The most common letters of English, used by the frequency attack.
E = ALPHABET.index("E")
T = ALPHABET.index("T")
A = ALPHABET.index("A")
O = ALPHABET.index("O")


# Multipliers coprime with 26 (the only ones that give invertible mappings).
CO_PRIMES = [a for a in range(1, ALPHA_LEN) if gcd(a, ALPHA_LEN) == 1]


class Config(CipherConfigImpl):
    """
    Affine cipher parameters.

    Attributes
    a: int
        Multiplicative key. Must be coprime with 26.
    b: int
        Additive key. Normalized into 0-25.
    """

    def __init__(self, a: int = 5, b: int = 8) -> None:
        if isinstance(a, dict):
            params = a
            a = params.get("a", 5)
            b = params.get("b", 8)
        if not isinstance(a, int) or isinstance(a, bool):
            raise InvalidParameterError("Affine 'a' must be an integer")
        if not isinstance(b, int) or isinstance(b, bool):
            raise InvalidParameterError("Affine 'b' must be an integer")
        if a % ALPHA_LEN not in CO_PRIMES:
            raise InvalidParameterError(
                f"Affine 'a' ({a}) must be coprime with 26; valid values: {CO_PRIMES}"
            )
        super().__init__({"a": a % ALPHA_LEN, "b": b % ALPHA_LEN})


class AffineCipher(Cipher):
    """Affine cipher implementation."""

    name = "Affine"
    description = "Map each letter as (ax + b) mod 26; 'a' must be coprime with 26."

    def encrypt(self, plaintext: str, config: CipherConfig) -> str:
        cfg = config if isinstance(config, Config) else Config(config.parameters)
        # Set our configurations
        a = cfg.get("a", 1)
        b = cfg.get("b", 0)
        # Normalize our mapping
        upper = "".join(ALPHABET[(a * i + b) % ALPHA_LEN] for i in range(ALPHA_LEN))
        # Create a translation table
        table = str.maketrans(
            ALPHABET + ALPHABET.lower(),
            upper + upper.lower(),
        )
        return plaintext.translate(table)

    def decrypt(self, ciphertext: str, config: CipherConfig) -> str:
        cfg = config if isinstance(config, Config) else Config(config.parameters)
        # Set our configurations
        a = cfg.get("a", 1)
        b = cfg.get("b", 0)
        # Find the inverse of our alpha
        a_inv = find_mod_inverse(a, ALPHA_LEN)
        # Normalize our mapping
        lower = "".join(
            ALPHABET[(a_inv * (i - b)) % ALPHA_LEN] for i in range(ALPHA_LEN)
        )
        # Create a translation table
        table = str.maketrans(
            ALPHABET + ALPHABET.lower(),
            lower + lower.lower(),
        )
        return ciphertext.translate(table)

    # Allow this cipher to be cracked
    def can_crack(self) -> bool:
        return True

    def crack(self, ciphertext: str) -> Sequence[tuple[str, CipherConfig]]:
        # Prefer the frequency attack where we map the most common ciphertext
        # letters onto candidate English letters and solve the resulting
        # linear system for (a, b). Each valid pair yields a candidate key.
        # The fallback brute force is used when no pair is decisive.
        candidates = self._frequency_attack(ciphertext)
        if candidates:
            plaintext = self.decrypt(ciphertext, candidates[0])
            return [(plaintext, candidates[0])]
        return self._brute_force(ciphertext)

    def _frequency_attack(self, ciphertext: str) -> list[CipherConfig]:
        # Recover candidate keys from a frequency analysis. Take the three most
        # common ciphertext letters (ignoring non-alphabet ones) and try mapping
        # them onto the three most common English letters. Each mapping gives a
        # 2x2 system of encrypting equations. Solving naively means dividing by
        # the plaintext gap, but that gap can be non-invertible mod 26 (as it is
        # between E and A), so instead iterate the co-prime values of ``a``,
        # derive ``b`` from the first equation, and keep the candidate only when
        # it also satisfies the other two equations. We require three
        # equations rather than two so spurious mappings that satisfy one pair
        # but not a third are weeded out.
        alpha = [c.upper() for c in ciphertext if c.upper() in ALPHABET]
        letters = [c for c, _ in Counter(alpha).most_common(3)]
        if len(letters) < 3:
            return []
        # Ciphertext indices of the three most common letters (these are the y
        # values in the encrypting equation y = a*x + b mod 26).
        cy = [ALPHABET.index(c) for c in letters]
        # The three most common English letters, tried as target-letter
        # triples. These are the plaintext x values. The attack succeeds as
        # long as the ciphertext's most frequent letters match some ordering
        # of these.
        targets = [E, T, A, O]
        candidates: list[CipherConfig] = []
        for x1, x2, x3 in permutations(targets, 3):
            if len({x1, x2, x3}) < 3:
                continue  # need three distinct target letters
            for a in CO_PRIMES:
                b = (cy[0] - a * x1) % ALPHA_LEN
                if (a * x2 + b) % ALPHA_LEN == cy[1] and (a * x3 + b) % ALPHA_LEN == cy[2]:
                    candidate = Config(a=a, b=b)
                    if candidate not in candidates:
                        candidates.append(candidate)
                    break
        return candidates

    def _brute_force(self, ciphertext: str) -> list[tuple[str, CipherConfig]]:
        # Brute force the full valid key space
        results: list[tuple[str, CipherConfig]] = []
        for a in CO_PRIMES:
            for b in range(ALPHA_LEN):
                results.append(
                    (self.decrypt(ciphertext, Config(a=a, b=b)), Config(a=a, b=b))
                )
        return results


# The instance the registry imports.
affine = AffineCipher()
