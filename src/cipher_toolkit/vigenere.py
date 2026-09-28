"""
Vigenere cipher

The Vigenere cipher applies a sequence of Caesar shifts determined by a keyword.
Each keyword letter selects a shift: ``A`` leaves the letter unchanged, ``B``
shifts by one, and so on. The keyword repeats, so the letter at position ``i``
is shifted by the ``i mod len(key)``-th keyword letter. Encrypting maps a
plaintext letter ``p`` (indexed 0-25) to a ciphertext letter ``(p + key) mod 26``,
and decryption reverses it as ``(c - key) mod 26``.

Cracking a Vigenere cipher has two stages. The first finds the key length:
with the true length ``L``, every ``L``-th ciphertext letter is shifted by the
same keyword letter, so each such "column" keeps its own English letter
distribution. Splitting the ciphertext into ``L`` columns and measuring each
column's index of coincidence reveals the
length. The candidate lengths are the ones whose columns best resemble English.
The second stage recovers each column's shift independently: for each position in
the keyword it tries every shift, decrypts the column, and keeps the shift whose
decrypted letters best fit the reference English distribution. The column shifts
together spell out the keyword.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence

import numpy as np

from .ciphers import Cipher, CipherConfig, CipherConfigImpl, InvalidParameterError
from .frequency import ELF_FREQUENCIES_LIST

__all__ = ["VigenereCipher", "vigenere"]

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ALPHA_LEN = len(ALPHABET)

# The longest key we are willing to search for. Beyond this the columns get too
# short to score reliably against English.
_MAX_KEY_LEN = 12

# Few letters below which column frequency scoring is unreliable, so the
# crack falls back to trying the short keys by hand instead.
_MIN_FOR_FREQUENCY = 50

# Index of coherence at or above which a split is treated as English rather than
# a random mix. English's uneven letter frequencies push this near 0.067, while
# an unstructured column sits near 0.038. Anything at or above this floor is a
# candidate key length.
_IC_THRESHOLD = 0.06


class Config(CipherConfigImpl):
    """
    Vigenere cipher parameters.

    Attributes
    key: str
        The keyword. Letters are upper-cased and anything non-alphabetic is
        dropped, so "secret" and "SECRET" encrypt identically. Each keyword
        letter becomes a column shift.
    """

    def __init__(self, key: str = "LEMON") -> None:
        if isinstance(key, dict):
            key = key.get("key", "LEMON")
        if not isinstance(key, str):
            raise InvalidParameterError("Vigenere key must be a string")
        cleaned = "".join(ch for ch in key.upper() if ch in ALPHABET)
        if not cleaned:
            raise InvalidParameterError("Vigenere key must contain at least one letter")
        super().__init__({"key": cleaned})


class VigenereCipher(Cipher):
    """Vigenere cipher implementation."""

    name = "Vigenere"
    description = "Apply keyword-driven Caesar shifts; crack via key-length analysis."

    def encrypt(self, plaintext: str, config: CipherConfig) -> str:
        cfg = config if isinstance(config, Config) else Config(config.parameters)
        key = cfg.get("key", "")
        return _shift(plaintext, key, +1)

    def decrypt(self, ciphertext: str, config: CipherConfig) -> str:
        cfg = config if isinstance(config, Config) else Config(config.parameters)
        key = cfg.get("key", "")
        return _shift(ciphertext, key, -1)

    def can_crack(self) -> bool:
        return True

    def crack(self, ciphertext: str) -> Sequence[tuple[str, CipherConfig]]:
        letters = [c for c in ciphertext.upper() if c in ALPHABET]
        text = "".join(letters)

        if not letters:
            return []
        if len(letters) < _MIN_FOR_FREQUENCY:
            # Too short to score columns reliably. Try the short keys directly.
            return self._brute_short(text)

        lengths = self._identify_key_lengths(text)
        best: list[tuple[str, CipherConfig, float]] = []
        for length in lengths:
            key, _ = self._recover_key(text, length)
            plaintext = self.decrypt(text, Config(key=key))
            score = _sum_squared_diff(_letter_counts(plaintext))
            best.append((plaintext, Config(key=key), score))
        best.sort(key=lambda c: c[2])
        return [(plaintext, config) for plaintext, config, _ in best]

    def _identify_key_lengths(self, text: str) -> list[int]:
        """
        Return candidate key lengths best first, starting with the true length.

        The key length is the smallest split whose average index of coherence
        jumps above the random baseline. At that length every column is
        shifted by one keyword letter, so each column keeps English's skewed
        distribution and its coherence rises toward English's. Multiples
        of the true length also lift the coherence, so among every length above
        baseline the smallest is the actual key. Any larger members are kept as
        fallbacks when the smallest split proves not to be English after all.
        """
        ic = {
            length: _avg_index_of_coherence(text, length)
            for length in range(1, _MAX_KEY_LEN + 1)
        }
        above = [length for length in ic if ic[length] > _IC_THRESHOLD]
        above.sort()
        primary = above[0] if above else 1
        candidates = [primary] + [length for length in above if length != primary]
        return candidates

    def _recover_key(self, text: str, length: int) -> tuple[str, list[int]]:
        """Recover the keyword of the given ``length`` and its column shifts."""
        columns = [[""] * len(text) for _ in range(length)]
        for index, letter in enumerate(text):
            columns[index % length][index // length] = letter
        shifts: list[int] = []
        for column in columns:
            column_text = "".join(column)
            best_shift = _best_shift_for_column(column_text)
            shifts.append(best_shift)
        key = "".join(ALPHABET[shift] for shift in shifts)
        return key, shifts

    def _brute_short(self, text: str) -> list[tuple[str, CipherConfig]]:
        """Try each short key length once, best score first."""
        results: list[tuple[str, CipherConfig, int]] = []
        for length in range(1, min(5, len(text)) + 1):
            key, _ = self._recover_key(text, length)
            plaintext = self.decrypt(text, Config(key=key))
            results.append(
                (
                    plaintext,
                    Config(key=key),
                    _sum_squared_diff(_letter_counts(plaintext)),
                )
            )
        results.sort(key=lambda c: c[2])
        return [(plaintext, config) for plaintext, config, _ in results]


def _shift(text: str, key: str, direction: int) -> str:
    """
    Apply the Vigenere ``key`` to ``text``.

    ``direction`` is +1 for encryption and -1 for decryption. Non-alphabet
    characters pass through untouched so the cipher leaves spaces and
    punctuation alone; the keyword wraps as it walks the alphabetic positions.
    """
    if not key:
        return text
    result = []
    key_index = 0
    for letter in text:
        upper = letter.upper()
        if upper not in ALPHABET:
            result.append(letter)
            continue
        base = ALPHABET.index(upper)
        shift = ALPHABET.index(key[key_index % len(key)])
        new_index = (base + direction * shift) % ALPHA_LEN
        new_letter = ALPHABET[new_index]
        result.append(new_letter.lower() if letter.islower() else new_letter)
        key_index += 1
    return "".join(result)


def _letter_counts(text: str) -> list[float]:
    """Return each letter's share of ``text`` as a 26-entry percentage list."""
    counts = Counter(c for c in text.upper() if c in ALPHABET)
    total = sum(counts.values())
    if total == 0:
        return [0.0] * ALPHA_LEN
    return [counts.get(letter, 0) * 100 / total for letter in ALPHABET]


def _best_shift_for_column(column_text: str) -> int:
    """
    Return the shift matching a ciphertext column by the dot-product method.

    For each candidate shift ``s`` (0-25) we build ``A_s``, the reference English
    distribution shifted by ``s`` (a ciphertext letter at index ``j`` decrypts to
    plaintext index ``(j - s) mod 26``), and take the dot product ``W . A_s`` with
    the column's own normalized frequency vector ``W``. The shift that maximizes
    this dot product is kept: the English distribution is skewed, so the largest
    product occurs when a column's tall letters line up with English's tall
    letters, which happens only at the true shift.
    """
    observed = _letter_counts(column_text)
    if not observed:
        return 0
    return max(
        range(ALPHA_LEN),
        key=lambda shift: np.dot(observed, _shifted_english(shift)),
    )


def _shifted_english(shift: int) -> list[float]:
    """
    Return the reference English distribution a ciphertext column would show if
    the key letter for its column shifts plaintext by ``shift``.

    Vigenere encryption maps plaintext index ``p`` to ciphertext index
    ``(p + shift) mod 26``. So a column encrypted with ``shift`` has its English
    percentage at plaintext index ``p`` sitting at ciphertext index
    ``(p + shift) mod 26``. We place each English percentage at that ciphertext
    position. The result ``A_shift`` satisfies ``A_shift[c] = E[(c - shift) mod
    26]``, so dotting the ciphertext column against it is the same as decrypting
    by ``shift`` and comparing to plain English.
    """
    shifted = [0.0] * ALPHA_LEN
    for plaintext_index, percentage in enumerate(ELF_FREQUENCIES_LIST):
        shifted[(plaintext_index + shift) % ALPHA_LEN] = percentage
    return shifted


def _sum_squared_diff(observed: list[float]) -> float:
    """
    Return the sum of squared differences between ``observed`` and English.

    This measures how far a letter distribution is from English: it is zero only
    when the distribution exactly matches, and grows with every letter that sits
    too high or too low. It ranks the final candidate plaintexts, the per-column
    shift itself is chosen with the dot-product method instead.
    """
    expected = ELF_FREQUENCIES_LIST
    diff = np.array(observed) - np.array(expected)
    return float(np.sum(diff**2))


def _avg_index_of_coherence(text: str, length: int) -> float:
    """
    Return the average index of coherence across the ``length`` columns.

    Splitting the text into ``length`` columns and taking each column's index of
    coherence (the chance two random letters match) averages out per-column
    noise. The true key length keeps every column's shift constant, so each
    column's letters stay English-like and the average stays high; a wrong
    length scatters English across shifts and the average falls toward that of
    random text.
    """
    columns = [[] for _ in range(length)]
    for index, letter in enumerate(text):
        columns[index % length].append(letter)
    if not columns or any(len(column) < 2 for column in columns):
        return 0.0
    coherence = [_index_of_coherence(column) for column in columns]
    return sum(coherence) / len(coherence)


def _index_of_coherence(letters: Sequence[str]) -> float:
    """
    Return the index of coherence of ``letters``: the chance two random letters
    are equal.

    Counting each letter and summing the "choose two" pairs, then dividing by the
    total number of letter pairs, gives this match probability. English text
    scores around 0.067. Random text scores near 0.038.
    """
    total = len(letters)
    if total < 2:
        return 0.0
    counts = Counter(letters)
    matches = sum(count * (count - 1) for count in counts.values())
    return matches / (total * (total - 1))


# The instance the registry imports.
vigenere = VigenereCipher()
