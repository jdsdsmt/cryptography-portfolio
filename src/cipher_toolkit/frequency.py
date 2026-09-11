"""
Frequency analysis of a text.

This module is not a cipher. It is a utility that turns a string of text into
a table of how often each character appears.

Theory
Letter frequencies are a statistical fingerprint of a language. In English the
letter ``e`` is by far the most common, followed by ``t``, ``a``, ``o``, ``i``,
``n``, and ``s``. Their exact proportions vary with the text, but the overall
ranking is stable enough that a ciphertext whose letter counts line up with the
expected ranking is a strong hint that it hides English rather than random noise.

To read a frequency table you first fold everything to one case so that ``A``
and ``a`` are counted together, then count every character and divide by the
total number of characters. The result is the fraction of the text that each
character makes up.

"""

from collections import Counter

__all__ = ["ELF_FREQUENCIES", "analyze_frequency"]

# English letter frequencies, the reference distribution a ciphertext is
# compared against when cracking. Keys are upper-case letters ordered from
# most to least frequent; values are the percentage of the text each letter
# makes up, taken from the corpus this analysis was measured on. Reference the
# table with ``frequency.ELF_FREQUENCIES``.
ELF_FREQUENCIES: dict[str, float] = {
    "E": 12.02,
    "T": 9.10,
    "A": 8.12,
    "O": 7.68,
    "I": 7.31,
    "N": 6.95,
    "S": 6.28,
    "R": 6.02,
    "H": 5.92,
    "D": 4.32,
    "L": 3.98,
    "U": 2.88,
    "C": 2.71,
    "M": 2.61,
    "F": 2.30,
    "Y": 2.11,
    "W": 2.09,
    "G": 2.03,
    "P": 1.82,
    "B": 1.49,
    "V": 1.11,
    "K": 0.69,
    "X": 0.17,
    "Q": 0.11,
    "J": 0.10,
    "Z": 0.07,
}


def analyze_frequency(text: str) -> dict[str, float]:
    """
    Return how often each character appears in ``text`` as a fraction of the
    total.

    The comparison is case-insensitive so ``A`` and ``a`` are tallied together.
    Every character counts. The returned dictionary is ordered from the most frequent character
    to the least, which is how the table is normally read when cracking a cipher.

    Theory
    Dividing a character's count by the total gives its fraction of the text.
    That fraction is what the theory of letter frequencies predicts should
    match the expected distribution for a language, like English's.

    Parameters
    text:
        The string to analyze. It is folded to lowercase and every character is tallied.

    Returns
    dict from str to float
        A mapping of each distinct lowercased character to the fraction of
        the text it makes up. The dictionary is sorted with the most frequent
        character first. An empty ``text`` comes back as an empty ``dict``,
        so there is no division by zero.

    """
    folded = text.lower()
    if not folded:
        return {}
    counts = Counter(folded)
    total = len(folded)
    # Sort by descending frequency so the table leads with the most common
    # characters, which is how it is used when comparing against a language.
    return {char: count / total for char, count in counts.most_common()}
