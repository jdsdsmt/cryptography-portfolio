"""
Linear Diophantine equation solver.

Solves equations of the form  a*x + b*y = c  over the integers.

This isn't really a cipher (no alphabet to map) but it fits the toolkit's
``Cipher`` protocol, so the CLI treats it like one. ``encrypt`` and ``decrypt``
undo each other, and ``crack`` finds small solutions from the equation alone.

A solution exists only when ``gcd(a, b)`` divides ``c``. If one exists, there
are infinitely many, spread out along a line: once you have one solution
``(x0, y0)``, the others are  ``(x0, y0) + t * (b/g, -a/g)`` for any integer t.
``decrypt`` uses ``extended_gcd`` to find one solution, then scales it up.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

from .ciphers import Cipher, CipherConfig, CipherConfigImpl, InvalidParameterError
from .cryptomath import extended_gcd

__all__ = ["DiophantineCipher", "diophantine"]

# An equation like "3x + 5y = 29". Each variable has an optional coefficient
# (so "x" means +1, "-x" means -1), the sign attaching to its own digits. The
# sign before the second term is part of that coefficient, so a space between
# the sign and its digit is tolerated: "3x - 4y" parses b as -4 while
# "3x + 5y" parses b as +5.
_EQUATION_RE = re.compile(
    r"""
    ^\s*
    (?P<a>[-+]?\d*)\s*[xX]\s*
    (?P<b>[-+]?\s*\d*)\s*[yY]\s*
    =\s*
    (?P<c>[+-]?\d+)
    $
    """,
    re.VERBOSE,
)


class Config(CipherConfigImpl):
    """
    Diophantine equation parameters.

    Attributes
    a: int
        The coefficient of ``x`` in  a*x + b*y = c .
    b: int
        The coefficient of ``y`` in  a*x + b*y = c .
    """

    def __init__(self, a: int = 2, b: int = 3) -> None:
        if isinstance(a, dict):
            # Allow the dict form, Config({"a": .., "b": ..}), matching the
            # other ciphers: pull both coefficients out of the one mapping.
            params = a
            a = params.get("a", 2)
            b = params.get("b", 3)
        if not isinstance(a, int) or isinstance(a, bool):
            raise InvalidParameterError("Diophantine 'a' must be an integer")
        if not isinstance(b, int) or isinstance(b, bool):
            raise InvalidParameterError("Diophantine 'b' must be an integer")
        if a == 0 and b == 0:
            raise InvalidParameterError("both coefficients cannot be zero")
        super().__init__({"a": a, "b": b})


class DiophantineCipher(Cipher):
    """Linear Diophantine equation solver (a*x + b*y = c over the integers)."""

    name = "Diophantine"
    description = "Solve linear Diophantine equations a*x + b*y = c over the integers."

    def encrypt(self, plaintext: str, config: CipherConfig) -> str:
        """Return the equation  a*x + b*y = c  satisfied by the point (x, y).

        ``plaintext`` encodes a solution point as ``"x, y"``. The constant
        ``c`` is what that point would produce, so ``encrypt`` builds the
        equation a known point solves.
        """
        a = config.get("a", 0)
        b = config.get("b", 0)
        x, y = _parse_point(plaintext)
        c = a * x + b * y
        return _format_equation(a, b, c)

    def decrypt(self, plaintext: str, config: CipherConfig) -> str:
        """Solve  a*x + b*y = c  and return the particular and general solution.

        ``plaintext`` is the constant ``c``. The solution is returned as a
        short two-line report carrying the particular solution and the full
        one-parameter family it generates.
        """
        a = config.get("a", 0)
        b = config.get("b", 0)
        c = _parse_constant(plaintext)
        x0, y0, g = _solve(a, b, c)
        return _report(a, b, c, x0, y0, g)

    # Allow this solver to be cracked from an equation string alone.
    def can_crack(self) -> bool:
        return True

    def crack(self, ciphertext: str) -> Sequence[tuple[str, CipherConfig]]:
        """Recover small candidate solutions from an equation string.

        The equation (``"3x + 5y = 29"``) supplies ``a``, ``b`` and ``c``
        itself, so no key is needed. Each candidate is a small integer point
        that satisfies the equation, ordered from the simplest outward.
        """
        a, b, c = _parse_equation(ciphertext)
        if a == 0 and b == 0:
            if c != 0:
                raise InvalidParameterError("0x + 0y = c has no solutions")
            # Every point solves 0 = 0; hand back a few trivial ones. The
            # config is degenerate (both coefficients 0), so build it directly
            # rather than through Config, whose constructor rejects both-zero.
            empty = CipherConfigImpl({"a": 0, "b": 0})
            return [("0, 0", empty), ("1, 0", empty)]
        if not _is_solvable(a, b, c):
            raise InvalidParameterError(f"{a}x + {b}y = {c} has no integer solutions")
        return [(point, Config(a=a, b=b)) for point in _candidate_solutions(a, b, c, 5)]


def _parse_point(text: str) -> tuple[int, int]:
    """Parse a solution point like ``"3, -5"`` into ``(x, y)``."""
    compact = text.strip().replace(" ", "")
    if "," not in compact:
        raise InvalidParameterError("a solution point must look like 'x, y'")
    left, right = compact.split(",", 1)
    try:
        return int(left), int(right)
    except ValueError:
        raise InvalidParameterError("solution coordinates must be integers")


def _parse_constant(text: str) -> int:
    """Parse the right-hand side constant ``c`` from the user's input."""
    try:
        return int(text.strip())
    except ValueError:
        raise InvalidParameterError("the constant c must be an integer")


def _parse_equation(text: str) -> tuple[int, int, int]:
    """Parse an equation string like ``"3x + 5y = 29"`` into ``(a, b, c)``."""
    match = _EQUATION_RE.search(text.strip())
    if not match:
        raise InvalidParameterError(
            "equation must look like 'a*x + b*y = c' (e.g. 3x + 5y = 29)"
        )
    a = _coeff(match.group("a"))
    b = _coeff(match.group("b"))
    try:
        c = int(match.group("c"))
    except ValueError:
        raise InvalidParameterError("constant after '=' must be an integer")
    return a, b, c


def _coeff(group: str | None) -> int:
    """Turn a captured coefficient group into an int.

    Handles a sign separated from its digits by whitespace (like "+ 5" or
    "- 4") by dropping the space. A bare sign counts as 1, so "x + y" works.
    """
    text = "".join((group or "").split())  # drop any space between sign and digits
    if text in ("", "+"):
        return 1
    if text == "-":
        return -1
    return int(text)


def _is_solvable(a: int, b: int, c: int) -> bool:
    """Whether  a*x + b*y = c  has an integer solution (Bezout's criterion)."""
    g = abs(extended_gcd(a, b)[0])
    if g == 0:  # a == 0 and b == 0
        return c == 0
    return c % g == 0


def _solve(a: int, b: int, c: int) -> tuple[int, int, int]:
    """Return ``(x0, y0, g)``: one particular solution and gcd(a, b).

    Raises ``InvalidParameterError`` when ``gcd(a, b)`` does not divide ``c``.
    """
    g, x, y = extended_gcd(a, b)
    if g < 0:  # keep the gcd positive so the scale below floors correctly
        g, x, y = -g, -x, -y
    if c % g != 0:
        raise InvalidParameterError(f"{a}x + {b}y = {c} has no integer solutions")
    scale = c // g
    return x * scale, y * scale, g


def _candidate_solutions(a: int, b: int, c: int, count: int) -> list[str]:
    """Brute force the ``count`` simplest integer points solving the equation.

    Tries every ``x`` in range and keeps ``y`` when it comes out an integer.
    Points are ordered by ``|x| + |y|`` so the smallest, most obvious ones
    come first (the brute-force analogue of the Affine crack).
    """
    found: set[tuple[int, int]] = set()
    for x in range(-50, 51):
        if b != 0:
            remainder = c - a * x
            if remainder % b == 0:
                found.add((x, remainder // b))
        elif a != 0 and c % a == 0 and x == c // a:
            # b == 0 collapses to a*x = c, so x is pinned and y is free.
            found.add((x, 0))
    ordered = sorted(found, key=lambda p: (abs(p[0]) + abs(p[1]), p))
    return [f"{x}, {y}" for x, y in ordered[:count]]


def _format_equation(a: int, b: int, c: int) -> str:
    """Render ``a*x + b*y = c`` with tidy coefficients (1 and -1 are slimmed)."""
    parts: list[str] = []
    for coeff, var in ((a, "x"), (b, "y")):
        if coeff == 0:
            continue
        magnitude = "" if abs(coeff) == 1 else str(abs(coeff))
        sign = "+" if coeff > 0 else "-"
        parts.append(f"{sign}{magnitude}{var}")
    left = " + ".join(parts) if parts else "0"
    left = left.removeprefix("+")
    return f"{left} = {c}"


def _signed(value: int) -> str:
    """Format ``value`` with an explicit plus or minus sign.

    No space is inserted between the sign and the digits so the output stays
    easy to round-trip: ``+5`` and ``-3`` parse back as integers cleanly.
    """
    return f"+{value}" if value >= 0 else f"-{abs(value)}"


def _report(a: int, b: int, c: int, x0: int, y0: int, g: int) -> str:
    """Build the two-line solve report: a solution plus the general family."""
    step_x = b // g
    step_y = -(a // g)
    return (
        f"Solution (x, y) = ({x0}, {y0})\n"
        f"General solution: x = {x0} {_signed(step_x)} t,  "
        f"y = {y0} {_signed(step_y)} t   (for any integer t)"
    )


# The instance the registry imports.
diophantine = DiophantineCipher()
