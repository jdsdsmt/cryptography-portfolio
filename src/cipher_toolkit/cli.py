"""Interactive command line interface for the cipher toolkit.

Run with ``uv run cipher-toolkit``. The flow is:

1. Select a cipher from the registered list.
2. Choose a mode: encrypt, decrypt, or crack.
3. Enter the message (or paste ciphertext).
4. Supply any cipher-specific keys.
5. See the result.

The CLI parses input and calls into the cipher registry, so the
cryptography itself lives in the cipher modules and is fully testable.
"""

from __future__ import annotations

import re
import sys
from collections.abc import Callable, Sequence

from . import affine, caesar, diophantine, vigenere
from .ciphers import (
    Cipher,
    CipherConfig,
    CipherConfigImpl,
    CrackError,
    InvalidParameterError,
    registry,
)
from .cryptomath import (
    extended_gcd,
    find_mod_inverse,
    gcd,
    prime_factors,
    primitive_root,
    solve_crt,
)
from .register import register_all

# Only these ciphers operate purely on the character alphabet so the CLI can
# strip everything else and group the alphabet ciphertext. Other ciphers
# handle their own filtering and formatting and must not rely on these helpers.
_ALPHA_CIPHERS = {"Caesar", "Affine"}
_LETTERS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")


def _whitelist(text: str) -> str:
    """Drop anything outside the alphabet."""
    return "".join(ch for ch in text if ch in _LETTERS)


def _group(text: str, size: int = 5) -> str:
    """Split ``text`` into space-separated chunks of ``size`` characters."""
    return " ".join(text[i : i + size] for i in range(0, len(text), size))


def _prompt(message: str) -> str:
    return input(message).strip()


def _read_message() -> str:
    return input("Enter message: ")


def _pick_cipher() -> Cipher | None:
    """Pick a cipher, or return ``None`` for the top level math tools."""
    print("\nAvailable ciphers:")
    for index, name in enumerate(registry.names(), start=1):
        print(f"  {index}. {name}")
    print("  0. Math tools")
    while True:
        choice = _prompt("Select a cipher (number): ")
        if not choice.isdigit():
            print("Please enter a number.")
            continue
        index = int(choice)
        if index == 0:
            return None
        if 1 <= index <= len(registry.names()):
            return registry.get(registry.names()[index - 1])
        print(f"Enter a number between 1 and {len(registry.names())}.")


def _pick_mode(cipher: Cipher) -> str:
    modes = ["encrypt", "decrypt"]
    if cipher.can_crack():
        modes.append("crack")
    print("\nChoose a mode:")
    for index, mode in enumerate(modes, start=1):
        print(f"  {index}. {mode}")
    while True:
        choice = _prompt("Select a mode (number): ")
        if not choice.isdigit():
            print("Please enter a number.")
            continue
        index = int(choice)
        if 1 <= index <= len(modes):
            return modes[index - 1]
        print(f"Enter a number between 1 and {len(modes)}.")


def _make_config(cipher: Cipher, mode: str) -> CipherConfig:
    """Build a cipher's config from key prompts, or use defaults."""
    params: dict[str, object] = {}

    if cipher is caesar.caesar:
        raw = _prompt("Caesar key (shift 0-25, blank = 3): ")
        params["key"] = int(raw) if raw else 3

    elif cipher is affine.affine:
        params["a"] = int(_prompt("Affine 'a' (coprime with 26, blank = 5): ") or 5)
        params["b"] = int(_prompt("Affine 'b' (blank = 8): ") or 8)

    elif cipher is diophantine.diophantine:
        # The coefficients a and b are part of the equation in every mode that
        # uses them. Crack supplies them from the equation string instead.
        if mode in ("decrypt", "encrypt"):
            params["a"] = int(_prompt("Diophantine 'a' (blank = 2): ") or 2)
            params["b"] = int(_prompt("Diophantine 'b' (blank = 3): ") or 3)

    elif cipher is vigenere.vigenere:
        params["key"] = _prompt("Vigenere key (blank = LEMON): ") or "LEMON"

    return CipherConfigImpl(params)


def _run(cipher: Cipher, mode: str) -> None:
    """Read a message, normalize it, and run one cipher.

    Caesar and Affine are alphabet ciphers, so the CLI whitelists them and
    groups their output. Caesar, Affine, and Vigenere also get case normalization
    (upper for encrypt, lower for decrypt) so the cipher sees uniform input.
    Every other cipher is left exactly as entered, keeping its own characters and
    formatting.
    """
    raw = _read_message()
    is_alpha = cipher.name in _ALPHA_CIPHERS
    is_vigenere = cipher is vigenere.vigenere
    is_encrypt = mode == "encrypt"
    normalize_case = is_alpha or is_vigenere

    # Crack. The alphabet ciphers score on the lowercased stream.
    # The rest keep their text so recovered plaintext still reads naturally.
    if mode == "crack":
        source = _whitelist(raw.lower()) if is_alpha else raw
        candidates = cipher.crack(source)
        if not candidates:
            print("\nNo plaintext could be cracked.")
            return
        print(f"\nCracked '{cipher.name}' candidates:")
        for plaintext, config in candidates:
            if is_alpha:
                print(f"  shift={config.parameters} -> {_group(plaintext.upper())}")
            elif is_vigenere:
                print(f"  key={config.parameters['key']} -> {plaintext}")
            else:
                print(f"  {config.parameters} -> {plaintext}")
        return

    plaintext = (raw.upper() if is_encrypt else raw.lower()) if normalize_case else raw
    config = _make_config(cipher, mode)
    try:
        result = (
            cipher.encrypt(plaintext, config)
            if is_encrypt
            else cipher.decrypt(plaintext, config)
        )
    except InvalidParameterError as exc:
        print(f"\nInvalid parameter: {exc}")
        return
    verb = "Encrypted" if is_encrypt else "Decrypted"
    shown = result.lower() if is_encrypt else result.upper()
    if is_alpha:
        shown = _group(shown)
    print(f"\n{verb} result: {shown}")


def _run_diophantine(cipher: Cipher, mode: str) -> None:
    """Handle the Diophantine solver, whose inputs are points and equations.

    This cipher does not play by the alphabet rules, so it gets its own branch.
    The message the user enters plays a different role depending on the mode:
    a solution point for encrypt, the constant for decrypt, and a full equation
    for crack.
    """
    if mode == "crack":
        try:
            candidates = cipher.crack(_read_message())
        except InvalidParameterError as exc:
            print(f"\nInvalid parameter: {exc}")
            return
        if not candidates:
            print("\nNo solution could be found.")
            return
        print("\nDiophantine solution points (smallest first):")
        for point, _config in candidates:
            print(f"  {point}")
        return

    if mode == "encrypt":
        # "x, y" -> "a*x + b*y = c". The constant is derived, so the
        # coefficients are enough and we prompt for them as the key.
        config = _make_config(cipher, mode)
        try:
            result = cipher.encrypt(_read_message(), config)
        except InvalidParameterError as exc:
            print(f"\nInvalid parameter: {exc}")
            return
        print(f"\nEquation result: {result}")
        return

    # "c" -> the particular and general solution.
    config = _make_config(cipher, mode)
    try:
        result = cipher.decrypt(_read_message(), config)
    except InvalidParameterError as exc:
        print(f"\nInvalid parameter: {exc}")
        return
    print(f"\n{result}")


# A regular expression splitting the raw entry of cryptomath tools on commas,
# semicolons, or runs of whitespace, so an entry like "12, 8" works
# and a tuple such as "(1, 2, 3)" pasted from a previous run parses cleanly.
_SPLIT_RE = re.compile(r"[\s,;()]+")

# The cryptomath tools, in menu order: (name, description, arity). The arity is
# how many integer arguments the tool takes, which is also how many the menu
# prompts for. solve_crt takes an even number, entered interleaved as
# "n1 mod m1 n2 mod m2", so its arity reflects that convention.
_MATH_TOOLS: list[tuple[str, str, int]] = [
    ("gcd", "greatest common divisor of two integers", 2),
    ("extended_gcd", "Bezout coefficients (g, x, y) for gcd", 2),
    ("find_mod_inverse", "modular inverse of a mod n (a must be coprime)", 2),
    ("prime_factors", "prime factorization of an integer", 1),
    ("primitive_root", "is a a primitive root mod p? (p prime)", 2),
    (
        "solve_crt",
        "Chinese Remainder Theorem solution (enter as n1 mod m1 n2 mod m2)",
        4,
    ),
]

# Backends for each tool, given the parsed integer list. solve_crt's values are
# entered interleaved as n1 mod m1 n2 mod m2, so its lambda reads the even
# positions as residues and the odd positions as moduli.
_MATH_BACKENDS: dict[str, Callable[[list[int]], str]] = {
    "gcd": lambda vs: f"gcd({vs[0]}, {vs[1]}) = {gcd(vs[0], vs[1])}",
    "extended_gcd": lambda vs: (
        f"extended_gcd({vs[0]}, {vs[1]}) = {extended_gcd(vs[0], vs[1])}"
    ),
    "find_mod_inverse": lambda vs: (
        f"modular inverse of {vs[0]} mod {vs[1]} = {find_mod_inverse(vs[0], vs[1])}"
    ),
    "prime_factors": lambda vs: f"prime factors of {vs[0]} = {prime_factors(vs[0])}",
    "primitive_root": lambda vs: (
        f"{vs[0]} is "
        f"{'a primitive' if primitive_root(vs[0], vs[1]) else 'not a primitive'} "
        f"root mod {vs[1]}"
    ),
    "solve_crt": lambda vs: (
        "solve_crt("
        + ", ".join(f"{vs[i]} mod {vs[i + 1]}" for i in range(0, len(vs), 2))
        + ")"
        " = " + str(solve_crt(vs[0::2], vs[1::2]))
    ),
}


def _parse_ints(text: str, n: int) -> list[int]:
    """Return exactly ``n`` integers from ``text``.

    Splits on commas, semicolons, or whitespace and strips parentheses, so an
    entry like "12, 8" works and a tuple such as "(1, 2, 3)" pasted
    from a previous run parses cleanly. Reprompts until the
    count and the values are both usable, so one bad line doesnt crashes the tool.
    """
    tokens = [tok for tok in _SPLIT_RE.split(text) if tok]
    while len(tokens) != n:
        tokens = [
            tok for tok in _SPLIT_RE.split(_prompt(f"Enter {n} integer(s): ")) if tok
        ]
    try:
        return [int(tok) for tok in tokens]
    except ValueError:
        print("Please enter integers.")
        return _parse_ints(text, n)


def _run_math_tool(name: str) -> None:
    """Prompt for the arguments of one cryptomath tool and print its result.

    ``name`` is a tool key from ``_MATH_TOOLS``. Errors are surfaced through the
    tool's own ``ValueError`` (raised inside gcd, the inverse, CRT, etc.), which
    the caller's ``except`` block renders as a message rather than a traceback.
    """
    _, _, arity = next(t for t in _MATH_TOOLS if t[0] == name)
    try:
        values = _parse_ints("", arity)
        print(f"\n{_MATH_BACKENDS[name](values)}")
    except ValueError as exc:
        print(f"\n{exc}")


def _run_math_menu() -> None:
    """Walk through the cryptomath tools, one per pass, until the user quits."""
    while True:
        print("\n=== Math tools ===")
        for index, (_name, description, _arity) in enumerate(_MATH_TOOLS, start=1):
            print(f"  {index}. {description}")
        print("  0. Back")
        choice = _prompt("Select a tool (number): ")
        if not choice.isdigit():
            print("Please enter a number.")
            continue
        index = int(choice)
        if index == 0:
            return
        if 1 <= index <= len(_MATH_TOOLS):
            name, _description, _arity = _MATH_TOOLS[index - 1]
            _run_math_tool(name)


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point. Returns a process exit code."""
    register_all()
    while True:
        print("=== Cipher Toolkit ===")
        try:
            cipher = _pick_cipher()
            if cipher is None:
                _run_math_menu()
                continue
            mode = _pick_mode(cipher)
            if cipher is diophantine.diophantine:
                _run_diophantine(cipher, mode)
            else:
                _run(cipher, mode)
        except (EOFError, KeyboardInterrupt):
            print("\nBye!")
            return 0
        except InvalidParameterError as exc:
            print(f"\nError: {exc}")
            return 1
        print("\nReturn to the main menu? (y/N): ")
        if _prompt("").lower() not in ("y", "yes"):
            return 0


if __name__ == "__main__":
    sys.exit(main())
