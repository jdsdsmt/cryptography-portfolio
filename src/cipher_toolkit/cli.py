"""Interactive command-line interface for the cipher toolkit.

Run with ``uv run cipher-toolkit``. The flow is:

1. Select a cipher from the registered list.
2. Choose a mode: encrypt, decrypt, or crack.
3. Enter the message (or paste ciphertext).
4. Supply any cipher-specific keys.
5. See the result.

The CLI is thin: it parses input and calls into the cipher registry, so the
cryptography itself lives in the cipher modules and is fully testable.
"""

from __future__ import annotations

import sys
from collections.abc import Sequence

from . import affine, caesar
from .ciphers import (
    Cipher,
    CipherConfig,
    CipherConfigImpl,
    CrackError,
    InvalidParameterError,
    registry,
)
from .register import register_all

# Only these ciphers operate purely on the Latin alphabet, so the CLI can
# strip everything else and group the alphabet ciphertext. Other ciphers
# (e.g. ones that also encode digits or punctuation) handle their own
# filtering and formatting and must not rely on these helpers.
_ALPHA_CIPHERS = {"Caesar", "Affine"}
_LETTERS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")


def _whitelist(text: str) -> str:
    """Drop anything outside the alphabet (spaces, punctuation, digits)."""
    return "".join(ch for ch in text if ch in _LETTERS)


def _group(text: str, size: int = 5) -> str:
    """Split ``text`` into space-separated chunks of ``size`` characters."""
    return " ".join(text[i : i + size] for i in range(0, len(text), size))


def _prompt(message: str) -> str:
    return input(message).strip()


def _read_message() -> str:
    return input("Enter message: ")


def _pick_cipher() -> Cipher:
    print("\nAvailable ciphers:")
    for index, name in enumerate(registry.names(), start=1):
        print(f"  {index}. {name}")
    while True:
        choice = _prompt("Select a cipher (number): ")
        if not choice.isdigit():
            print("Please enter a number.")
            continue
        index = int(choice)
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


def _make_config(cipher: Cipher) -> CipherConfig:
    """Build a cipher's config from key prompts, or use defaults."""
    params: dict[str, object] = {}

    if cipher is caesar.caesar:
        raw = _prompt("Caesar key (shift 0-25, blank = 3): ")
        params["key"] = int(raw) if raw else 3

    elif cipher is affine.affine:
        params["a"] = int(_prompt("Affine 'a' (coprime with 26, blank = 5): ") or 5)
        params["b"] = int(_prompt("Affine 'b' (blank = 8): ") or 8)

    return CipherConfigImpl(params)


def _run(cipher: Cipher, mode: str) -> None:
    raw = _read_message()

    # Plain text is always shown in capitals; ciphertext always in lowercase.
    # Clamp the input to the expected case so the cipher sees a clean stream.
    # Only alphabet-only ciphers whitelist and group — others keep their own
    # character set and formatting untouched.
    if cipher.name in _ALPHA_CIPHERS:
        if mode == "crack":
            candidates = cipher.crack(_whitelist(raw.lower()))
            if not candidates:
                print("\nNo plaintext could be cracked.")
                return
            print(f"\nCracked '{cipher.name}' candidates:")
            for plaintext, config in candidates:
                print(f"  shift={config.parameters} -> {_group(plaintext.upper())}")
            return
        plaintext = (
            _whitelist(raw.upper()) if mode == "encrypt" else _whitelist(raw.lower())
        )
        config = _make_config(cipher)
        try:
            result = (
                cipher.encrypt(plaintext, config)
                if mode == "encrypt"
                else cipher.decrypt(plaintext, config)
            )
        except InvalidParameterError as exc:
            print(f"\nInvalid parameter: {exc}")
            return
        verb = "Encrypted" if mode == "encrypt" else "Decrypted"
        shown = _group(result.lower()) if mode == "encrypt" else _group(result.upper())
        print(f"\n{verb} result: {shown}")
        return

    # Ciphers outside the whitelist/grouping scope: keep the original behavior.
    plaintext = raw.upper() if mode == "encrypt" else raw.lower()
    config = _make_config(cipher)
    try:
        result = (
            cipher.encrypt(plaintext, config)
            if mode == "encrypt"
            else cipher.decrypt(plaintext, config)
        )
    except InvalidParameterError as exc:
        print(f"\nInvalid parameter: {exc}")
        return
    verb = "Encrypted" if mode == "encrypt" else "Decrypted"
    shown = result.lower() if mode == "encrypt" else result.upper()
    print(f"\n{verb} result: {shown}")


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point. Returns a process exit code."""
    register_all()
    print("=== Cipher Toolkit ===")
    try:
        cipher = _pick_cipher()
        mode = _pick_mode(cipher)
        _run(cipher, mode)
    except (EOFError, KeyboardInterrupt):
        print("\nBye!")
        return 0
    except InvalidParameterError as exc:
        print(f"\nError: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
