"""
Registers every cipher module into the shared ``registry``.

Import this module (or import anything from ``cipher_toolkit``) to ensure all
ciphers are available. To add a new cipher:

1. Create ``src/cipher_toolkit/<name>.py`` implementing the ``Cipher`` protocol.
2. Import it here and call ``registry.register(<instance>)``.
"""

from __future__ import annotations

from . import affine, caesar, diophantine, vigenere
from .ciphers import registry


def register_all() -> None:
    """Register every built-in cipher. Idempotent: safe to call repeatedly."""
    for cipher in (
        caesar.caesar,
        affine.affine,
        diophantine.diophantine,
        vigenere.vigenere,
    ):
        if not registry.has(cipher.name):
            registry.register(cipher)


register_all()
