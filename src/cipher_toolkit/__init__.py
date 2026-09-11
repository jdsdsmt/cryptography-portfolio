"""cipher-toolkit: an extensible system for encrypting, decrypting, and cracking ciphers.

Adding a cipher is a two-step process:

1. Create ``src/cipher_toolkit/<name>.py`` implementing the ``Cipher`` protocol.
2. Import it and register it in ``cipher_toolkit.register``.

The CLI (``cipher_toolkit.cli``) discovers every registered cipher, so new
ciphers appear automatically with no other changes.
"""

from __future__ import annotations

from .cli import main

__all__ = ["main"]
