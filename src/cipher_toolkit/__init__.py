"""A toolkit for encrypting, decrypting, and cracking classic ciphers.

It's a bunch of cipher modules that each follow the same basic interface,
plus a CLI to interact with them.
"""

from __future__ import annotations

from .cli import main

__all__ = ["main"]
