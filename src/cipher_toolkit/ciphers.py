"""
The pieces every cipher shares: the interface, a registry to
hold them, and a couple of error types. Ensures all
the individual cipher modules behave the same way.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from collections.abc import Sequence


class CipherError(Exception):
    """Base class for all cipher-toolkit errors."""


class InvalidParameterError(CipherError):
    """Raised when a cipher parameter is missing, out of range, or invalid."""


class OperationError(CipherError):
    """Raised when encryption or decryption fails on the supplied input."""


class CrackError(CipherError):
    """Raised when a cipher cannot crack a given ciphertext."""


@runtime_checkable  # Used for type checking
class CipherConfig(Protocol):
    """An operation configuration of cipher parameters.

    Cipher-specific parameters (Caesar's shift, the Affine ``a``/``b``)
    are passed in as a plain dict. Keeping parameters here means
    the ciphers don't need to change the dataclass.
    """

    def get(self, key: str, default: Any = ...) -> Any: ...

    def __getitem__(self, key: str) -> Any: ...


class CipherConfigImpl:
    """Reference implementation of the ``CipherConfig`` backed by a dict."""

    def __init__(self, parameters: dict[str, Any] | None = None) -> None:
        self.parameters: dict[str, Any] = dict(parameters or {})

    def get(self, key: str, default: Any = None) -> Any:
        return self.parameters.get(key, default)

    # Useful for dictionary-like operations
    def __getitem__(self, key: str) -> Any:
        if key not in self.parameters:
            raise KeyError(key)
        return self.parameters[key]

    def __contains__(self, key: str) -> bool:
        return key in self.parameters

    # Good debugging
    def __repr__(self) -> str:
        return f"CipherConfig({self.parameters!r})"


@runtime_checkable  # Type checking
class Cipher(Protocol):
    """A cipher implementing the toolkit's encrypt/decrypt/crack contract.

    Implementations must be importable and instantiable with no arguments so
    the registry can construct them lazily.
    """

    #: Human readable name shown in menus.
    name: str
    #: Short description shown alongside the cipher in listings.
    description: str

    def encrypt(self, plaintext: str, config: CipherConfig) -> str:
        """Return the ciphertext for ``plaintext`` under ``config``."""

    def decrypt(self, ciphertext: str, config: CipherConfig) -> str:
        """Return the plaintext for ``ciphertext`` under ``config``."""

    def can_crack(self) -> bool:
        """Whether ``crack`` is implemented for this cipher."""
        return False

    def crack(self, ciphertext: str) -> Sequence[tuple[str, CipherConfig]]:
        """Recover candidate plaintexts for an unknown key ciphertext.

        Returns a sequence of ``(plaintext, config)`` tuples, ordered from most
        to least likely. The empty sequence means nothing cracked.
        """
        raise CrackError(f"{self.name} cannot be cracked")


class Registry:
    """Holds every cipher module. Keyed by lowercased name and alias."""

    def __init__(self) -> None:
        self._ciphers: dict[str, Cipher] = {}
        self._aliases: dict[str, str] = {}

    def register(self, cipher: Cipher) -> None:
        """Register a cipher instance. Raises ``ValueError`` on conflicts."""
        key = cipher.name.lower()
        if key in self._ciphers:
            raise ValueError(f"duplicate cipher registered: {cipher.name!r}")
        self._ciphers[key] = cipher
        self._aliases.setdefault(key, cipher.name)

    def get(self, name: str) -> Cipher:
        """Return the cipher for ``name``."""
        key = name.strip().lower()
        if key not in self._ciphers:
            available = ", ".join(sorted(self._aliases.values())) or "(none)"
            raise InvalidParameterError(
                f"unknown cipher {name!r}. Available ciphers: {available}"
            )
        return self._ciphers[key]

    def has(self, name: str) -> bool:
        """Whether a cipher is already registered for ``name``."""
        return name.strip().lower() in self._ciphers

    def names(self) -> list[str]:
        """Return the display names of all registered ciphers, in registration order."""
        return [self._aliases[k] for k in self._ciphers]


# Module-level singleton so the CLI, ciphers, and tests all see one registry.
registry = Registry()
