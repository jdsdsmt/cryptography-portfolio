# cipher-toolkit

This is a small tool for encrypting, decrypting, and cracking classic ciphers. You can add new ciphers just by dropping in a new module and the CLI picks it up after registering.

## Setup

It uses [`uv`](https://docs.astral.sh/uv/).

```bash
uv sync          # create .venv and install dependencies
uv run cipher-toolkit   # start the interactive CLI
```

## Usage

Just run the CLI and follow the prompts:

1. Pick a cipher.
2. Pick a mode: encrypt, decrypt, or crack.
3. Type your message.
4. For encrypt or decrypt, enter the key or keys. Leave it blank to use the default.

### Built-in ciphers

| Cipher      | Key(s)            | Notes                                                        |
| ----------- | ----------------- | ------------------------------------------------------------ |
| Caesar      | `key` (0-25)      | Shifts each letter by a fixed amount. Default `3`.           |
| Affine      | `a`, `b`          | Maps a letter to `(a*x + b) mod 26`. `a` has to be coprime with 26. Default `a=5, b=8`. |
| Vigenere    | `key` (keyword)   | Keyword Caesar shifts. Cracks via key length analysis.       |
| Diophantine | `a`, `b`, `c`     | Solves `a*x + b*y = c` over the integers. Used by the Affine crack. |

## Adding a new cipher

1. Create `src/cipher_toolkit/<name>.py`.
2. Make a class that follows the `Cipher` protocol from `cipher_toolkit.ciphers`:

   ```python
   from cipher_toolkit.ciphers import Cipher, CipherConfig, CipherConfigImpl

   class MyCipher(Cipher):
       name = "MyCipher"
       description = "What it does."

       def encrypt(self, plaintext, config):
           return plaintext

       def decrypt(self, ciphertext, config):
           return ciphertext

       def can_crack(self):
           return True

       def crack(self, ciphertext):
           return []   # list of (plaintext, CipherConfig) tuples
   ```

3. Import it and register it in `src/cipher_toolkit/register.py`:

   ```python
   from . import my_cipher
   ...
   for cipher in (caesar.caesar, affine.affine, vigenere.vigenere, my_cipher.my_cipher):
       ...
   ```

That is it. The new cipher shows up in the CLI automatically.

## How it is built

The core is just a thin registry and each cipher is its own module.

- `cipher_toolkit/ciphers.py` — Holds the `Cipher` protocol, the `CipherConfig` protocol plus `CipherConfigImpl`, the exception hierarchy, and the `registry`.
- `cipher_toolkit/register.py` — Imports every built-in cipher and calls `register_all()`.
- `cipher_toolkit/cli.py` — The interactive front end.
- `cipher_toolkit/cryptomath.py` — Modular arithmetic helpers like totients and CRT.
- `cipher_toolkit/diophantine.py` — Solves linear Diophantine equations for the Affine crack.
- `cipher_toolkit/frequency.py` — Frequency analysis for cracking.
- `cipher_toolkit/{caesar,affine,vigenere}.py` — The actual ciphers.

## Testing

The tests in `tests/` were written with Claude Code using a self hosted ornith-1.5:35b model.

