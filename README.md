# cipher-toolkit

An extensible system for encrypting, decrypting, and cracking classic ciphers.
Ciphers are added as self-contained modules and are discovered automatically by
the CLI — no changes to the core required.

## Setup

The project uses [`uv`](https://docs.astral.sh/uv/).

```bash
uv sync          # create .venv and install dependencies
uv run cipher-toolkit   # start the interactive CLI
```

## Usage

Run the CLI and follow the prompts:

1. Select a cipher.
2. Choose a mode: **encrypt**, **decrypt**, or **crack**.
3. Enter your message.
4. (For encrypt/decrypt) Enter the cipher's key(s). Leave blank to use the
   default.

### Built-in ciphers

| Cipher   | Key(s)            | Notes                                                        |
| -------- | ----------------- | ------------------------------------------------------------ |
| Caesar   | `key` (0-25)      | Shift each letter by a fixed amount. Default `3`.            |
| Affine   | `a`, `b`          | Maps a letter to `(a·x + b) mod 26`. `a` must be coprime with 26. Default `a=5, b=8`. |

## Adding a new cipher

1. Create `src/cipher_toolkit/<name>.py`.
2. Implement the `Cipher` protocol from `cipher_toolkit.ciphers`:

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
   for cipher in (caesar.caesar, affine.affine, my_cipher.my_cipher):
       ...
   ```

The new cipher will appear in the CLI automatically.
