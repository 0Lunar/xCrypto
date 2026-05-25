# xCrypto

A lightweight, high-level cryptographic library written in C. xCrypto provides a clean, unified API for common cipher operations, abstracting away low-level details while giving you full control over algorithms, modes, keys, and padding.

## Features

- **Algorithms:** AES, DES *(more coming soon)*
- **Padding schemes:** PKCS7, X9.23
- **Modes of operation:** ECB, CBC *(more coming soon)*
- **Structured error handling** via `CipherError`
- **CSPRNG** utility for secure key and IV generation
- **Simple, consistent API** — configure once, encrypt/decrypt, finalize

## Installation

```sh
# Clone the repository
git clone https://github.com/yourusername/xCrypto.git
cd xCrypto
```

## API Overview

### Context Management

| Function | Description |
|---|---|
| `NewCipher()` | Allocates and returns a new `CipherCtx` |
| `CipherSetAlgorithm(ctx, algo)` | Sets the cipher algorithm (`AES`, `DES`) |
| `CipherSetKey(ctx, key, len)` | Sets the encryption key |
| `CipherSetMode(ctx, mode)` | Sets the mode of operation (`ECB`, `CBC`) |
| `CipherSetIV(ctx, iv, len)` | Sets the initialization vector |
| `CipherReset(ctx, flags)` | Resets the context (use `CIPHER_STATE_RESET`) |

### Encryption / Decryption

| Function | Description |
|---|---|
| `CipherEncrypt(ctx, data, len)` | Feeds plaintext into the cipher |
| `CipherDecrypt(ctx, data, len)` | Feeds ciphertext into the cipher |
| `CipherFinalize(ctx)` | Finalizes and returns the output buffer |

### Padding

| Function | Description |
|---|---|
| `Padder(scheme, data, len, blockSize, outLen)` | Pads data using the specified scheme (`PKCS7`, `X923`) |
| `Unpadder(scheme, data, len, blockSize, outLen)` | Removes padding from data |

### Error Handling

Most functions that do not return a value use `CipherError` to report failures. The context object exposes:

```c
CipherError err = GetError(ctx);            // Get the last error code
const char *msg = GetErrorString[err];      // Get a human-readable error message
```

### Utilities

```c
csprng_buf(buf, len); // Fill a buffer with cryptographically secure random bytes
```

## Roadmap

- [ ] Additional modes: CTR, GCM, CFB, OFB
- [ ] RSA support (sign, verify, encrypt, decrypt)
- [ ] Key derivation functions (PBKDF2, HKDF)
- [ ] Stream cipher support (ChaCha20)

## License

This project is licensed under the [MIT License](LICENSE.md).