# vaultx

> Cross-platform file encryption utility — AES-256-GCM / ChaCha20-Poly1305 + Argon2id

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Go 1.22+](https://img.shields.io/badge/go-1.22+-blue.svg)](https://go.dev)

---

## Features

| Feature | Details |
|---|---|
| **AES-256-GCM** | Default algorithm — authenticated encryption, 256-bit key |
| **ChaCha20-Poly1305** | Fast alternative, especially on ARM / embedded devices |
| **Argon2id KDF** | Password → key derivation resistant to GPU/ASIC brute-force |
| **Streaming encryption** | 64 KB chunks — encrypts files of any size without loading into RAM |
| **stdin / stdout** | Use `-` as path to pipe data between processes |
| **Directory encryption** | Encrypt entire folders into a single `.vx` vault file |
| **Verify** | Check password and file integrity without writing anything to disk |
| **Secure shred** | 3-pass overwrite before deleting originals (`--shred`) |
| **Armor mode** | Base64 output for text-safe transport (`--armor`) |
| **GUI** | Desktop app built with [Fyne](https://fyne.io) — no terminal needed |
| **Raycast** | Script Commands for quick encrypt/decrypt from Raycast |
| **Single binary** | No runtime or dependencies — one file, works everywhere |

---

## Install

### Download binary (no Go required)

Grab the latest pre-built binary for your platform from the [Releases](https://github.com/yacasper/vaultx/releases) page:

| Platform | File |
|---|---|
| Linux x86_64 | `vaultx-linux-x64` |
| Linux ARM64 | `vaultx-linux-arm64` |
| macOS Intel | `vaultx-macos-x64` |
| macOS Apple Silicon | `vaultx-macos-arm64` |
| Windows x86_64 | `vaultx-windows-x64.exe` |

```bash
# macOS / Linux example
chmod +x vaultx-macos-arm64
sudo mv vaultx-macos-arm64 /usr/local/bin/vaultx
```

### go install (all platforms)

```bash
go install github.com/yacasper/vaultx@latest
```

> Requires [Go 1.22+](https://go.dev/dl/)

### Build from source

```bash
git clone https://github.com/yacasper/vaultx
cd vaultx
go build -ldflags="-s -w -X main.version=$(git describe --tags --always)" -o vaultx .
sudo mv vaultx /usr/local/bin/
```

---

## Usage

### Encrypt

```bash
# Basic — prompts for password, output: secret.pdf.vx
vaultx encrypt secret.pdf

# Specify output path
vaultx encrypt secret.pdf -o vault.vx

# Use ChaCha20-Poly1305 instead of AES-256-GCM
vaultx encrypt photo.jpg --algo chacha20

# Encrypt entire directory into one vault file
vaultx encrypt documents/ -o documents.vx

# Securely delete original after encryption (3-pass overwrite)
vaultx encrypt report.pdf --shred

# Base64-armored output (text-safe, e.g. for email body)
vaultx encrypt message.txt --armor

# Read from stdin, write to stdout
cat secret.txt | vaultx encrypt - -p "password" > secret.vx
```

### Decrypt

```bash
# Basic — output: secret.pdf (strips .vx extension)
vaultx decrypt secret.pdf.vx

# Specify output path
vaultx decrypt vault.vx -o restored.pdf

# Decrypt a directory vault
vaultx decrypt documents.vx -o restored_docs/

# Read from stdin, write to stdout
cat secret.vx | vaultx decrypt - -p "password"
```

### Verify

Check that the password is correct and the file has not been tampered with.
Nothing is written to disk.

```bash
vaultx verify secret.pdf.vx
# 🔍  Verifying: secret.pdf.vx
#     Deriving key… done.
#     Algorithm : AES-256-GCM
#     Integrity… ok.
# ✅  Password correct. File integrity verified.
```

### Pipe example

```bash
# Encrypt and decrypt in a single pipeline
cat secret.txt | vaultx encrypt - -p "pass" | vaultx decrypt - -p "pass"
```

### Info

```bash
vaultx info secret.pdf.vx
# 📄  File      : secret.pdf.vx
#     Size      : 2,048 bytes
#     Armored   : false
#     Algorithm : AES-256-GCM
#     Content   : file
```

---

## File Format

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ MAGIC (7B)   │ ALGO (1B) │ TYPE (1B) │ SALT (32B) │ NONCE (12B)             │
│ "VAULTX\x02" │  0x01/02  │  0x00/01  │  Argon2id  │  random base            │
├──────────────────────────────────────────────────────────────────────────────┤
│ [ FLAG (1B) │ LEN (4B) │ CIPHERTEXT (LEN B) ] × N chunks                    │
│   0x00=more │          │ plaintext chunk + 16B auth tag                      │
│   0xFF=last │          │                                                     │
└──────────────────────────────────────────────────────────────────────────────┘
```

- **TYPE** — `0x00` = file/stream, `0x01` = directory (zipped)
- **Chunk nonce** — base nonce XOR chunk index (unique per chunk, prevents nonce reuse)
- **Chunk AAD** — encodes chunk index + last flag (prevents truncation attacks)
- **Chunk size** — 64 KB plaintext; last chunk may be smaller

---

## Security Design

### Key Derivation — Argon2id

```
password + random_salt → Argon2id → 256-bit key
  time_cost=3, memory=64MB, parallelism=4
```

Argon2id is the [PHC winner](https://github.com/P-H-C/phc-winner-argon2) and recommended by [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) for password hashing. It is resistant to GPU, FPGA and ASIC brute-force attacks.

### Authenticated Encryption

Both AES-256-GCM and ChaCha20-Poly1305 are **AEAD** ciphers — they provide:
- **Confidentiality** — content is encrypted
- **Integrity** — any tampering will cause decryption to fail with an error
- **Authenticity** — only someone with the correct key can produce a valid ciphertext

Each 64 KB chunk is independently authenticated. The chunk AAD encodes the chunk index and a "last chunk" flag, preventing truncation and reordering attacks.

### Secure Shred

The `--shred` flag overwrites the original file 3 times with random bytes before deletion, making recovery from disk significantly harder. Note: this is not guaranteed on SSDs with wear-leveling or copy-on-write filesystems (e.g. Btrfs, APFS).

---

## GUI

A desktop app is included in the [`gui/`](gui/) directory, built with [Fyne](https://fyne.io).

### Build (binary)

```bash
go build -o vaultx-gui ./gui/
./vaultx-gui
```

### Build (macOS .app bundle)

```bash
go install fyne.io/tools/cmd/fyne@latest
fyne package -os darwin -name vaultx -src ./gui
# → vaultx.app
cp -r vaultx.app /Applications/
```

> Requires Xcode Command Line Tools: `xcode-select --install`

### Features

- Encrypt file or folder
- Decrypt `.vx` file
- Verify integrity
- Dark theme, resizable window, native file picker

---

## Raycast Integration

Script Commands for [Raycast](https://www.raycast.com) are included in the [`raycast/`](raycast/) directory.

### Setup

1. Open Raycast → **Settings** → **Extensions** → **Script Commands**
2. Click **+** → **Add Script Directory**
3. Select the `raycast/` folder from this repository

### Available commands

| Command | Description |
|---|---|
| **Encrypt File** | Encrypt a file or folder — prompts for password, then opens a native file picker |
| **Decrypt File** | Decrypt a `.vx` file — prompts for password, then opens a native file picker |
| **Verify File** | Verify integrity of a `.vx` file — prompts for password, then opens a native file picker |
| **Encrypt Clipboard** | Encrypt clipboard text and replace it with the encrypted (base64) result |
| **Decrypt Clipboard** | Decrypt armored vaultx text from clipboard and replace it with the original |

File commands open a native macOS file picker (via AppleScript) after you enter the password.

---

## Versioning & Updates

```bash
vaultx version
# vaultx v1.1.3
```

```bash
# Update to latest
go install github.com/yacasper/vaultx@latest
```

### Release a new version (for maintainers)

```bash
git tag v1.2.0
git push --tags
```

GitHub Actions and Gitea Actions will automatically build binaries for all platforms and attach them to the release.

---

## Why not GPG / 7-Zip / openssl?

| Tool | Problem |
|---|---|
| GPG | Complex key management, asymmetric focus, legacy defaults |
| 7-Zip AES | Leaks filename list, metadata visible without password |
| `openssl enc` | Weak KDF (PBKDF2 with low iterations), no Argon2 |
| **vaultx** | Single binary, modern KDF, no metadata leakage, streaming, minimal codebase |

---

## Contributing

1. Fork this repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Commit your changes: `git commit -m 'Add my feature'`
4. Push: `git push origin feature/my-feature`
5. Open a Pull Request

---

## License

[MIT](LICENSE) — free to use, modify, and distribute.
