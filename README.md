# Tiny MFA

A Go package for generating and verifying Time-Based One-Time Passwords (TOTP) per [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238).

## What it does

- Generate and validate TOTP tokens (SHA-1, SHA-256, SHA-512)
- Generate secret keys of appropriate size for each algorithm
- Create QR codes so users can add accounts to their authenticator app
- AES-GCM encrypt/decrypt helpers
- Base32 encode/decode for secret keys
- Bcrypt password hashing

## Installation

```bash
go get github.com/ghmer/go-tiny-mfa
```

## Quick Start

```go
package main

import (
    "fmt"
    "time"

    "github.com/ghmer/go-tiny-mfa"
    "github.com/ghmer/go-tiny-mfa/utils"
)

func main() {
    tmfa := tinymfa.NewTinyMfa()
    util := utils.NewTinyMfaUtil()

    // Generate a secret key
    key, err := tmfa.GenerateStandardSecretKey()
    if err != nil {
        panic(err)
    }

    // Encode the key to base32 for storage/display
    encodedKey := util.EncodeBase32Key(key)
    fmt.Println("Secret Key:", *encodedKey)

    // Generate a TOTP token
    token, err := tmfa.GenerateToken(
        time.Now().Unix(),
        key,
        tinymfa.Present,
        6,
        tinymfa.SHA1,
        tinymfa.DefaultTimeStep,
        tinymfa.DefaultT0,
    )
    if err != nil {
        panic(err)
    }
    fmt.Printf("Current Token: %06d\n", token)

    // Validate the token
    valid, err := tmfa.ValidateToken(
        token,
        key,
        time.Now().Unix(),
        6,
        tinymfa.SHA1,
        tinymfa.DefaultTimeStep,
        tinymfa.DefaultT0,
    )
    if err != nil {
        panic(err)
    }
    fmt.Println("Token Valid:", valid)
}
```

## Core API

### Secret Key Generation

Keys are generated using `crypto/rand`. There are convenience methods for the recommended key sizes per algorithm:

```go
tmfa := tinymfa.NewTinyMfa()

// 20-byte key (for SHA-1)
key, err := tmfa.GenerateStandardSecretKey()

// 32-byte key (for SHA-256)
key, err := tmfa.GenerateExtendedSecretKey()

// 64-byte key (for SHA-512)
key, err := tmfa.GenerateSuperbSecretKey()

// Or pick the algorithm and let the library choose the size
key, err := tmfa.GenerateSecretKeyForAlgorithm(tinymfa.SHA256)

// Or specify the size directly (20, 32, or 64 bytes)
key, err := tmfa.GenerateSecretKey(tinymfa.KeySizeSHA256)
```

### Token Generation

```go
tmfa := tinymfa.NewTinyMfa()
timestamp := time.Now().Unix()

// 6-digit token, SHA-1, default 30-second window
token, err := tmfa.GenerateToken(
    timestamp,
    &secretKey,
    tinymfa.Present,         // Present, Future, or Past window
    6,                       // Token length (5–8 digits)
    tinymfa.SHA1,
    tinymfa.DefaultTimeStep, // 30 seconds
    tinymfa.DefaultT0,       // epoch offset 0
)

// Token for the next time window
nextToken, err := tmfa.GenerateToken(
    timestamp,
    &secretKey,
    tinymfa.Future,
    6,
    tinymfa.SHA1,
    tinymfa.DefaultTimeStep,
    tinymfa.DefaultT0,
)

// 8-digit token with SHA-256
token, err := tmfa.GenerateToken(
    timestamp,
    &secretKey,
    tinymfa.Present,
    8,
    tinymfa.SHA256,
    tinymfa.DefaultTimeStep,
    tinymfa.DefaultT0,
)
```

### Token Validation

Validation checks the present, past, and future time windows to account for clock drift:

```go
tmfa := tinymfa.NewTinyMfa()

// Basic validation
valid, err := tmfa.ValidateToken(
    123456,
    &secretKey,
    time.Now().Unix(),
    6,
    tinymfa.SHA1,
    tinymfa.DefaultTimeStep,
    tinymfa.DefaultT0,
)

// Convenience method — uses the current timestamp automatically
validation := tmfa.ValidateTokenCurrentTimestamp(
    123456,
    &secretKey,
    6,
    tinymfa.SHA1,
    tinymfa.DefaultTimeStep,
    tinymfa.DefaultT0,
)
fmt.Println("Valid:", validation.Success)
fmt.Println("Message:", validation.Message)
if validation.Error != nil {
    fmt.Println("Error:", validation.Error)
}

// Or validate against a specific timestamp
validation = tmfa.ValidateTokenWithTimestamp(
    123456,
    &secretKey,
    timestamp,
    6,
    tinymfa.SHA1,
    tinymfa.DefaultTimeStep,
    tinymfa.DefaultT0,
)
```

### QR Code Generation

Generate QR codes that work with Google Authenticator, Authy, and similar apps:

```go
tmfa := tinymfa.NewTinyMfa()
util := utils.NewTinyMfaUtil()

encodedKey := util.EncodeBase32Key(&secretKey)

// Get the QR code as PNG bytes
qrCode, err := tmfa.GenerateQrCode(
    "MyApp",
    "user@example.com",
    encodedKey,
    6,
    tinymfa.SHA1,
    tinymfa.DefaultTimeStep,
)

// Save it yourself
err = os.WriteFile("qrcode.png", qrCode, 0644)

// Or let the library write it to a file directly
err = tmfa.WriteQrCodeImage(
    "MyApp",
    "user@example.com",
    encodedKey,
    6,
    tinymfa.SHA1,
    tinymfa.DefaultTimeStep,
    "qrcode.png",
)
```

## Utility Functions

### Base32 Encoding/Decoding

```go
util := utils.NewTinyMfaUtil()

encoded := util.EncodeBase32Key(&secretKey)
fmt.Println(*encoded)

decoded, err := util.DecodeBase32Key(encoded)
```

### AES Encryption/Decryption

Uses AES-GCM under the hood:

```go
util := utils.NewTinyMfaUtil()

data := []byte("sensitive information")
passphrase := []byte("my-secure-passphrase")

// Encrypt / decrypt in memory
encrypted, err := util.Encrypt(&data, &passphrase)
decrypted, err := util.Decrypt(encrypted, &passphrase)

// Or work with files directly
err = util.EncryptFile("secrets.enc", &data, &passphrase)
decrypted, err = util.DecryptFile("secrets.enc", &passphrase)
```

### Bcrypt Hashing

```go
util := utils.NewTinyMfaUtil()

password := []byte("user-password")
hashed, err := util.BcryptHash(password)

err = util.BycrptVerify(hashed, password)
if err == nil {
    fmt.Println("Password is valid")
}
```

## Configuration

### Hash Algorithms

Three algorithms are supported, as defined in RFC 6238:

| Constant         | Algorithm   | Note                                 |
|------------------|-------------|--------------------------------------|
| `tinymfa.SHA1`   | HMAC-SHA-1  | Default, widest compatibility        |
| `tinymfa.SHA256` | HMAC-SHA-256| Good default for new projects        |
| `tinymfa.SHA512` | HMAC-SHA-512| Larger key, larger HMAC              |

### Custom Time Parameters

You can change the time step and epoch offset if you need to:

```go
// 60-second time step instead of the default 30
token, err := tmfa.GenerateToken(
    timestamp, &secretKey, tinymfa.Present,
    6, tinymfa.SHA1,
    60, // time step in seconds
    0,  // epoch offset
)

// Custom epoch offset (e.g. Jan 1, 2021)
token, err := tmfa.GenerateToken(
    timestamp, &secretKey, tinymfa.Present,
    6, tinymfa.SHA1,
    tinymfa.DefaultTimeStep,
    1609459200,
)
```

### QR Code Colors

```go
import "github.com/ghmer/go-tiny-mfa/structs"

tmfa := tinymfa.NewTinyMfa()

tmfa.SetQRCodeConfig(structs.QrCodeConfig{
    BgColor: structs.ColorSetting{Red: 255, Green: 255, Blue: 255, Alpha: 255},
    FgColor: structs.ColorSetting{Red: 0, Green: 0, Blue: 255, Alpha: 255},
})

current := tmfa.GetQRCodeConfig()
```

## API Reference

### TinyMfa

| Method | Description |
|--------|-------------|
| `NewTinyMfa() TinyMfaInterface` | Create a new instance |
| `GenerateStandardSecretKey() (*[]byte, error)` | 20-byte key |
| `GenerateExtendedSecretKey() (*[]byte, error)` | 32-byte key |
| `GenerateSuperbSecretKey() (*[]byte, error)` | 64-byte key |
| `GenerateSecretKey(size int8) (*[]byte, error)` | Key of a given size |
| `GenerateSecretKeyForAlgorithm(algorithm HashAlgorithm) (*[]byte, error)` | Key sized for a given algorithm |
| `GenerateToken(...) (int, error)` | Generate a TOTP token |
| `ValidateToken(...) (bool, error)` | Validate a TOTP token |
| `ValidateTokenCurrentTimestamp(...) Validation` | Validate using current time |
| `ValidateTokenWithTimestamp(...) Validation` | Validate using a specific time |
| `GenerateQrCode(...) ([]byte, error)` | QR code as PNG bytes |
| `WriteQrCodeImage(...) error` | Write QR code PNG to a file |
| `BuildPayload(...) string` | Build an `otpauth://` URL |
| `SetQRCodeConfig(structs.QrCodeConfig)` | Set QR code colors |
| `GetQRCodeConfig() structs.QrCodeConfig` | Get current QR code colors |
| `GenerateMessageBytes(int64) ([]byte, error)` | Int64 → big-endian bytes |
| `CalculateHMAC([]byte, *[]byte, HashAlgorithm) ([]byte, error)` | Compute HMAC |
| `GenerateMessage(int64, uint8, int64, int64) (int64, error)` | Compute the time counter value |

### TinyMfaUtil

| Method | Description |
|--------|-------------|
| `NewTinyMfaUtil() TinyMfaUtilInterface` | Create a new utility instance |
| `Encrypt(data, passphrase *[]byte) (*[]byte, error)` | AES-GCM encrypt |
| `Decrypt(data, passphrase *[]byte) (*[]byte, error)` | AES-GCM decrypt |
| `EncryptFile(path string, data, passphrase *[]byte) error` | Encrypt to file |
| `DecryptFile(path string, passphrase *[]byte) (*[]byte, error)` | Decrypt from file |
| `CreateMd5Hash(b *[]byte) *[]byte` | MD5 hash |
| `EncodeBase32Key(key *[]byte) *string` | Base32 encode |
| `DecodeBase32Key(encodedKey *string) (*[]byte, error)` | Base32 decode |
| `BcryptHash(tohash []byte) ([]byte, error)` | Bcrypt hash |
| `BycrptVerify(comparable, verifiable []byte) error` | Bcrypt verify |

### Constants

| Constant | Value | Purpose |
|----------|-------|---------|
| `SHA1` | — | HMAC-SHA-1 |
| `SHA256` | — | HMAC-SHA-256 |
| `SHA512` | — | HMAC-SHA-512 |
| `KeySizeSHA1` | 20 | Key size for SHA-1 |
| `KeySizeSHA256` | 32 | Key size for SHA-256 |
| `KeySizeSHA512` | 64 | Key size for SHA-512 |
| `Present` | — | Current time window |
| `Future` | — | Next time window |
| `Past` | — | Previous time window |
| `DefaultTimeStep` | 30 | Default time step in seconds |
| `DefaultT0` | 0 | Unix epoch |

## License

MIT — see [LICENSE](LICENSE) for details.
