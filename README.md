# Tiny MFA: A Go package for Time-Based One-Time Password (TOTP) generation and verification

## Table of Contents

- [Tiny MFA: A Go package for Time-Based One-Time Password (TOTP) generation and verification](#tiny-mfa-a-go-package-for-time-based-one-time-password-totp-generation-and-verification)
  - [Table of Contents](#table-of-contents)
  - [Overview](#overview)
  - [Installation](#installation)
  - [Usage](#usage)
    - [Generating TOTP Tokens](#generating-totp-tokens)
    - [Verifying TOTP Tokens](#verifying-totp-tokens)
    - [Generating QR Codes](#generating-qr-codes)
    - [Encrypting and Decrypting Data](#encrypting-and-decrypting-data)
  - [API Documentation](#api-documentation)
  - [License](#license)

## Overview

The Tiny MFA package is a Go library for generating and verifying Time-Based One-Time Passwords (TOTP) according to the TOTP algorithm specified in RFC 6238. It also includes functionality for encrypting and decrypting data using AES-256-CBC.

## Installation

To install the Tiny MFA package, run the following command:

```bash
go get github.com/ghmer/go-tiny-mfa
```

## Usage

### Generating TOTP Tokens

To generate a TOTP token, you can use the `GenerateValidToken` method of the `TinyMfa` struct. This method takes four arguments: the current Unix timestamp, the secret key, the offset type (either present, future, or past), and the desired token length.

```go
package main

import (
    "github.com/ghmer/go-tiny-mfa"
)

func main() {
    tinymfa := tinymfa.NewTinyMfa()
    timeStamp := time.Now().Unix()
    key := []byte("your_secret_key") // replace with your secret key
    size := 6 // replace with the totp length

    token, _ := tmfa.GenerateValidToken(timeStamp, &key, tinymfa.Present, size)
    if err != nil {
        panic(err)
    }

    fmt.Println(token)
}
```

### Verifying TOTP Tokens

To verify a TOTP token, you can use the `ValidateToken` method of the `TinyMfa` struct. This method takes five arguments: the submitted token, the secret key, the current Unix timestamp, and the desired token length.

```go
package main

import (
    "github.com/ghmer/go-tiny-mfa"
)

func main() {
    tinymfa := tinymfa.NewTinyMfa()
    
    tokenNow := "123456" // replace with the submitted token
    key := []byte("your_secret_key") // replace with your secret key
    timeStamp := time.Now().Unix()
    size := 6 // replace with the totp length


    valid, _ := tmfa.ValidateToken(tokenNow, &key, timeStamp, 6)
    if err != nil {
        panic(err)
    }

    fmt.Println(valid)
}
```

### Generating QR Codes

```go

func main() {
    var issuer string = "tinymfa.parzival.link"
    var user string = "demo"
    var key string = base32.StdEncoding.EncodeToString(Key)
    var digits uint8 = 6

    qrcode, err := tmfa.GenerateQrCode(issuer, user, &key, digits)
    if err != nil {
        panic(err)
    }
    // write png to file
    os.WriteFile("./qrcode1.png", qrcode, 0644)

    // shorthand for the above
    tmfa.WriteQrCodeImage(issuer, user, &key, digits, "./qrcode2.png")
}
```

### Encrypting and Decrypting Data

To encrypt data using the `TinyMfa` package, you can use the `Encrypt` method. This method takes two arguments: the data to be encrypted and the passphrase used for encryption.

```go
package main

import (
    "github.com/ghmer/go-tiny-mfa/utils"
)

func main() {
    data := []byte("Hello, World!")
    passphrase := []byte("your_passphrase")
    encryptedData, err := util.Encrypt(&data, &passphrase)
    if err != nil {
        panic(err)
    }
    fmt.Println(encryptedData)
}
```

To decrypt data using the `TinyMfa` package, you can use the `Decrypt` method. This method takes two arguments: the encrypted data and the passphrase used for decryption.

```go
package main

import (
    "github.com/ghmer/go-tiny-mfa/utils"
)

func main() {
    encryptedData := []byte("your_encrypted_data")
    passphrase := []byte("your_passphrase")
    decryptedData, err := util.Decrypt(encryptedData, &passphrase)
    if err != nil {
        panic(err)
    }
    fmt.Println(decryptedData)
}
```

## API Documentation

The `TinyMfa` package includes the following methods:

* `GenerateValidToken`: Generates a TOTP token for the given timestamp and secret key.
* `ValidateToken`: Verifies whether the submitted token is valid for the given timestamp and secret key.
* `Encrypt`: Encrypts data using AES-256-CBC with the given passphrase.
* `Decrypt`: Decrypts encrypted data using AES-256-CBC with the given passphrase.

## License

The Tiny MFA package is released under the MIT License. See [LICENSE](LICENSE) for details.
