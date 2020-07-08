package qrcode

import (
	"fmt"

	qrcode "github.com/skip2/go-qrcode"
)

const FormatString string = "otpauth://totp/%1$s:%2$s@%1$s?algorithm=SHA1&digits=6&issuer=%1$s&period=30&secret=%3$s"

// Generates a QRCode of the totp url
func GenerateQrCode(issuer, username, secret string) ([]byte, error) {
	var png []byte
	otpauthUrl := fmt.Sprintf(FormatString, issuer, username, issuer, issuer, secret)
	png, err := qrcode.Encode(otpauthUrl, qrcode.Medium, 256)

	return png, err
}
