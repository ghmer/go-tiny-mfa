package qrcode

import (
	"fmt"

	qrcode "github.com/skip2/go-qrcode"
)

//FormatString is a predefined String that is used when generating a QR Code
const FormatString string = "otpauth://totp/%s:%s@%s?algorithm=SHA1&digits=6&issuer=%s&period=30&secret=%s"

// GenerateQrCode Generates a QRCode of the totp url
func GenerateQrCode(issuer, username, secret string) ([]byte, error) {
	var png []byte
	otpauthURL := fmt.Sprintf(FormatString, issuer, username, issuer, issuer, secret)
	png, err := qrcode.Encode(otpauthURL, qrcode.Medium, 256)

	return png, err
}
