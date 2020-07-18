package qrcode

import (
	"fmt"
	"strings"

	qrcode "github.com/skip2/go-qrcode"
)

//FormatString is a predefined String that is used when generating a QR Code
const FormatString string = "otpauth://totp/%s:%s@%s?algorithm=SHA1&digits=6&issuer=%s&period=30&secret=%s"

// GenerateQrCode Generates a QRCode of the totp url
func GenerateQrCode(issuer, username, secret string) ([]byte, error) {
	var png []byte
	otpauthURL := buildPayload(issuer, username, secret)
	png, err := qrcode.Encode(otpauthURL, qrcode.Medium, 256)

	return png, err
}

//WriteQrCodeImage saves the QrCode image to a file
func WriteQrCodeImage(issuer, username, secret, filePath string) error {
	otpauthURL := buildPayload(issuer, username, secret)
	err := qrcode.WriteFile(otpauthURL, qrcode.Medium, 256, filePath)

	return err
}

func buildPayload(issuer, username, secret string) string {
	index := strings.Index(secret, "=")
	mySecret := secret
	if index != -1 {
		mySecret = secret[:index]
	}
	otpauthURL := fmt.Sprintf(FormatString, issuer, username, issuer, issuer, mySecret)

	return otpauthURL
}
