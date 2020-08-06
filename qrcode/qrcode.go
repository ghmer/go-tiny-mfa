package qrcode

import (
	"fmt"
	"go-tiny-mfa/middleware"
	"go-tiny-mfa/structs"
	"strings"

	qrcode "github.com/skip2/go-qrcode"
)

//FormatString is a predefined String that is used when generating a QR Code
const FormatString string = "otpauth://totp/%s:%s@%s?algorithm=SHA1&digits=%d&issuer=%s&period=30&secret=%s"

// GenerateQrCode Generates a QRCode of the totp url
func GenerateQrCode(user structs.User, digits uint8) ([]byte, error) {
	var png []byte
	secret, err := middleware.GetUserKeyBase32(user)
	if err != nil {
		return nil, err
	}
	otpauthURL := buildPayload(user.Issuer.Name, user.Name, secret, digits)
	png, err = qrcode.Encode(otpauthURL, qrcode.Medium, 256)

	return png, err
}

// WriteQrCodeImage writes a png to the filesystem
func WriteQrCodeImage(user structs.User, filePath string, digits uint8) error {
	secret, err := middleware.GetUserKeyBase32(user)
	if err != nil {
		return err
	}
	return writeQrCodeImage(user.Issuer.Name, user.Name, secret, filePath, digits)
}

//writes a QRCode to the filesystem.
func writeQrCodeImage(issuer, username, secret, filePath string, digits uint8) error {
	otpauthURL := buildPayload(issuer, username, secret, digits)
	err := qrcode.WriteFile(otpauthURL, qrcode.Medium, 256, filePath)

	return err
}

//builds the payload for the QRCode. In detail, this takes the otpAuthURL Formatstring constant
//and formats it using the details provided in the method call.
func buildPayload(issuer, username, secret string, digits uint8) string {
	index := strings.Index(secret, "=")
	mySecret := secret
	if index != -1 {
		mySecret = secret[:index]
	}
	otpauthURL := fmt.Sprintf(FormatString, issuer, username, issuer, digits, issuer, mySecret)

	return otpauthURL
}
