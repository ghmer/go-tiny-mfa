package tinymfa

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"image/color"
	"math"
	"strings"
	"time"

	"github.com/ghmer/go-tiny-mfa/structs"
	"github.com/skip2/go-qrcode"
)

const (
	// Present can be used as an Offset Type
	Present uint8 = iota
	// Future can be used as an Offset Type
	Future
	// Past can be used as an Offset Type
	Past
)

const (
	// OffsetPresent is the offset to add when the OffsetTypePresent was used
	OffsetPresent int8 = 0

	// OffsetFuture is the offset to add when the OffsetTypeFuture was used
	OffsetFuture int8 = 30

	// OffsetPast is the offset to add when the OffsetTypePast was used
	OffsetPast int8 = -30

	// KeySizeStandard is the default size of the SecretKey (128bit)
	KeySizeStandard int8 = 16

	// KeySizeExtended is the extended size of the SecretKey (256bit)
	KeySizeExtended int8 = 32
)

type TinyMfaInterface interface {
	// GenerateStandardSecretKey returns 16bytes to be used as a secret key
	GenerateStandardSecretKey() (*[]byte, error)

	// GenerateExtendedSecretKey returns 32bytes to be used as a secret key
	GenerateExtendedSecretKey() (*[]byte, error)

	// generateSecretKey returns size bytes to be used as a secret key
	GenerateSecretKey(size int8) (*[]byte, error)

	// GenerateMessageBytes takes in a int64 number and turns it to a BigEndian byte array
	GenerateMessageBytes(message int64) ([]byte, error)

	// CalculateHMAC calculates the hmac-sha1 value for a given message and key (RFC2104)
	CalculateHMAC(message []byte, key *[]byte) []byte

	// GenerateMessage takes in a Unix Timestamp and an offsetType of 0,1,2
	// offsetTypes: 0=No Offset; 1=Future Offset; 2=Past Offset
	GenerateMessage(timestamp int64, offsetType uint8) int64

	// GenerateValidToken takes a Unix Timestamp and a secret key and calculates a valid TOTP token
	GenerateValidToken(unixTimestamp int64, key *[]byte, offsetType, tokenlength uint8) (int, error)

	// ValidateTokenCurrentTimestamp takes a submitted token and a secret key and validates against the current Unix Timestamp whether the token is valid
	ValidateTokenCurrentTimestamp(token int, key *[]byte, tokenlength uint8) Validation

	// ValidateTokenWithTimestamp takes a submitted token and a secret key and validates against the current Unix Timestamp whether the token is valid
	ValidateTokenWithTimestamp(token int, key *[]byte, timestamp int64, tokenlength uint8) Validation

	// ValidateToken takes a submitted token, a secret key and a Unix Timestamp and validates whether the token is valid
	ValidateToken(token int, key *[]byte, unixTimestamp int64, tokenlength uint8) (bool, error)

	// GenerateQrCode generates a QRCode for the provided issuer, user and secret. It takes in a color setting and number of digits for the TOTP token.
	GenerateQrCode(issuer, user string, secret *string, digits uint8) ([]byte, error)

	// ConvertColorSetting converts the ColorSetting struct into a color.Color object. This is useful for QRCode generation.
	ConvertColorSetting(setting structs.ColorSetting) color.Color

	// WriteQrCodeImage writes a png to the filesystem
	WriteQrCodeImage(issuer, user string, secret *string, digits uint8, filepath string) error

	// writeQrCodeImage writes a QRCode to the filesystem.
	writeQrCodeImage(issuer, username string, secret *string, digits uint8, filePath string) error

	// builds the payload for the QRCode. In detail, this takes the otpAuthURL Formatstring constant
	// and formats it using the details provided in the method call.
	BuildPayload(issuer, username string, secret *string, digits uint8) string

	// SetFormatString sets the FormatString for the QRCode.
	SetFormatString(formatstring string)

	// GetFormatString returns the current FormatString for the QRCode.
	GetFormatString() string

	// SetQRCodeConfig sets the QRCodeConfig for the QRCode.
	SetQRCodeConfig(qrcodeConfig structs.QrCodeConfig)

	// GetQRCodeConfig returns the current QRCodeConfig for the QRCode.
	GetQRCodeConfig() structs.QrCodeConfig
}

// Validation is a struct used to return the result of a token validation
type Validation struct {
	Message int64
	Success bool
	Error   error
}

type TinyMfa struct {
	QRCodeConfig structs.QrCodeConfig
	FormatString string
}

func NewTinyMfa() TinyMfaInterface {
	return &TinyMfa{
		QRCodeConfig: structs.StandardQrCodeConfig(),
		FormatString: "otpauth://totp/%s:%s@%s?algorithm=SHA1&digits=%d&issuer=%s&period=30&secret=%s",
	}
}

// GenerateStandardSecretKey returns 16bytes to be used as a secret key
func (tinymfa *TinyMfa) GenerateStandardSecretKey() (*[]byte, error) {
	return tinymfa.GenerateSecretKey(KeySizeStandard)
}

// GenerateExtendedSecretKey returns 32bytes to be used as a secret key
func (tinymfa *TinyMfa) GenerateExtendedSecretKey() (*[]byte, error) {
	return tinymfa.GenerateSecretKey(KeySizeExtended)
}

// generateSecretKey returns size bytes to be used as a secret key
func (tinymfa *TinyMfa) GenerateSecretKey(size int8) (*[]byte, error) {
	if size != KeySizeStandard && size != KeySizeExtended {
		return nil, errors.New("invalid secret key size")
	}
	key := make([]byte, size)
	_, err := rand.Read(key)

	return &key, err
}

// GenerateMessageBytes takes in a int64 number and turns it to a BigEndian byte array
func (tinymfa *TinyMfa) GenerateMessageBytes(message int64) ([]byte, error) {
	buffer := new(bytes.Buffer)
	err := binary.Write(buffer, binary.BigEndian, message)

	return buffer.Bytes(), err
}

// CalculateHMAC calculates the hmac-sha1 value for a given message and key (RFC2104)
func (tinymfa *TinyMfa) CalculateHMAC(message []byte, key *[]byte) []byte {
	mac := hmac.New(sha1.New, *key)
	mac.Write(message)

	return mac.Sum(nil)
}

// GenerateMessage takes in a Unix Timestamp and an offsetType of 0,1,2
// offsetTypes: 0=No Offset; 1=Future Offset; 2=Past Offset
func (tinymfa *TinyMfa) GenerateMessage(timestamp int64, offsetType uint8) int64 {
	var offset int8

	// based on offsetType, we are applying different offsets to the timestamp
	switch offsetType {
	case Present: // standard case, no offset is added to the timestamp
		offset = OffsetPresent
	case Future: // setting an offset of 30 seconds into the future
		offset = OffsetFuture
	case Past: // removing an offset of 30 seconds
		offset = OffsetPast
	}

	// apply the chosen offset
	timestamp = timestamp + int64(offset)
	// flatten the timestamp by removing the overlapping seconds
	timestamp = timestamp - (timestamp % 30)

	// finally, generating the message by dividing the flattened timestamp by 30
	message := math.Floor(float64(timestamp) / 30.0)

	return int64(message)
}

// GenerateValidToken takes a Unix Timestamp and a secret key and calculates a valid TOTP token
func (tinymfa *TinyMfa) GenerateValidToken(unixTimestamp int64, key *[]byte, offsetType, tokenlength uint8) (int, error) {
	message, err := tinymfa.GenerateMessageBytes(tinymfa.GenerateMessage(unixTimestamp, offsetType))
	if err != nil {
		return 0, err
	}
	rfc2104hmac := tinymfa.CalculateHMAC(message, key)

	// the offset is the numerical representation of the last byte of the hmac-sha1 message.
	// i.E if the last byte was 4 (in its decimal representation), we will derive the dynamic
	// trunacted result, starting at the 4th index of the byte array
	var offset int = int(rfc2104hmac[(len(rfc2104hmac)-1)] & 0xF)
	// probably a huge number. Making room for it
	var truncResult int64
	for i := 0; i < 4; i++ {
		// shift 8bit to the left to make room for the next byte
		truncResult <<= 8
		// perform a bitwise inclusive OR on the next offset
		// this adds the next digit to the truncated result
		truncResult |= int64(rfc2104hmac[offset+i] & 0xFF)
	}
	// setting the most significant bit to 0
	truncResult &= 0x7FFFFFFF
	// making sure we get the right amount of numbers
	switch tokenlength {
	case 5:
		truncResult %= 100000
	case 6:
		truncResult %= 1000000
	case 7:
		truncResult %= 10000000
	case 8:
		truncResult %= 100000000
	default:
		return 0, fmt.Errorf("%d is not a valid length for a token. try something between 5-8", tokenlength)
	}

	token := int(truncResult)

	return token, nil
}

// ValidateTokenCurrentTimestamp takes a submitted token and a secret key and validates against the current Unix Timestamp whether the token is valid
func (tinymfa *TinyMfa) ValidateTokenCurrentTimestamp(token int, key *[]byte, tokenlength uint8) Validation {
	currentTimestamp := time.Now().Unix()
	result, err := tinymfa.ValidateToken(token, key, currentTimestamp, tokenlength)
	var validation = Validation{
		Message: tinymfa.GenerateMessage(currentTimestamp, Present),
		Success: result,
		Error:   err,
	}
	return validation
}

// ValidateTokenWithTimestamp takes a submitted token and a secret key and validates against the current Unix Timestamp whether the token is valid
func (tinymfa *TinyMfa) ValidateTokenWithTimestamp(token int, key *[]byte, timestamp int64, tokenlength uint8) Validation {
	result, err := tinymfa.ValidateToken(token, key, timestamp, tokenlength)
	var validation = Validation{
		Message: tinymfa.GenerateMessage(timestamp, Present),
		Success: result,
		Error:   err,
	}
	return validation
}

// ValidateToken takes a submitted token, a secret key and a Unix Timestamp and validates whether the token is valid
func (tinymfa *TinyMfa) ValidateToken(token int, key *[]byte, unixTimestamp int64, tokenlength uint8) (bool, error) {
	var result bool = false
	// validating against a token that was generated with a current timestamp
	// usually, the clocks of server and client should be synchronized, so this
	// should be the most common case
	generatedToken, err := tinymfa.GenerateValidToken(unixTimestamp, key, Present, tokenlength)
	if err != nil {
		return false, err
	}
	if generatedToken == token {
		result = true
	}

	// the token could not be verified with a current timestamp, but maybe the
	// user missed the timewindow for that token. Verifying it against a token
	// that was valid up to 30 seconds ago
	if !result {
		generatedToken, err := tinymfa.GenerateValidToken(unixTimestamp, key, Past, tokenlength)
		if err != nil {
			return false, err
		}
		if generatedToken == token {
			result = true
		}
	}

	// we still could not verify the token. Doing a last check against the token
	// that becomes valid in the next window.
	if !result {
		generatedToken, err := tinymfa.GenerateValidToken(unixTimestamp, key, Future, tokenlength)
		if err != nil {
			return false, err
		}
		if generatedToken == token {
			result = true
		}
	}

	// returning the outcome of our checks
	return result, nil
}

// GenerateQrCode Generates a QRCode of the totp url
func (tinymfa *TinyMfa) GenerateQrCode(issuer, user string, secret *string, digits uint8) ([]byte, error) {
	var png []byte

	otpauthURL := tinymfa.BuildPayload(issuer, user, secret, digits)
	code, err := qrcode.New(otpauthURL, qrcode.Medium)
	if err != nil {
		return nil, err
	}

	code.BackgroundColor = tinymfa.ConvertColorSetting(tinymfa.QRCodeConfig.BgColor)
	code.ForegroundColor = tinymfa.ConvertColorSetting(tinymfa.QRCodeConfig.FgColor)

	png, err = code.PNG(256)

	return png, err
}

func (tinymfa *TinyMfa) ConvertColorSetting(setting structs.ColorSetting) color.Color {
	return color.RGBA{
		R: setting.Red,
		G: setting.Green,
		B: setting.Blue,
		A: setting.Alpha,
	}
}

// WriteQrCodeImage writes a png to the filesystem
func (tinymfa *TinyMfa) WriteQrCodeImage(issuer, user string, secret *string, digits uint8, filePath string) error {
	return tinymfa.writeQrCodeImage(issuer, user, secret, digits, filePath)
}

// writes a QRCode to the filesystem.
func (tinymfa *TinyMfa) writeQrCodeImage(issuer, username string, secret *string, digits uint8, filePath string) error {
	otpauthURL := tinymfa.BuildPayload(issuer, username, secret, digits)
	err := qrcode.WriteFile(otpauthURL, qrcode.Medium, 256, filePath)

	return err
}

// builds the payload for the QRCode. In detail, this takes the otpAuthURL Formatstring constant
// and formats it using the details provided in the method call.
func (tinymfa *TinyMfa) BuildPayload(issuer, username string, secret *string, digits uint8) string {
	index := strings.Index(*secret, "=")
	mySecret := *secret
	if index != -1 {
		mySecret = strings.TrimSuffix(*secret, "=")
	}
	otpauthURL := fmt.Sprintf(tinymfa.FormatString, issuer, username, issuer, digits, issuer, mySecret)
	mySecret = ""

	return otpauthURL
}

// GetFormatString returns the current FormatString for the QRCode.
func (tinymfa *TinyMfa) GetFormatString() string {
	return tinymfa.FormatString
}

// SetFormatString sets the FormatString for the QRCode.
func (tinymfa *TinyMfa) SetFormatString(formatstring string) {
	tinymfa.FormatString = formatstring
}

// GetQRCodeConfig returns the current QRCodeConfig for the QRCode.
func (tinymfa *TinyMfa) GetQRCodeConfig() structs.QrCodeConfig {
	return tinymfa.QRCodeConfig
}

// SetQRCodeConfig sets the QRCodeConfig for the QRCode.
func (tinymfa *TinyMfa) SetQRCodeConfig(qrcodeConfig structs.QrCodeConfig) {
	tinymfa.QRCodeConfig = qrcodeConfig
}
