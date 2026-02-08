package tinymfa

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"
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

// HashAlgorithm represents the hash algorithm used for HMAC computation.
// RFC 6238 Section 1.2 defines SHA-1, SHA-256, and SHA-512 as valid algorithms.
type HashAlgorithm uint8

const (
	// SHA1 selects HMAC-SHA-1 for TOTP computation (RFC 6238 Section 1.2).
	SHA1 HashAlgorithm = iota
	// SHA256 selects HMAC-SHA-256 for TOTP computation (RFC 6238 Section 1.2).
	SHA256
	// SHA512 selects HMAC-SHA-512 for TOTP computation (RFC 6238 Section 1.2).
	SHA512
)

const (
	// KeySizeSHA1 is the recommended secret key size for SHA-1 (160 bits / 20 bytes).
	// RFC 6238 Section 4 recommends keys be at least as long as the HMAC output.
	KeySizeSHA1 int8 = 20

	// KeySizeSHA256 is the recommended secret key size for SHA-256 (256 bits / 32 bytes).
	// RFC 6238 Section 4 recommends keys be at least as long as the HMAC output.
	KeySizeSHA256 int8 = 32

	// KeySizeSHA512 is the recommended secret key size for SHA-512 (512 bits / 64 bytes).
	// RFC 6238 Section 4 recommends keys be at least as long as the HMAC output.
	KeySizeSHA512 int8 = 64
)

const (
	// DefaultTimeStep is the default time step size in seconds (RFC 6238 Section 4.1).
	DefaultTimeStep int64 = 30

	// DefaultT0 is the default Unix epoch offset in seconds (RFC 6238 Section 4.1).
	DefaultT0 int64 = 0
)

type TinyMfaInterface interface {
	// GenerateStandardSecretKey returns a 20-byte secret key (SHA-1 recommended size).
	GenerateStandardSecretKey() (*[]byte, error)

	// GenerateExtendedSecretKey returns a 32-byte secret key (SHA-256 recommended size).
	GenerateExtendedSecretKey() (*[]byte, error)

	// GenerateSuperbSecretKey returns a 64-byte secret key (SHA-512 recommended size).
	GenerateSuperbSecretKey() (*[]byte, error)

	// GenerateSecretKey returns a secret key of the specified size.
	// Valid sizes are KeySizeSHA1 (20), KeySizeSHA256 (32), and KeySizeSHA512 (64).
	GenerateSecretKey(size int8) (*[]byte, error)

	// GenerateSecretKeyForAlgorithm generates a secret key with the recommended size
	// for the specified hash algorithm per RFC 6238 Section 4.
	GenerateSecretKeyForAlgorithm(algorithm HashAlgorithm) (*[]byte, error)

	// GenerateMessageBytes takes in a int64 number and turns it to a BigEndian byte array.
	GenerateMessageBytes(message int64) ([]byte, error)

	// CalculateHMAC calculates the HMAC value for a given message and key
	// using the specified hash algorithm (RFC 2104, RFC 6238 Section 1.2).
	CalculateHMAC(message []byte, key *[]byte, algorithm HashAlgorithm) ([]byte, error)

	// GenerateMessage computes the time counter T for TOTP using configurable
	// parameters per RFC 6238 Section 4.2.
	GenerateMessage(timestamp int64, offsetType uint8, timeStep int64, t0 int64) (int64, error)

	// GenerateToken generates a TOTP token per RFC 6238 with configurable hash algorithm,
	// time step, and epoch offset (RFC 6238 Section 4.2).
	GenerateToken(unixTimestamp int64, key *[]byte, offsetType uint8, tokenlength uint8, algorithm HashAlgorithm, timeStep int64, t0 int64) (int, error)

	// ValidateToken validates a submitted TOTP token with configurable algorithm
	// and time parameters per RFC 6238 Section 5.2.
	ValidateToken(token int, key *[]byte, unixTimestamp int64, tokenlength uint8, algorithm HashAlgorithm, timeStep int64, t0 int64) (bool, error)

	// ValidateTokenCurrentTimestamp validates a TOTP token against the current
	// Unix timestamp with configurable parameters (RFC 6238 Section 5.2).
	ValidateTokenCurrentTimestamp(token int, key *[]byte, tokenlength uint8, algorithm HashAlgorithm, timeStep int64, t0 int64) Validation

	// ValidateTokenWithTimestamp validates a TOTP token against a provided
	// Unix timestamp with configurable parameters (RFC 6238 Section 5.2).
	ValidateTokenWithTimestamp(token int, key *[]byte, timestamp int64, tokenlength uint8, algorithm HashAlgorithm, timeStep int64, t0 int64) Validation

	// GenerateQrCode generates a QRCode for the provided issuer, user and secret with specified algorithm and timeStep.
	GenerateQrCode(issuer, user string, secret *string, digits uint8, algorithm HashAlgorithm, timeStep int64) ([]byte, error)

	// ConvertColorSetting converts the ColorSetting struct into a color.Color object.
	ConvertColorSetting(setting structs.ColorSetting) color.Color

	// WriteQrCodeImage writes a QR code PNG to the filesystem with specified algorithm and timeStep.
	WriteQrCodeImage(issuer, user string, secret *string, digits uint8, algorithm HashAlgorithm, timeStep int64, filepath string) error

	// BuildPayload builds the otpauth:// URL payload for QR code generation with specified algorithm and timeStep.
	BuildPayload(issuer, username string, secret *string, digits uint8, algorithm HashAlgorithm, timeStep int64) string

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
}

func NewTinyMfa() TinyMfaInterface {
	return &TinyMfa{
		QRCodeConfig: structs.StandardQrCodeConfig(),
	}
}

// GenerateStandardSecretKey returns a 20-byte secret key (SHA-1 recommended size).
func (tinymfa *TinyMfa) GenerateStandardSecretKey() (*[]byte, error) {
	return tinymfa.GenerateSecretKey(KeySizeSHA1)
}

// GenerateExtendedSecretKey returns a 32-byte secret key (SHA-256 recommended size).
func (tinymfa *TinyMfa) GenerateExtendedSecretKey() (*[]byte, error) {
	return tinymfa.GenerateSecretKey(KeySizeSHA256)
}

// GenerateSuperbSecretKey returns a 64-byte secret key (SHA-512 recommended size).
func (tinymfa *TinyMfa) GenerateSuperbSecretKey() (*[]byte, error) {
	return tinymfa.GenerateSecretKey(KeySizeSHA512)
}

// GenerateSecretKey returns a secret key of the specified size.
// Valid sizes are KeySizeSHA1 (20), KeySizeSHA256 (32), and KeySizeSHA512 (64).
func (tinymfa *TinyMfa) GenerateSecretKey(size int8) (*[]byte, error) {
	if size != KeySizeSHA1 && size != KeySizeSHA256 && size != KeySizeSHA512 {
		return nil, fmt.Errorf("invalid secret key size: %d (valid sizes: %d, %d, %d)", size, KeySizeSHA1, KeySizeSHA256, KeySizeSHA512)
	}
	key := make([]byte, size)
	_, err := rand.Read(key)

	return &key, err
}

// GenerateSecretKeyForAlgorithm generates a cryptographically random secret key with the
// recommended size for the specified hash algorithm. Key sizes follow the recommendation
// in RFC 6238 Section 4, which states that keys SHOULD be of the length of the HMAC output
// to facilitate interoperability.
//   - SHA-1:   20 bytes (160 bits)
//   - SHA-256: 32 bytes (256 bits)
//   - SHA-512: 64 bytes (512 bits)
func (tinymfa *TinyMfa) GenerateSecretKeyForAlgorithm(algorithm HashAlgorithm) (*[]byte, error) {
	switch algorithm {
	case SHA1:
		return tinymfa.GenerateSecretKey(KeySizeSHA1)
	case SHA256:
		return tinymfa.GenerateSecretKey(KeySizeSHA256)
	case SHA512:
		return tinymfa.GenerateSecretKey(KeySizeSHA512)
	default:
		return nil, fmt.Errorf("unsupported hash algorithm: %d", algorithm)
	}
}

// GenerateMessageBytes takes in a int64 number and turns it to a BigEndian byte array
func (tinymfa *TinyMfa) GenerateMessageBytes(message int64) ([]byte, error) {
	buffer := new(bytes.Buffer)
	err := binary.Write(buffer, binary.BigEndian, message)

	return buffer.Bytes(), err
}

// hashFuncForAlgorithm returns the hash.Hash constructor for the given HashAlgorithm.
// RFC 6238 Section 1.2 specifies SHA-1, SHA-256, and SHA-512 as valid hash functions.
func hashFuncForAlgorithm(algorithm HashAlgorithm) (func() hash.Hash, error) {
	switch algorithm {
	case SHA1:
		return sha1.New, nil
	case SHA256:
		return sha256.New, nil
	case SHA512:
		return sha512.New, nil
	default:
		return nil, fmt.Errorf("unsupported hash algorithm: %d", algorithm)
	}
}

// CalculateHMAC calculates the HMAC value for a given message and key
// using the specified hash algorithm. Supported algorithms are SHA-1, SHA-256, and SHA-512.
// RFC 2104 defines the HMAC construction. RFC 6238 Section 1.2 specifies the supported
// hash functions for TOTP.
func (tinymfa *TinyMfa) CalculateHMAC(message []byte, key *[]byte, algorithm HashAlgorithm) ([]byte, error) {
	hashFunc, err := hashFuncForAlgorithm(algorithm)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(hashFunc, *key)
	mac.Write(message)

	return mac.Sum(nil), nil
}

// GenerateMessage computes the time counter T for TOTP using configurable
// time step and epoch offset parameters. The counter is calculated as:
//
//	T = floor((unixTime + offset - t0) / timeStep)
//
// where offset is determined by offsetType: Present=0, Future=+timeStep, Past=-timeStep.
// RFC 6238 Section 4.2 defines the time counter computation.
// RFC 6238 Section 5.2 defines the time step size X (default 30s) and epoch T0 (default 0).
func (tinymfa *TinyMfa) GenerateMessage(timestamp int64, offsetType uint8, timeStep int64, t0 int64) (int64, error) {
	if timeStep <= 0 {
		return 0, fmt.Errorf("timeStep must be greater than 0, got %d", timeStep)
	}

	var offset int64
	switch offsetType {
	case Present:
		offset = 0
	case Future:
		offset = timeStep
	case Past:
		offset = -timeStep
	}

	adjusted := timestamp + offset - t0
	message := int64(math.Floor(float64(adjusted) / float64(timeStep)))

	return message, nil
}

// GenerateToken generates a TOTP token per RFC 6238 with configurable hash algorithm,
// time step, and epoch offset. This function implements the full TOTP generation pipeline:
//  1. Compute time counter T (RFC 6238 Section 4.2)
//  2. Convert T to 8-byte big-endian representation
//  3. Compute HMAC using the selected algorithm (RFC 2104)
//  4. Apply dynamic truncation (RFC 4226 Section 5.3)
//  5. Reduce to the requested number of digits (RFC 4226 Section 5.4)
//
// Supported token lengths are 5-8 digits. Supported algorithms are SHA1, SHA256, SHA512.
// RFC 6238 Section 4.2 recommends SHA-256 or SHA-512 for new deployments.
func (tinymfa *TinyMfa) GenerateToken(unixTimestamp int64, key *[]byte, offsetType uint8, tokenlength uint8, algorithm HashAlgorithm, timeStep int64, t0 int64) (int, error) {
	counter, err := tinymfa.GenerateMessage(unixTimestamp, offsetType, timeStep, t0)
	if err != nil {
		return 0, err
	}

	message, err := tinymfa.GenerateMessageBytes(counter)
	if err != nil {
		return 0, err
	}

	rfc2104hmac, err := tinymfa.CalculateHMAC(message, key, algorithm)
	if err != nil {
		return 0, err
	}

	// Dynamic truncation per RFC 4226 Section 5.3
	// The offset is the low-order 4 bits of the last byte of the HMAC result
	var offset int = int(rfc2104hmac[(len(rfc2104hmac)-1)] & 0xF)
	var truncResult int64
	for i := 0; i < 4; i++ {
		truncResult <<= 8
		truncResult |= int64(rfc2104hmac[offset+i] & 0xFF)
	}
	// Clear the most significant bit to avoid signed/unsigned issues (RFC 4226 Section 5.3)
	truncResult &= 0x7FFFFFFF

	// Compute TOTP value with the requested digit count (RFC 4226 Section 5.4)
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

	return int(truncResult), nil
}

// ValidateToken validates a submitted TOTP token against present, past, and future
// time windows using the specified hash algorithm and time parameters. The validation
// checks three consecutive time steps to account for clock drift between client and server.
// RFC 6238 Section 5.2 recommends validation across a window of time steps.
func (tinymfa *TinyMfa) ValidateToken(token int, key *[]byte, unixTimestamp int64, tokenlength uint8, algorithm HashAlgorithm, timeStep int64, t0 int64) (bool, error) {
	// Check present window
	generatedToken, err := tinymfa.GenerateToken(unixTimestamp, key, Present, tokenlength, algorithm, timeStep, t0)
	if err != nil {
		return false, err
	}
	if generatedToken == token {
		return true, nil
	}

	// Check past window
	generatedToken, err = tinymfa.GenerateToken(unixTimestamp, key, Past, tokenlength, algorithm, timeStep, t0)
	if err != nil {
		return false, err
	}
	if generatedToken == token {
		return true, nil
	}

	// Check future window
	generatedToken, err = tinymfa.GenerateToken(unixTimestamp, key, Future, tokenlength, algorithm, timeStep, t0)
	if err != nil {
		return false, err
	}
	if generatedToken == token {
		return true, nil
	}

	return false, nil
}

// ValidateTokenCurrentTimestamp validates a submitted TOTP token against the current
// Unix timestamp using the specified algorithm and time parameters. This is a convenience
// wrapper around ValidateToken that captures the current system time.
// RFC 6238 Section 5.2 defines the validation procedure.
func (tinymfa *TinyMfa) ValidateTokenCurrentTimestamp(token int, key *[]byte, tokenlength uint8, algorithm HashAlgorithm, timeStep int64, t0 int64) Validation {
	currentTimestamp := time.Now().Unix()
	return tinymfa.ValidateTokenWithTimestamp(token, key, currentTimestamp, tokenlength, algorithm, timeStep, t0)
}

// ValidateTokenWithTimestamp validates a submitted TOTP token against a provided
// Unix timestamp using the specified algorithm and time parameters. This is a convenience
// wrapper around ValidateToken that returns a Validation struct.
// RFC 6238 Section 5.2 defines the validation procedure.
func (tinymfa *TinyMfa) ValidateTokenWithTimestamp(token int, key *[]byte, timestamp int64, tokenlength uint8, algorithm HashAlgorithm, timeStep int64, t0 int64) Validation {
	result, err := tinymfa.ValidateToken(token, key, timestamp, tokenlength, algorithm, timeStep, t0)
	counter, counterErr := tinymfa.GenerateMessage(timestamp, Present, timeStep, t0)
	if counterErr != nil && err == nil {
		err = counterErr
	}
	return Validation{
		Message: counter,
		Success: result,
		Error:   err,
	}
}

// GenerateQrCode Generates a QRCode of the totp url with specified algorithm and timeStep
func (tinymfa *TinyMfa) GenerateQrCode(issuer, user string, secret *string, digits uint8, algorithm HashAlgorithm, timeStep int64) ([]byte, error) {
	var png []byte

	otpauthURL := tinymfa.BuildPayload(issuer, user, secret, digits, algorithm, timeStep)
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

// WriteQrCodeImage writes a png to the filesystem with specified algorithm and timeStep
func (tinymfa *TinyMfa) WriteQrCodeImage(issuer, user string, secret *string, digits uint8, algorithm HashAlgorithm, timeStep int64, filePath string) error {
	otpauthURL := tinymfa.BuildPayload(issuer, user, secret, digits, algorithm, timeStep)
	err := qrcode.WriteFile(otpauthURL, qrcode.Medium, 256, filePath)
	return err
}

// BuildPayload builds the otpauth:// URL payload for QR code generation with specified algorithm and timeStep.
func (tinymfa *TinyMfa) BuildPayload(issuer, username string, secret *string, digits uint8, algorithm HashAlgorithm, timeStep int64) string {
	index := strings.Index(*secret, "=")
	mySecret := *secret
	if index != -1 {
		mySecret = strings.TrimSuffix(*secret, "=")
	}

	// Determine algorithm string for the URL
	var algoStr string
	switch algorithm {
	case SHA1:
		algoStr = "SHA1"
	case SHA256:
		algoStr = "SHA256"
	case SHA512:
		algoStr = "SHA512"
	default:
		algoStr = "SHA1"
	}

	formatString := "otpauth://totp/%s:%s@%s?algorithm=%s&digits=%d&issuer=%s&period=%d&secret=%s"
	otpauthURL := fmt.Sprintf(formatString, issuer, username, issuer, algoStr, digits, issuer, timeStep, mySecret)
	mySecret = ""

	return otpauthURL
}

// GetQRCodeConfig returns the current QRCodeConfig for the QRCode.
func (tinymfa *TinyMfa) GetQRCodeConfig() structs.QrCodeConfig {
	return tinymfa.QRCodeConfig
}

// SetQRCodeConfig sets the QRCodeConfig for the QRCode.
func (tinymfa *TinyMfa) SetQRCodeConfig(qrcodeConfig structs.QrCodeConfig) {
	tinymfa.QRCodeConfig = qrcodeConfig
}
