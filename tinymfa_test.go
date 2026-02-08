package tinymfa_test

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"os"
	"testing"
	"time"

	tinymfa "github.com/ghmer/go-tiny-mfa"
	"github.com/ghmer/go-tiny-mfa/structs"
	"github.com/ghmer/go-tiny-mfa/utils"
)

// RFC 6238 Appendix B test seed keys
var keySHA1 = []byte("12345678901234567890")                                               // 20 bytes
var keySHA256 = []byte("12345678901234567890123456789012")                                 // 32 bytes
var keySHA512 = []byte("1234567890123456789012345678901234567890123456789012345678901234") // 64 bytes

var tmfa = tinymfa.NewTinyMfa()
var mfautil = utils.NewTinyMfaUtil()

// RFC 6238 Appendix B test timestamps
var rfcTestTimes = []int64{59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000}

// RFC 6238 Appendix B expected 8-digit tokens
var rfcExpectedSHA1 = []int{94287082, 7081804, 14050471, 89005924, 69279037, 65353130}
var rfcExpectedSHA256 = []int{46119246, 68084774, 67062674, 91819424, 90698825, 77737706}
var rfcExpectedSHA512 = []int{90693936, 25091201, 99943326, 93441116, 38618901, 47863826}

func TestGenerateStandardSecretKey(t *testing.T) {
	key, err := tmfa.GenerateStandardSecretKey()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(*key) != int(tinymfa.KeySizeSHA1) {
		t.Errorf("expected key length %d, got %d", tinymfa.KeySizeSHA1, len(*key))
	}
}

func TestGenerateExtendedSecretKey(t *testing.T) {
	key, err := tmfa.GenerateExtendedSecretKey()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(*key) != int(tinymfa.KeySizeSHA256) {
		t.Errorf("expected key length %d, got %d", tinymfa.KeySizeSHA256, len(*key))
	}
}

func TestGenerateSecretKey(t *testing.T) {
	key, err := tmfa.GenerateSecretKey(tinymfa.KeySizeSHA1)
	if err != nil {
		t.Fatalf("unexpected error for SHA1 size: %v", err)
	}
	if len(*key) != int(tinymfa.KeySizeSHA1) {
		t.Errorf("expected key length %d, got %d", tinymfa.KeySizeSHA1, len(*key))
	}

	key, err = tmfa.GenerateSecretKey(tinymfa.KeySizeSHA256)
	if err != nil {
		t.Fatalf("unexpected error for SHA256 size: %v", err)
	}
	if len(*key) != int(tinymfa.KeySizeSHA256) {
		t.Errorf("expected key length %d, got %d", tinymfa.KeySizeSHA256, len(*key))
	}

	key, err = tmfa.GenerateSecretKey(tinymfa.KeySizeSHA512)
	if err != nil {
		t.Fatalf("unexpected error for SHA512 size: %v", err)
	}
	if len(*key) != int(tinymfa.KeySizeSHA512) {
		t.Errorf("expected key length %d, got %d", tinymfa.KeySizeSHA512, len(*key))
	}

	_, err = tmfa.GenerateSecretKey(17)
	if err == nil {
		t.Error("expected error for invalid key size, got nil")
	}
}

func TestGenerateSecretKeyForAlgorithm(t *testing.T) {
	tests := []struct {
		name      string
		algorithm tinymfa.HashAlgorithm
		expected  int
	}{
		{"SHA1", tinymfa.SHA1, int(tinymfa.KeySizeSHA1)},
		{"SHA256", tinymfa.SHA256, int(tinymfa.KeySizeSHA256)},
		{"SHA512", tinymfa.SHA512, int(tinymfa.KeySizeSHA512)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := tmfa.GenerateSecretKeyForAlgorithm(tt.algorithm)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(*key) != tt.expected {
				t.Errorf("expected key length %d, got %d", tt.expected, len(*key))
			}
		})
	}

	// Test invalid algorithm
	_, err := tmfa.GenerateSecretKeyForAlgorithm(99)
	if err == nil {
		t.Error("expected error for invalid algorithm, got nil")
	}
}

func TestGenerateMessageBytes(t *testing.T) {
	message, err := tmfa.GenerateMessageBytes(1234567890)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(message) != 8 {
		t.Errorf("expected 8 bytes, got %d", len(message))
	}
}

func TestCalculateHMAC(t *testing.T) {
	message, _ := tmfa.GenerateMessageBytes(1234567890)

	tests := []struct {
		name         string
		key          *[]byte
		algorithm    tinymfa.HashAlgorithm
		expectedSize int
	}{
		{"SHA1", &keySHA1, tinymfa.SHA1, sha1.Size},
		{"SHA256", &keySHA256, tinymfa.SHA256, sha256.Size},
		{"SHA512", &keySHA512, tinymfa.SHA512, sha512.Size},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hmac, err := tmfa.CalculateHMAC(message, tt.key, tt.algorithm)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(hmac) != tt.expectedSize {
				t.Errorf("expected HMAC length %d, got %d", tt.expectedSize, len(hmac))
			}
		})
	}

	// Test invalid algorithm
	_, err := tmfa.CalculateHMAC(message, &keySHA1, 99)
	if err == nil {
		t.Error("expected error for invalid algorithm, got nil")
	}
}

func TestGenerateMessage(t *testing.T) {
	messagePresent, _ := tmfa.GenerateMessage(1234567890, tinymfa.Present, tinymfa.DefaultTimeStep, tinymfa.DefaultT0)
	messageFuture, _ := tmfa.GenerateMessage(1234567890, tinymfa.Future, tinymfa.DefaultTimeStep, tinymfa.DefaultT0)
	messagePast, _ := tmfa.GenerateMessage(1234567890, tinymfa.Past, tinymfa.DefaultTimeStep, tinymfa.DefaultT0)

	if messageFuture != messagePresent+1 {
		t.Errorf("expected future=%d, got %d", messagePresent+1, messageFuture)
	}
	if messagePast != messagePresent-1 {
		t.Errorf("expected past=%d, got %d", messagePresent-1, messagePast)
	}
}

func TestGenerateMessageWithParams(t *testing.T) {
	// Test with default parameters
	expected, _ := tmfa.GenerateMessage(1234567890, tinymfa.Present, tinymfa.DefaultTimeStep, tinymfa.DefaultT0)
	got, err := tmfa.GenerateMessage(1234567890, tinymfa.Present, tinymfa.DefaultTimeStep, tinymfa.DefaultT0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != expected {
		t.Errorf("expected %d, got %d", expected, got)
	}

	// Test with different timeStep (60s)
	// 1234567890 % 60 = 30, so timestamp = 1234567890 - 30 = 1234567860
	// message = floor(1234567860 / 60) = 20576131
	got60, err := tmfa.GenerateMessage(1234567890, tinymfa.Present, 60, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got60 != 20576131 {
		t.Errorf("expected 20576131, got %d", got60)
	}

	// Test timeStep=0 returns error
	_, err = tmfa.GenerateMessage(1234567890, tinymfa.Present, 0, 0)
	if err == nil {
		t.Error("expected error for timeStep=0, got nil")
	}

	// Test negative timeStep returns error
	_, err = tmfa.GenerateMessage(1234567890, tinymfa.Present, -1, 0)
	if err == nil {
		t.Error("expected error for negative timeStep, got nil")
	}
}

func TestGenerateToken(t *testing.T) {
	// Verify all 6 RFC SHA-1 test vectors with 8-digit tokens
	for i, ts := range rfcTestTimes {
		token, err := tmfa.GenerateToken(ts, &keySHA1, tinymfa.Present, 8, tinymfa.SHA1, tinymfa.DefaultTimeStep, tinymfa.DefaultT0)
		if err != nil {
			t.Fatalf("unexpected error for timestamp %d: %v", ts, err)
		}
		if token != rfcExpectedSHA1[i] {
			t.Errorf("timestamp %d: expected %d, got %d", ts, rfcExpectedSHA1[i], token)
		}
	}

	// Test token lengths 5-8 produce no errors
	for _, length := range []uint8{5, 6, 7, 8} {
		_, err := tmfa.GenerateToken(1234567890, &keySHA1, tinymfa.Present, length, tinymfa.SHA1, tinymfa.DefaultTimeStep, tinymfa.DefaultT0)
		if err != nil {
			t.Errorf("unexpected error for token length %d: %v", length, err)
		}
	}

	// Test invalid length 9 returns error
	_, err := tmfa.GenerateToken(1234567890, &keySHA1, tinymfa.Present, 9, tinymfa.SHA1, tinymfa.DefaultTimeStep, tinymfa.DefaultT0)
	if err == nil {
		t.Error("expected error for token length 9, got nil")
	}
}

func TestGenerateTokenAllAlgorithms(t *testing.T) {
	tests := []struct {
		name      string
		timestamp int64
		key       *[]byte
		algorithm tinymfa.HashAlgorithm
		expected  int
	}{
		// SHA-1 test vectors
		{"SHA1/59", 59, &keySHA1, tinymfa.SHA1, 94287082},
		{"SHA1/1111111109", 1111111109, &keySHA1, tinymfa.SHA1, 7081804},
		{"SHA1/1111111111", 1111111111, &keySHA1, tinymfa.SHA1, 14050471},
		{"SHA1/1234567890", 1234567890, &keySHA1, tinymfa.SHA1, 89005924},
		{"SHA1/2000000000", 2000000000, &keySHA1, tinymfa.SHA1, 69279037},
		{"SHA1/20000000000", 20000000000, &keySHA1, tinymfa.SHA1, 65353130},
		// SHA-256 test vectors
		{"SHA256/59", 59, &keySHA256, tinymfa.SHA256, 46119246},
		{"SHA256/1111111109", 1111111109, &keySHA256, tinymfa.SHA256, 68084774},
		{"SHA256/1111111111", 1111111111, &keySHA256, tinymfa.SHA256, 67062674},
		{"SHA256/1234567890", 1234567890, &keySHA256, tinymfa.SHA256, 91819424},
		{"SHA256/2000000000", 2000000000, &keySHA256, tinymfa.SHA256, 90698825},
		{"SHA256/20000000000", 20000000000, &keySHA256, tinymfa.SHA256, 77737706},
		// SHA-512 test vectors
		{"SHA512/59", 59, &keySHA512, tinymfa.SHA512, 90693936},
		{"SHA512/1111111109", 1111111109, &keySHA512, tinymfa.SHA512, 25091201},
		{"SHA512/1111111111", 1111111111, &keySHA512, tinymfa.SHA512, 99943326},
		{"SHA512/1234567890", 1234567890, &keySHA512, tinymfa.SHA512, 93441116},
		{"SHA512/2000000000", 2000000000, &keySHA512, tinymfa.SHA512, 38618901},
		{"SHA512/20000000000", 20000000000, &keySHA512, tinymfa.SHA512, 47863826},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := tmfa.GenerateToken(tt.timestamp, tt.key, tinymfa.Present, 8, tt.algorithm, tinymfa.DefaultTimeStep, tinymfa.DefaultT0)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if token != tt.expected {
				t.Errorf("expected %d, got %d", tt.expected, token)
			}
		})
	}
}

func TestGenerateTokenInvalidInputs(t *testing.T) {
	// Invalid token length
	_, err := tmfa.GenerateToken(1234567890, &keySHA1, tinymfa.Present, 9, tinymfa.SHA1, tinymfa.DefaultTimeStep, tinymfa.DefaultT0)
	if err == nil {
		t.Error("expected error for token length 9, got nil")
	}

	// Invalid algorithm
	_, err = tmfa.GenerateToken(1234567890, &keySHA1, tinymfa.Present, 8, 99, tinymfa.DefaultTimeStep, tinymfa.DefaultT0)
	if err == nil {
		t.Error("expected error for invalid algorithm, got nil")
	}

	// timeStep=0
	_, err = tmfa.GenerateToken(1234567890, &keySHA1, tinymfa.Present, 8, tinymfa.SHA1, 0, tinymfa.DefaultT0)
	if err == nil {
		t.Error("expected error for timeStep=0, got nil")
	}
}

func TestValidateToken(t *testing.T) {
	ts := int64(1234567890)
	tokenPresent, _ := tmfa.GenerateToken(ts, &keySHA1, tinymfa.Present, 8, tinymfa.SHA1, tinymfa.DefaultTimeStep, tinymfa.DefaultT0)
	tokenFuture, _ := tmfa.GenerateToken(ts, &keySHA1, tinymfa.Future, 8, tinymfa.SHA1, tinymfa.DefaultTimeStep, tinymfa.DefaultT0)
	tokenPast, _ := tmfa.GenerateToken(ts, &keySHA1, tinymfa.Past, 8, tinymfa.SHA1, tinymfa.DefaultTimeStep, tinymfa.DefaultT0)

	valid, err := tmfa.ValidateToken(tokenPresent, &keySHA1, ts, 8, tinymfa.SHA1, tinymfa.DefaultTimeStep, tinymfa.DefaultT0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !valid {
		t.Error("expected present token to be valid")
	}

	valid, err = tmfa.ValidateToken(tokenFuture, &keySHA1, ts, 8, tinymfa.SHA1, tinymfa.DefaultTimeStep, tinymfa.DefaultT0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !valid {
		t.Error("expected future token to be valid")
	}

	valid, err = tmfa.ValidateToken(tokenPast, &keySHA1, ts, 8, tinymfa.SHA1, tinymfa.DefaultTimeStep, tinymfa.DefaultT0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !valid {
		t.Error("expected past token to be valid")
	}
}

func TestValidateTokenAllAlgorithms(t *testing.T) {
	ts := int64(1234567890)
	token, _ := tmfa.GenerateToken(ts, &keySHA256, tinymfa.Present, 8, tinymfa.SHA256, tinymfa.DefaultTimeStep, tinymfa.DefaultT0)

	valid, err := tmfa.ValidateToken(token, &keySHA256, ts, 8, tinymfa.SHA256, tinymfa.DefaultTimeStep, tinymfa.DefaultT0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !valid {
		t.Error("expected token to be valid")
	}

	// Invalid token should return false
	valid, err = tmfa.ValidateToken(12345678, &keySHA256, ts, 8, tinymfa.SHA256, tinymfa.DefaultTimeStep, tinymfa.DefaultT0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if valid {
		t.Error("expected invalid token to return false")
	}
}

func TestValidateTokenCurrentTimestamp(t *testing.T) {
	now := time.Now().Unix()
	token, err := tmfa.GenerateToken(now, &keySHA1, tinymfa.Present, 8, tinymfa.SHA1, tinymfa.DefaultTimeStep, tinymfa.DefaultT0)
	if err != nil {
		t.Fatalf("unexpected error generating token: %v", err)
	}

	result := tmfa.ValidateTokenCurrentTimestamp(token, &keySHA1, 8, tinymfa.SHA1, tinymfa.DefaultTimeStep, tinymfa.DefaultT0)
	if result.Error != nil {
		t.Fatalf("unexpected error: %v", result.Error)
	}
	if !result.Success {
		t.Error("expected token to be valid")
	}
}

func TestValidateTokenWithTimestamp(t *testing.T) {
	// Validate RFC test vector tokens against their timestamps
	tests := []struct {
		name     string
		expected []int
		key      *[]byte
		algo     tinymfa.HashAlgorithm
	}{
		{"SHA1", rfcExpectedSHA1, &keySHA1, tinymfa.SHA1},
		{"SHA256", rfcExpectedSHA256, &keySHA256, tinymfa.SHA256},
		{"SHA512", rfcExpectedSHA512, &keySHA512, tinymfa.SHA512},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for i, ts := range rfcTestTimes {
				result := tmfa.ValidateTokenWithTimestamp(tt.expected[i], tt.key, ts, 8, tt.algo, tinymfa.DefaultTimeStep, tinymfa.DefaultT0)
				if result.Error != nil {
					t.Fatalf("unexpected error for timestamp %d: %v", ts, result.Error)
				}
				if !result.Success {
					t.Errorf("expected token %d to be valid for timestamp %d", tt.expected[i], ts)
				}
			}
		})
	}
}

func TestUtilEncode(t *testing.T) {
	encoded := mfautil.EncodeBase32Key(&keySHA1)
	if encoded == nil || len(*encoded) == 0 {
		t.Error("expected non-empty encoded key")
	}
}

func TestUtilDecode(t *testing.T) {
	encoded := mfautil.EncodeBase32Key(&keySHA1)
	decoded, err := mfautil.DecodeBase32Key(encoded)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for i, b := range *decoded {
		if b != keySHA1[i] {
			t.Errorf("decoded key mismatch at index %d: expected %d, got %d", i, keySHA1[i], b)
		}
	}
}

func TestGenerateQrCode(t *testing.T) {
	encoded := mfautil.EncodeBase32Key(&keySHA1)
	issuer := "tinymfa.test"
	user := "demo"
	var digits uint8 = 8

	// Test GenerateQrCode returns valid PNG data with SHA1
	qrcode, err := tmfa.GenerateQrCode(issuer, user, encoded, digits, tinymfa.SHA1, 30)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(qrcode) == 0 {
		t.Error("expected non-empty QR code data")
	}

	// Test with SHA256
	encoded256 := mfautil.EncodeBase32Key(&keySHA256)
	qrcode256, err := tmfa.GenerateQrCode(issuer, user, encoded256, digits, tinymfa.SHA256, 30)
	if err != nil {
		t.Fatalf("unexpected error for SHA256: %v", err)
	}
	if len(qrcode256) == 0 {
		t.Error("expected non-empty QR code data for SHA256")
	}

	// Test WriteQrCodeImage writes a file
	path := "./test_qrcode.png"
	defer os.Remove(path)
	err = tmfa.WriteQrCodeImage(issuer, user, encoded, digits, tinymfa.SHA1, 30, path)
	if err != nil {
		t.Fatalf("unexpected error writing QR code: %v", err)
	}
}

func TestConvertColorSetting(t *testing.T) {
	setting := structs.ColorSetting{Red: 255, Green: 0, Blue: 0, Alpha: 128}
	color := tmfa.ConvertColorSetting(setting)
	r, g, b, a := color.RGBA()
	if r != 65535 || g != 0 || b != 0 || a != 32896 {
		t.Errorf("expected RGBA (65535, 0, 0, 32896), got (%d, %d, %d, %d)", r, g, b, a)
	}
}

func TestSetQRCodeConfig(t *testing.T) {
	newConfig := structs.QrCodeConfig{
		BgColor: structs.ColorSetting{Red: 255, Green: 0, Blue: 0, Alpha: 128},
		FgColor: structs.ColorSetting{Red: 255, Green: 0, Blue: 0, Alpha: 128},
	}
	tmfa.SetQRCodeConfig(newConfig)
	got := tmfa.GetQRCodeConfig()
	if got != newConfig {
		t.Errorf("expected QRCodeConfig %v, got %v", newConfig, got)
	}
}

func TestGetQRCodeConfig(t *testing.T) {
	config := tmfa.GetQRCodeConfig()
	if config == (structs.QrCodeConfig{}) {
		t.Error("expected non-zero QR code config")
	}
}
