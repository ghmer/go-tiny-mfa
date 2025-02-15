package tinymfa_test

import (
	"crypto/sha1"
	"os"
	"strconv"
	"testing"
	"time"

	tinymfa "github.com/ghmer/go-tiny-mfa"
	"github.com/ghmer/go-tiny-mfa/utils"
)

const (
	TimeStamp                        int64 = 1234567890
	TokenNow, TokenFuture, TokenPast int   = 617213, 892079, 601302
)

var Key = []byte{1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 1}
var EncodedKey = ""
var tmfa = tinymfa.NewTinyMfa()
var mfautil = utils.NewTinyMfaUtil()

func TestGenerateStandardSecretKey(t *testing.T) {
	key, err := tmfa.GenerateStandardSecretKey()
	if err != nil {
		t.Errorf("Error generating standard secret key: %v", err)
	}
	if len(*key) != int(tinymfa.KeySizeStandard) {
		t.Errorf("Incorrect key length. Expected %d bytes, got %d bytes", tinymfa.KeySizeStandard, len(*key))
	}
}

func TestGenerateExtendedSecretKey(t *testing.T) {
	key, err := tmfa.GenerateExtendedSecretKey()
	if err != nil {
		t.Errorf("Error generating extended secret key: %v", err)
	}
	if len(*key) != int(tinymfa.KeySizeExtended) {
		t.Errorf("Incorrect key length. Expected %d bytes, got %d bytes", tinymfa.KeySizeExtended, len(*key))
	}
}

func TestGenerateSecretKey(t *testing.T) {
	key, err := tmfa.GenerateSecretKey(tinymfa.KeySizeStandard)
	if err != nil {
		t.Errorf("Error generating secret key: %v", err)
	}
	if len(*key) != int(tinymfa.KeySizeStandard) {
		t.Errorf("Incorrect key length. Expected %d bytes, got %d bytes", tinymfa.KeySizeStandard, len(*key))
	}

	key, err = tmfa.GenerateSecretKey(tinymfa.KeySizeExtended)
	if err != nil {
		t.Errorf("Error generating secret key: %v", err)
	}
	if len(*key) != int(tinymfa.KeySizeExtended) {
		t.Errorf("Incorrect key length. Expected %d bytes, got %d bytes", tinymfa.KeySizeExtended, len(*key))
	}

	_, err = tmfa.GenerateSecretKey(tinymfa.KeySizeStandard + 1)
	if err == nil {
		t.Errorf("Expected error generating secret key with invalid size")
	}
}

func TestGenerateMessageBytes(t *testing.T) {
	message, err := tmfa.GenerateMessageBytes(1234567890)
	if err != nil {
		t.Errorf("Error generating message bytes: %v", err)
	}
	if len(message) != 8 {
		t.Errorf("Incorrect message length. Expected 8 bytes, got %d bytes", len(message))
	}
}

func TestCalculateHMAC(t *testing.T) {
	message := []byte{1, 2, 3, 4, 5}
	hmac := tmfa.CalculateHMAC(message, &Key)
	if len(hmac) != sha1.Size {
		t.Errorf("Incorrect HMAC length. Expected %d bytes, got %d bytes", sha1.Size, len(hmac))
	}

	hmac = tmfa.CalculateHMAC(message, &Key)
	if len(hmac) != sha1.Size {
		t.Errorf("Incorrect HMAC length. Expected %d bytes, got %d bytes", sha1.Size, len(hmac))
	}
}

func TestGenerateMessage(t *testing.T) {
	messageNow := tmfa.GenerateMessage(TimeStamp, tinymfa.Present)

	messageFuture := tmfa.GenerateMessage(TimeStamp, tinymfa.Future)
	if messageFuture != messageNow+1 {
		t.Errorf("Incorrect message value. Expected %d, got %d", messageNow+1, messageFuture)
	}

	messagePast := tmfa.GenerateMessage(TimeStamp, tinymfa.Past)
	if messagePast != messageNow-1 {
		t.Errorf("Incorrect message value. Expected %d, got %d", messageNow-1, messagePast)
	}
}

func TestGenerateValidToken(t *testing.T) {
	token, _ := tmfa.GenerateValidToken(TimeStamp, &Key, tinymfa.Present, 6)
	if token != TokenNow {
		t.Errorf("Incorrect token value. Expected %d, got %d", TokenNow, token)
	}

	token, _ = tmfa.GenerateValidToken(TimeStamp, &Key, tinymfa.Future, 6)
	if token != TokenFuture {
		t.Errorf("Incorrect token value. Expected %d, got %d", TokenFuture, token)
	}

	token, _ = tmfa.GenerateValidToken(TimeStamp, &Key, tinymfa.Past, 6)
	if token != TokenPast {
		t.Errorf("Incorrect token value. Expected %d, got %d", TokenPast, token)
	}

	token, _ = tmfa.GenerateValidToken(TimeStamp, &Key, tinymfa.Present, 5)
	length := strconv.Itoa(token)
	if len(length) != 5 {
		t.Errorf("Incorrect token value. Expected %d, got %d", 5, len(length))
	}

	token, _ = tmfa.GenerateValidToken(TimeStamp, &Key, tinymfa.Present, 6)
	length = strconv.Itoa(token)
	if len(length) != 6 {
		t.Errorf("Incorrect token value. Expected %d, got %d", 6, len(length))
	}

	token, _ = tmfa.GenerateValidToken(TimeStamp, &Key, tinymfa.Present, 7)
	length = strconv.Itoa(token)
	if len(length) != 7 {
		t.Errorf("Incorrect token value. Expected %d, got %d", 7, len(length))
	}

	token, _ = tmfa.GenerateValidToken(TimeStamp, &Key, tinymfa.Present, 8)
	length = strconv.Itoa(token)
	if len(length) != 8 {
		t.Errorf("Incorrect token value. Expected %d, got %d", 8, len(length))
	}

	_, err := tmfa.GenerateValidToken(TimeStamp, &Key, tinymfa.Present, 9)
	if err == nil {
		t.Errorf("Expected error when generating a token with size %d, got nil", 9)
	}

}

func TestValidateToken(t *testing.T) {
	valid, _ := tmfa.ValidateToken(TokenNow, &Key, TimeStamp, 6)
	if !valid {
		t.Errorf("Expected token to be valid")
	}

	valid, _ = tmfa.ValidateToken(TokenFuture, &Key, TimeStamp, 6)
	if !valid {
		t.Errorf("Expected token to be valid")
	}

	valid, _ = tmfa.ValidateToken(TokenPast, &Key, TimeStamp, 6)
	if !valid {
		t.Errorf("Expected token to be valid")
	}
}

func TestValidateTokenWithTimestamp(t *testing.T) {
	token, _ := tmfa.GenerateValidToken(TimeStamp, &Key, tinymfa.Present, 6)
	valid := tmfa.ValidateTokenWithTimestamp(token, &Key, TimeStamp, 6)
	if !valid.Success {
		t.Errorf("Expected token to be valid")
	}
}

func TestValidateTokenCurrentTimestamp(t *testing.T) {
	now := time.Now().Unix()
	token, _ := tmfa.GenerateValidToken(now, &Key, tinymfa.Present, 6)
	valid := tmfa.ValidateTokenCurrentTimestamp(token, &Key, 6)
	if !valid.Success {
		t.Errorf("Expected token to be valid")
	}
}

func TestUtilEncode(t *testing.T) {
	EncodedKey = *mfautil.EncodeBase32Key(&Key)
}

func TestUtilDecode(t *testing.T) {
	array, _ := mfautil.DecodeBase32Key(&EncodedKey)
	for i, b := range *array {
		if b != Key[i] {
			t.Errorf("Expected decoded key to be equal to original key")
		}
	}
}

func TestGenerateQrCode(t *testing.T) {
	var issuer string = "tinymfa.parzival.link"
	var user string = "demo"
	//var key string = base32.StdEncoding.EncodeToString(Key)
	var digits uint8 = 6

	qrcode, err := tmfa.GenerateQrCode(issuer, user, &EncodedKey, digits)
	if err != nil {
		panic(err)
	}
	// write png to file
	os.WriteFile("./qrcode1.png", qrcode, 0644)

	// shorthand for the above
	tmfa.WriteQrCodeImage(issuer, user, &EncodedKey, digits, "./qrcode2.png")

}
