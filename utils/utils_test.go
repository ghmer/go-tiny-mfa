package utils_test

import (
	"os"
	"path"
	"testing"

	"github.com/ghmer/go-tiny-mfa/utils"
)

var util = utils.NewTinyMfaUtil()
var passphrase = []byte("mysecretpassword")
var invalidpassphrase = []byte("invalidpassphrase")
var data = []byte("Hello, World!")

var encodedstring = "JBSWY3DPFQQHO33SNRSCC==="
var decodedstring = "Hello, world!"

func TestNewTinyMfaUtil(t *testing.T) {
	if util == nil {
		t.Errorf("Expected NewTinyMfaUtil to return a non-nil value")
	}
}

func TestEncrypt(t *testing.T) {
	encryptedData, err := util.Encrypt(&data, &passphrase)
	if err != nil {
		t.Errorf("Expected Encrypt to return no error, but got: %v", err)
	}

	if len(*encryptedData) == 0 {
		t.Errorf("Expected encrypted data to be non-empty")
	}
}

func TestEncryptFile(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "test-encrypt-file-")
	if err != nil {
		t.Errorf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	err = util.EncryptFile(path.Join(tempDir, "test.txt"), &data, &passphrase)
	if err != nil {
		t.Errorf("Failed to create temp dir: %v", err)
	}
	// Test with an invalid passphrase (invalid AES key size)
	err = util.EncryptFile(path.Join(tempDir, "test.txt"), &data, &invalidpassphrase)
	if err == nil {
		t.Errorf("Expected error when encrypting with invalid passphrase")
	}
}

func TestDecrypt(t *testing.T) {
	encryptedData, err := util.Encrypt(&data, &passphrase)
	if err != nil {
		t.Errorf("Failed to encrypt data: %v", err)
	}

	decryptedData, err := util.Decrypt(encryptedData, &passphrase)
	if err != nil {
		t.Errorf("Failed to decrypt data: %v", err)
	}
	if string(*decryptedData) != "Hello, World!" {
		t.Errorf("Expected decrypted data to match original data")
	}

	// Test with an invalid passphrase
	_, err = util.Decrypt(encryptedData, &invalidpassphrase)
	if err == nil {
		t.Errorf("Expected error when decrypting with invalid passphrase")
	}
}

func TestDecryptFile(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "test-decrypt-file-")
	if err != nil {
		t.Errorf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	util.EncryptFile(path.Join(tempDir, "test.txt"), &data, &passphrase)

	decryptedData, err := util.DecryptFile(path.Join(tempDir, "test.txt"), &passphrase)
	if err != nil {
		t.Errorf("Failed to decrypt file: %v", err)
	}
	if string(*decryptedData) != "Hello, World!" {
		t.Errorf("Expected decrypted data to match original data")
	}

	// Test with an invalid passphrase
	_, err = util.DecryptFile(path.Join(tempDir, "test.txt"), &invalidpassphrase)
	if err == nil {
		t.Errorf("Expected error when decrypting with invalid passphrase")
	}
}

func TestDecodeBase32Key(t *testing.T) {
	decodedKey, err := util.DecodeBase32Key(&encodedstring)
	if err != nil {
		t.Errorf("Failed to decode base32 key: %v", err)
	}
	if len(*decodedKey) != len(decodedstring) {
		t.Errorf("Expected decoded key to be 16 bytes long, got %d", len(*decodedKey))
	}

	// Test with an invalid base32 string
	key := "InvalidBase32String"
	_, err = util.DecodeBase32Key(&key)
	if err == nil {
		t.Errorf("Expected error with invalid base32 string")
	}
}

func TestEncodeBase32Key(t *testing.T) {
	encodedKey := util.EncodeBase32Key(&passphrase)
	if len(*encodedKey) != 32 {
		t.Errorf("Expected encoded key to be 31 bytes long, got %d", len(*encodedKey))

	}

	// Test with an empty passphrase
	emptyPassphrase := []byte{}
	encodedKey = util.EncodeBase32Key(&emptyPassphrase)
	if len(*encodedKey) != 0 {
		t.Errorf("Expected encoded key to be empty with empty passphrase")
	}
}

func TestBcryptHash(t *testing.T) {
	hash, err := util.BcryptHash(passphrase)
	if err != nil {
		t.Errorf("Failed to generate bcrypt hash: %v", err)
	}
	if len(hash) < 60 {
		t.Errorf("Expected bcrypt hash to be at least 60 bytes long")
	}
}

func TestBycrptVerify(t *testing.T) {
	hash, err := util.BcryptHash(passphrase)
	if err != nil {
		t.Errorf("Failed to generate bcrypt hash: %v", err)
	}

	err = util.BycrptVerify(hash, passphrase)
	if err != nil {
		t.Errorf("Expected bcrypt verify to succeed: %v", err)
	}

	// Test with an invalid passphrase

	err = util.BycrptVerify(hash, invalidpassphrase)
	if err == nil {
		t.Errorf("Expected error with invalid passphrase")
	}
}
