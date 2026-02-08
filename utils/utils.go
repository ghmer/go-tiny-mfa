package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"io"
	"os"

	"golang.org/x/crypto/bcrypt"
)

type TinyMfaUtilInterface interface {
	// Encrypt takes in a byte array as data and another byte array as the passphrase,
	// encrypts the data using the AES cipher and returns the encrypted data (also as byte array)
	// please note that the nonce needed to encrypt the data using AES GCM is appended to the byte array
	Encrypt(data, passphrase *[]byte) (*[]byte, error)

	// EncryptFile takes a filePath as a string and a passphrase as a byte array.
	// The file found at filePath is then Encrypted using the Encrypt Method
	// and then wrote back to the original filePath
	EncryptFile(filePath string, data, passphrase *[]byte) error

	// Decrypt takes in two byte arrays. The former one is the encrypted data,
	// the second one is the passphrase that shall be used.
	// The method returns the decrypted data in another byte array
	// Attention: It is assumed that a nonce is appended to the encrypted
	// byte array!
	Decrypt(data, passphrase *[]byte) (*[]byte, error)

	// DecryptFile takes a filePath as a string and a passphrase as a byte array.
	// The file found at filePath is then decrypted using the Decrypt Method
	// and then wrote back to the original filePath
	DecryptFile(filePath string, passphrase *[]byte) (*[]byte, error)

	// DecodeBase32Key Decodes a base32 encoded key to a byte array
	DecodeBase32Key(encodedKey *string) (*[]byte, error)

	// EncodeBase32Key encodes a byte array to a base32 encoded string
	EncodeBase32Key(key *[]byte) *string

	// BcryptHash hashes a given byte array with bcrypt and a cost of 10
	BcryptHash(tohash []byte) ([]byte, error)

	// BycrptVerify compares a bcrypted comparable and its plain byte array
	BycrptVerify(comparable, verifiable []byte) error
}

type TinyMfaUtil struct{}

func NewTinyMfaUtil() TinyMfaUtilInterface {
	return &TinyMfaUtil{}
}

// Encrypt takes in a byte array as data and another byte array as the passphrase,
// encrypts the data using the AES cipher and returns the encrypted data (also as byte array)
// please note that the nonce needed to encrypt the data using AES GCM is appended to the byte array
func (util *TinyMfaUtil) Encrypt(data, passphrase *[]byte) (*[]byte, error) {
	if len(*passphrase) != 16 && len(*passphrase) != 32 {
		return nil, errors.New("keysize not supported")
	}
	block, _ := aes.NewCipher(*passphrase)
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, *data, nil)
	return &ciphertext, nil
}

// EncryptFile takes a filePath as a string and a passphrase as a byte array.
// The file found at filePath is then Encrypted using the Encrypt Method
// and then wrote back to the original filePath
func (util *TinyMfaUtil) EncryptFile(filePath string, data, passphrase *[]byte) error {
	f, _ := os.Create(filePath)
	defer f.Close()

	cdata, err := util.Encrypt(data, passphrase)
	if err != nil {
		return err
	}

	f.Write(*cdata)

	return nil
}

// Decrypt takes in two byte arrays. The former one is the encrypted data,
// the second one is the passphrase that shall be used.
// The method returns the decrypted data in another byte array
// Attention: It is assumed that a nonce is appended to the encrypted
// byte array!
func (util *TinyMfaUtil) Decrypt(data, passphrase *[]byte) (*[]byte, error) {
	if len(*passphrase) != 16 && len(*passphrase) != 32 {
		return nil, errors.New("keysize not supported")
	}
	block, err := aes.NewCipher(*passphrase)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	dataslice := *data

	nonce, ciphertext := dataslice[:nonceSize], dataslice[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	for i := range dataslice {
		dataslice[i] = 0 // clear the memory of the decrypted data for security reasons.
	}

	return &plaintext, nil
}

// DecryptFile takes a filePath as a string and a passphrase as a byte array.
// The file found at filePath is then decrypted using the Decrypt Method
// and then wrote back to the original filePath
func (util *TinyMfaUtil) DecryptFile(filePath string, passphrase *[]byte) (*[]byte, error) {
	data, _ := os.ReadFile(filePath)
	return util.Decrypt(&data, passphrase)
}

// DecodeBase32Key Decodes a base32 encoded key to a byte array
func (util *TinyMfaUtil) DecodeBase32Key(encodedKey *string) (*[]byte, error) {
	key, err := base32.StdEncoding.DecodeString(*encodedKey)
	return &key, err
}

// EncodeBase32Key encodes a byte array to a base32 encoded string
func (util *TinyMfaUtil) EncodeBase32Key(key *[]byte) *string {
	encodedString := base32.StdEncoding.EncodeToString(*key)
	return &encodedString
}

// BcryptHash hashes a given byte array with bcrypt and a cost of 10
func (util *TinyMfaUtil) BcryptHash(tohash []byte) ([]byte, error) {
	// Hashing with a default cost of 10
	hash, err := bcrypt.GenerateFromPassword(tohash, bcrypt.DefaultCost)
	return hash, err
}

// BycrptVerify compares a bcrypted comparable and its plain byte array
func (util *TinyMfaUtil) BycrptVerify(comparable, verifiable []byte) error {
	// Comparing the password with the hash
	err := bcrypt.CompareHashAndPassword(comparable, verifiable)
	return err
}
