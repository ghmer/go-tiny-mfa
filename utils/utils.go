package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base32"
	"io"
	"os"

	"golang.org/x/crypto/bcrypt"
)

type TinyMfaUtilInterface interface {
	// Encrypt takes in a byte array as data and another byte array as the passphrase,
	// encrypts the data using the AES cipher and returns the encrypted data (also as byte array)
	// please note that the nonce needed to encrypt the data using AES GCM is appended to the byte array
	Encrypt(data, passphrase *[]byte) *[]byte

	// EncryptFile takes a filePath as a string and a passphrase as a byte array.
	// The file found at filePath is then Encrypted using the Encrypt Method
	// and then wrote back to the original filePath
	EncryptFile(filePath string, data, passphrase *[]byte)

	// Decrypt takes in two byte arrays. The former one is the encrypted data,
	// the second one is the passphrase that shall be used.
	// The method returns the decrypted data in another byte array
	// Attention: It is assumed that a nonce is appended to the encrypted
	// byte array!
	Decrypt(data, passphrase *[]byte) []byte

	// DecryptFile takes a filePath as a string and a passphrase as a byte array.
	// The file found at filePath is then decrypted using the Decrypt Method
	// and then wrote back to the original filePath
	DecryptFile(filePath string, passphrase *[]byte) []byte

	// CreateMd5Hash creates an md5 hash of the input byte array pointer.
	CreateMd5Hash(b *[]byte) *[]byte

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
func (util *TinyMfaUtil) Encrypt(data, passphrase *[]byte) *[]byte {
	// a passphrase must have a certain size (128/256bit)
	// therefore, if this condition is not met, we are going to create
	// a md5 hash of the passphrase that happens to be 128bit
	if len(*passphrase) != 16 && len(*passphrase) != 32 {
		passphrase = util.CreateMd5Hash(passphrase)
	}
	block, _ := aes.NewCipher(*passphrase)
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	ciphertext := gcm.Seal(nonce, nonce, *data, nil)
	return &ciphertext
}

// EncryptFile takes a filePath as a string and a passphrase as a byte array.
// The file found at filePath is then Encrypted using the Encrypt Method
// and then wrote back to the original filePath
func (util *TinyMfaUtil) EncryptFile(filePath string, data, passphrase *[]byte) {
	f, _ := os.Create(filePath)
	defer f.Close()
	f.Write(*util.Encrypt(data, passphrase))
}

// Decrypt takes in two byte arrays. The former one is the encrypted data,
// the second one is the passphrase that shall be used.
// The method returns the decrypted data in another byte array
// Attention: It is assumed that a nonce is appended to the encrypted
// byte array!
func (util *TinyMfaUtil) Decrypt(data, passphrase *[]byte) []byte {
	// a passphrase must have a certain size (128/256bit)
	// therefore, if this condition is not met, we are going to create
	// a md5 hash of the passphrase that happens to be 128bit
	if len(*passphrase) != 16 || len(*passphrase) != 32 {
		passphrase = util.CreateMd5Hash(passphrase)
	}
	block, err := aes.NewCipher(*passphrase)
	if err != nil {
		panic(err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonceSize := gcm.NonceSize()
	dataslice := *data

	nonce, ciphertext := dataslice[:nonceSize], dataslice[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}

	for i := range dataslice {
		dataslice[i] = 0 // clear the memory of the decrypted data for security reasons.
	}

	return plaintext
}

// DecryptFile takes a filePath as a string and a passphrase as a byte array.
// The file found at filePath is then decrypted using the Decrypt Method
// and then wrote back to the original filePath
func (util *TinyMfaUtil) DecryptFile(filePath string, passphrase *[]byte) []byte {
	data, _ := os.ReadFile(filePath)
	return util.Decrypt(&data, passphrase)
}

// CreateMd5Hash creates an md5 hash of the input byte array pointer.
func (util *TinyMfaUtil) CreateMd5Hash(b *[]byte) *[]byte {
	hasher := md5.New()
	hasher.Write(*b)

	result := hasher.Sum(nil)
	return &result
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
