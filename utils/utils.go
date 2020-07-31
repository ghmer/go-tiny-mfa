package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base32"
	"go-tiny-mfa/core"
	"go-tiny-mfa/structs"
	"io"
	"io/ioutil"
	"os"
)

//Encrypt takes in a byte array as data and another byte array as the passphrase,
//encrypts the data using the AES cipher and returns the encrypted data (also as byte array)
//please note that the nonce needed to encrypt the data using AES GCM is appended to the byte array
func Encrypt(data, passphrase []byte) []byte {
	// a passphrase must have a certain size (128/256bit)
	// therefore, if this condition is not met, we are going to create
	// a md5 hash of the passphrase that happens to be 128bit
	if len(passphrase) != 16 || len(passphrase) != 32 {
		passphrase = createMd5Hash(passphrase)
	}
	block, _ := aes.NewCipher(passphrase)
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext
}

//EncryptFile takes a filePath as a string and a passphrase as a byte array.
//The file found at filePath is then Encrypted using the Encrypt Method
//and then wrote back to the original filePath
func EncryptFile(filePath string, data, passphrase []byte) {
	f, _ := os.Create(filePath)
	defer f.Close()
	f.Write(Encrypt(data, passphrase))
}

//Decrypt takes in two byte arrays. The former one is the encrypted data,
//the second one is the passphrase that shall be used.
//The method returns the decrypted data in another byte array
//Attention: It is assumed that a nonce is appended to the encrypted
//byte array!
func Decrypt(data, passphrase []byte) []byte {
	// a passphrase must have a certain size (128/256bit)
	// therefore, if this condition is not met, we are going to create
	// a md5 hash of the passphrase that happens to be 128bit
	if len(passphrase) != 16 || len(passphrase) != 32 {
		passphrase = createMd5Hash(passphrase)
	}
	block, err := aes.NewCipher(passphrase)
	if err != nil {
		panic(err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
	return plaintext
}

//DecryptFile takes a filePath as a string and a passphrase as a byte array.
//The file found at filePath is then decrypted using the Decrypt Method
//and then wrote back to the original filePath
func DecryptFile(filePath string, passphrase []byte) []byte {
	data, _ := ioutil.ReadFile(filePath)
	return Decrypt(data, passphrase)
}

func createMd5Hash(key []byte) []byte {
	hasher := md5.New()
	hasher.Write(key)

	return hasher.Sum(nil)
}

//GenerateCryptedKeyBase32 generates a new Key, encrypts it with the master key and encodes it to base32
func GenerateCryptedKeyBase32(masterKey []byte) (string, error) {
	issuerKey, err := core.GenerateExtendedSecretKey()
	if err != nil {
		return "", err
	}

	cryptedKey := Encrypt(issuerKey, masterKey)

	return base32.StdEncoding.EncodeToString(cryptedKey), nil
}

//GenerateExtendedKeyBase32 returns a base32 encoded 256bit key
func GenerateExtendedKeyBase32() (string, error) {
	masterKey, err := core.GenerateExtendedSecretKey()
	if err != nil {
		return "", err
	}

	encodedKey := base32.StdEncoding.EncodeToString(masterKey)

	return encodedKey, nil
}

//DecodeBase32Key Decodes a base32 encoded key to a byte array
func DecodeBase32Key(encodedKey string) ([]byte, error) {
	key, err := base32.StdEncoding.DecodeString(encodedKey)
	return key, err
}

//ScrubInformation crubs some sensitive information from the objects and nullifies the given byte array
func ScrubInformation(user *structs.User, key *[]byte) {
	ScrubKey(key)
	ScrubUserStruct(user)
}

//ScrubKey nullifies a given byte array
func ScrubKey(key *[]byte) {
	if key != nil {
		for i := 0; i < len(*key); i++ {
			(*key)[i] = byte(0)
		}
	}
}

//ScrubUserStruct scrubs the key of the user and also the issuer key
func ScrubUserStruct(user *structs.User) {
	user.Key = ""
	ScrubIssuerStruct(&user.Issuer)
}

//ScrubIssuerStruct scrubs the key of the issuer
func ScrubIssuerStruct(issuer *structs.Issuer) {
	issuer.Key = ""
}
