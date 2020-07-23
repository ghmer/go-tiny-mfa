package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"io"
	"io/ioutil"
	"os"
)

//Encrypt takes in a byte array as data and another byte array as the passphrase,
//encrypts the data using the AES cipher and returns the encrypted data (also as byte array)
//please note that the nonce needed to encrypt the data using AES GCM is appended to the byte array
func Encrypt(data, passphrase []byte) []byte {
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

func createMd5Hash(key string) string {
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}
