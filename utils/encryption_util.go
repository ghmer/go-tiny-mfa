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

func decrypt(data, passphrase []byte) []byte {
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

func encryptFile(filename string, data, passphrase []byte) {
	f, _ := os.Create(filename)
	defer f.Close()
	f.Write(Encrypt(data, passphrase))
}

func decryptFile(filename string, passphrase []byte) []byte {
	data, _ := ioutil.ReadFile(filename)
	return decrypt(data, passphrase)
}

func createMd5Hash(key string) string {
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}
