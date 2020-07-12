package core

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"math"
	"time"
)

const (
	// Present can be used as an Offset Type
	Present int8 = iota
	// Future can be used as an Offset Type
	Future
	// Past can be used as an Offset Type
	Past
)

const (
	// OffsetPresent is the offset to add when the OffsetTypePresent was used
	OffsetPresent int = 0

	// OffsetFuture is the offset to add when the OffsetTypeFuture was used
	OffsetFuture int = 30000

	// OffsetPast is the offset to add when the OffsetTypePast was used
	OffsetPast int = -30000

	// KeySize is the size of the SecretKey
	KeySize int8 = 16
)

// GenerateSecretKey returns 16bytes to be used as a secret key
func GenerateSecretKey() ([]byte, error) {
	key := make([]byte, KeySize)
	res, err := rand.Read(key)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	fmt.Println(res)

	return key, nil
}

// GenerateMessageBytes takes in a int64 number and turns it to a BigEndian byte array
func GenerateMessageBytes(message int64) ([]byte, error) {
	buffer := new(bytes.Buffer)
	err := binary.Write(buffer, binary.BigEndian, message)
	if err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

// CalculateRFC2104HMAC calculates the hmac-sha1 value for a given message and key
func CalculateRFC2104HMAC(message []byte, key []byte) []byte {
	mac := hmac.New(sha1.New, key)
	mac.Write(message)

	return mac.Sum(nil)
}

// GenerateMessage takes in a Unix Timestamp and an offsetType of 0,1,2
// offsetTypes: 0=No Offset; 1=Future Offset; 2=Past Offset
func GenerateMessage(timestamp int64, offsetType int8) int64 {
	var offset int

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
	message := math.Floor(float64(timestamp / 30000)) // 30.000 milliseconds or 30 seconds

	return int64(message)
}

// GenerateValidToken takes a Unix Timestamp and a secret key and calculates a valid TOTP token
func GenerateValidToken(unixTimestamp int64, key []byte, offsetType int8) (int, error) {
	message, err := GenerateMessageBytes(GenerateMessage(unixTimestamp, offsetType))
	if err != nil {
		return 0, err
	}
	rfc2104hmac := CalculateRFC2104HMAC(message, key)

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
	truncResult %= 1000000

	token := int(truncResult)

	return token, nil
}

// ValidateToken takes a submitted token and a secret key and validates whether the token is valid
func ValidateToken(token int, key []byte) (bool, error) {
	var result bool = false
	unixTimestamp := time.Now().Unix()
	// validating against a token that was generated with a current timestamp
	// usually, the clocks of server and client should be synchronized, so this
	// should be the most common case
	generatedToken, err := GenerateValidToken(unixTimestamp, key, Present)
	if err != nil {
		return false, err
	}
	if generatedToken == token {
		result = true
	}

	// the token could not be verified with a current timestamp, but maybe the
	// user missed the timewindow for that token. Verifying it against a token
	// that was valid up to 30 seconds ago
	if result == false {
		generatedToken, err := GenerateValidToken(unixTimestamp, key, Past)
		if err != nil {
			return false, err
		}
		if generatedToken == token {
			result = true
		}
	}

	// we still could not verify the token. Doing a last check against the token
	// that becomes valid in the next window.
	if result == false {
		generatedToken, err := GenerateValidToken(unixTimestamp, key, Future)
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
