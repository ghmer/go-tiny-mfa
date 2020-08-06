package core

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"go-tiny-mfa/structs"
	"math"
	"time"
)

const (
	// Present can be used as an Offset Type
	Present uint8 = iota
	// Future can be used as an Offset Type
	Future
	// Past can be used as an Offset Type
	Past
)

const (
	// OffsetPresent is the offset to add when the OffsetTypePresent was used
	OffsetPresent int8 = 0

	// OffsetFuture is the offset to add when the OffsetTypeFuture was used
	OffsetFuture int8 = 30

	// OffsetPast is the offset to add when the OffsetTypePast was used
	OffsetPast int8 = -30

	// KeySizeStandard is the default size of the SecretKey (128bit)
	KeySizeStandard int8 = 16

	// KeySizeExtended is the extended size of the SecretKey (256bit)
	KeySizeExtended int8 = 32
)

// GenerateStandardSecretKey returns 16bytes to be used as a secret key
func GenerateStandardSecretKey() ([]byte, error) {
	return generateSecretKey(KeySizeStandard)
}

// GenerateExtendedSecretKey returns 32bytes to be used as a secret key
func GenerateExtendedSecretKey() ([]byte, error) {
	return generateSecretKey(KeySizeExtended)
}

// generateSecretKey returns size bytes to be used as a secret key
func generateSecretKey(size int8) ([]byte, error) {
	key := make([]byte, size)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}

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
func GenerateMessage(timestamp int64, offsetType uint8) int64 {
	var offset int8

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
	message := math.Floor(float64(timestamp / 30))

	return int64(message)
}

// GenerateValidToken takes a Unix Timestamp and a secret key and calculates a valid TOTP token
func GenerateValidToken(unixTimestamp int64, key []byte, offsetType, tokenlength uint8) (int, error) {
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

	token := int(truncResult)

	return token, nil
}

// ValidateTokenCurrentTimestamp takes a submitted token and a secret key and validates against the current Unix Timestamp whether the token is valid
func ValidateTokenCurrentTimestamp(token int, key []byte, tokenlength uint8) structs.Validation {
	currentTimestamp := time.Now().Unix()
	result, err := ValidateToken(token, key, currentTimestamp, tokenlength)
	var validation = structs.Validation{
		Message: GenerateMessage(currentTimestamp, Present),
		Success: result,
		Error:   err,
	}
	return validation
}

// ValidateTokenWithTimestamp takes a submitted token and a secret key and validates against the current Unix Timestamp whether the token is valid
func ValidateTokenWithTimestamp(token int, key []byte, timestamp int64, tokenlength uint8) structs.Validation {
	result, err := ValidateToken(token, key, timestamp, tokenlength)
	var validation = structs.Validation{
		Message: GenerateMessage(timestamp, Present),
		Success: result,
		Error:   err,
	}
	return validation
}

// ValidateToken takes a submitted token, a secret key and a Unix Timestamp and validates whether the token is valid
func ValidateToken(token int, key []byte, unixTimestamp int64, tokenlength uint8) (bool, error) {
	var result bool = false
	// validating against a token that was generated with a current timestamp
	// usually, the clocks of server and client should be synchronized, so this
	// should be the most common case
	generatedToken, err := GenerateValidToken(unixTimestamp, key, Present, tokenlength)
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
		generatedToken, err := GenerateValidToken(unixTimestamp, key, Past, tokenlength)
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
		generatedToken, err := GenerateValidToken(unixTimestamp, key, Future, tokenlength)
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
