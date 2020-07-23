package structs

// User is a struct that holds Username, Issuer and the Base32 encoded Secret Key
type User struct {
	ID               string
	Username         string
	Issuer           string
	CryptedBase32Key string
	enabled          bool
}
