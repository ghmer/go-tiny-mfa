package structs

// User is a struct that holds Username, Issuer and the Base32 encoded Secret Key
type User struct {
	Username  string
	Issuer    string
	Base32Key []byte
}
