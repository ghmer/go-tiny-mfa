package structs

// User is a struct that holds Username, Issuer and the Base32 encoded Secret Key
type User struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Email   string `json:"email"`
	Issuer  Issuer `json:"issuer"`
	Key     string `json:"-"`
	Enabled bool   `json:"enabled"`
}
