package structs

import "regexp"

// User is a struct that holds Username, Issuer and the Base32 encoded Secret Key
type User struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Email   string `json:"email"`
	Issuer  Issuer `json:"issuer"`
	Key     string `json:"-"`
	Enabled bool   `json:"enabled"`
}

func (user User) IsSafe() bool {
	var mailregex string = `[^@ \t\r\n]+@[^@ \t\r\n]+\.[^@ \t\r\n]+`
	var strregex string = `^[\w_-]*$`

	if ok, _ := regexp.MatchString(strregex, user.Name); !ok {
		return false
	}

	if ok, _ := regexp.MatchString(mailregex, user.Email); !ok {
		return false
	}

	return true
}
