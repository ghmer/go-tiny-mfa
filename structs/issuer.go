package structs

import "regexp"

//Issuer is a struct
type Issuer struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Contact     string `json:"contact"`
	Key         string `json:"-"`
	Enabled     bool   `json:"enabled"`
	TokenLength uint8  `json:"token_length"`
}

type IssuerCreation struct {
	Issuer Issuer `json:"issuer"`
	Token  Token  `json:"token"`
}

func (issuer Issuer) IsSafe() bool {
	var mailregex string = `[^@ \t\r\n]+@[^@ \t\r\n]+\.[^@ \t\r\n]+`
	var strregex string = `^[\w_-]*$`

	if ok, _ := regexp.MatchString(strregex, issuer.Name); !ok {
		return false
	}

	if ok, _ := regexp.MatchString(mailregex, issuer.Contact); !ok {
		return false
	}

	return true
}
