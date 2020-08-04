package structs

import (
	"fmt"
	"log"

	"github.com/google/uuid"
)

//Token is a struct that can be used to define access to a resource
type Token struct {
	ID          string `json:"id"`
	ObjectRefID string `json:"-"`
	Token       string `json:"access-token"`
	Description string `json:"description"`
}

//NewAccessToken generates a new access token that has full access on the given object
func NewAccessToken(args ...string) Token {
	var token Token
	token.ID = uuid.New().String()
	token.Token = uuid.New().String()

	for i, arg := range args {
		switch i {
		case 0:
			token.ObjectRefID = arg
			token.Description = "main access token"
		case 1:
			token.Description = arg
		default:
			log.Println(fmt.Sprintf("cannot use argument %s with parameter %d on a new token", arg, i))
		}
	}

	return token
}
