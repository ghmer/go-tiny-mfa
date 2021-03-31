package structs

import (
	"fmt"
	"log"

	"github.com/google/uuid"
)

//Token is a struct that can be used to define access to a resource
type Token struct {
	ID          string `json:"-"`
	ObjectRefID string `json:"-"`
	Token       string `json:"access-token"`
	Description string `json:"description"`
}

//TokenEntry is used when returning registered tokens
type TokenEntry struct {
	Id             string `json:"id"`
	Description    string `json:"description"`
	CreatedOn      string `json:"created_on"`
	LastAccessTime string `json:"last_access_time"`
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
