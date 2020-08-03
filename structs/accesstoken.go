package structs

import (
	"fmt"

	"github.com/google/uuid"
)

const (
	//ActionIDGet id of the GET action
	ActionIDGet = 1
	//ActionIDPost id of the POST action
	ActionIDPost = 2
	//ActionIDDelete id of the DELETE action
	ActionIDDelete = 3
	//ActionIDFull id of the FULL action
	ActionIDFull = 4
)

//Token is a struct that can be used to define access to a resource
type Token struct {
	ObjectRefID string `json:"-"`
	Token       string `json:"access-token"`
	Description string `json:"description"`
}

//NewAccessToken generates a new access token that has full access on the given object
func NewAccessToken(args ...string) Token {
	var token Token
	token.Token = uuid.New().String()

	for i, arg := range args {
		switch i {
		case 0:
			token.ObjectRefID = arg
			token.Description = "main access token"
		case 1:
			token.Description = arg
		default:
			fmt.Println(fmt.Sprintf("cannot use argument %s with parameter %d on a new token", arg, i))
		}
	}

	return token
}
