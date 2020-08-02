package structs

import (
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
	ActionRefID int    `json:"-"`
	Token       string `json:"access-token"`
}

//NewFullAccessToken generates a new access token that has full access on the given object
func NewFullAccessToken(objectid string) Token {
	var token Token
	token.ObjectRefID = objectid
	token.ActionRefID = ActionIDFull
	token.Token = uuid.New().String()

	return token
}

//NewGetAccessToken generates a new access token that has GET access on the given object
func NewGetAccessToken(objectid string) Token {
	var token Token
	token.ObjectRefID = objectid
	token.ActionRefID = ActionIDGet
	token.Token = uuid.New().String()

	return token
}

//NewPostAccessToken generates a new access token that has POST access on the given object
func NewPostAccessToken(objectid string) Token {
	var token Token
	token.ObjectRefID = objectid
	token.ActionRefID = ActionIDPost
	token.Token = uuid.New().String()

	return token
}

//NewDeleteAccessToken generates a new access token that has DELETE access on the given object
func NewDeleteAccessToken(objectid string) Token {
	var token Token
	token.ObjectRefID = objectid
	token.ActionRefID = ActionIDDelete
	token.Token = uuid.New().String()

	return token
}
