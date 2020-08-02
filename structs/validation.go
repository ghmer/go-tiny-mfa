package structs

//Validation is a struct used to return the result of a token validation
type Validation struct {
	Message int64
	Success bool
	Error   error
}
