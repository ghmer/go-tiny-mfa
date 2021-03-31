package structs

//Issuer is a struct
type Issuer struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Contact     string `json:"contact"`
	Key         string `json:"-"`
	Enabled     bool   `json:"enabled"`
	TokenLength uint8  `json:"token_length"`
}
