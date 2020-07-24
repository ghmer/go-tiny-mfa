package structs

//Issuer is a struct
type Issuer struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Contact string `json:"contact"`
	Enabled bool   `json:"enabled"`
}
