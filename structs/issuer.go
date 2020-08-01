package structs

//Issuer is a struct
type Issuer struct {
	ID      string `json:"token"`
	Name    string `json:"name"`
	Contact string `json:"contact"`
	Key     string `json:"key"`
	Enabled bool   `json:"enabled"`
}
