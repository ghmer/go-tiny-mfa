package structs

//Message is a struct used by the router
type Message struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}
