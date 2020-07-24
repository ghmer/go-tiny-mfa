package router

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
)

// Router is exported and used in main.go
func Router() *mux.Router {
	router := mux.NewRouter()

	router.HandleFunc("/", Welcome).Methods("GET")

	return router
}

// Welcome will return a single Hello World
func Welcome(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Context-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// send the response
	json.NewEncoder(w).Encode("Hello, World")
}

/*
/issuers
GET:    List all issuers (id, name)
POST:   Create new issuer {name : "name", contact: "contact@issuer.net", enabled: true}

/issuers/{issuer}
GET:    List issuer attributes {id: "id", name : "name", contact: "contact@issuer.net", enabled: true}
POST:   Update issuer attributes {contact: "contact@issuer.net", enabled: true}
DELETE: Delete the issuer

/issuers/{issuer}/users
GET:    List all users (id, name)
POST:   Create new user {name : "name", email: "email", enabled: true}

/issuers/{issuer}/users/{user}
GET:    List issuer attributes {id: "id", name : "name", email: "contact@issuer.net", key: "key", enabled: true}
POST:   Update user attributes {email: "contact@issuer.net", enabled: true}
DELETE: Delete the user

/issuers/{issuer}/users/{user}/validate/{token}
GET:    Validate a token
*/
