package router

import (
	"encoding/json"
	"fmt"
	"go-tiny-mfa/middleware"
	"net/http"

	"github.com/gorilla/mux"
)

// Router is exported and used in main.go
func Router() *mux.Router {
	router := mux.NewRouter()

	router.HandleFunc("/", Welcome).Methods("GET")
	router.HandleFunc("/api/v1/issuer", ListAllIssuers).Methods("GET")
	router.HandleFunc("/api/v1/issuer", ListAllIssuers).Methods("POST")
	router.HandleFunc("/api/v1/issuer/{issuer}", Welcome).Methods("GET")
	router.HandleFunc("/api/v1/issuer/{issuer}", Welcome).Methods("POST")
	router.HandleFunc("/api/v1/issuer/{issuer}", Welcome).Methods("DELETE")
	router.HandleFunc("/api/v1/issuer/{issuer}/users", Welcome).Methods("GET")
	router.HandleFunc("/api/v1/issuer/{issuer}/users", Welcome).Methods("POST")
	router.HandleFunc("/api/v1/issuer/{issuer}/users/{user}", Welcome).Methods("GET")
	router.HandleFunc("/api/v1/issuer/{issuer}/users/{user}", Welcome).Methods("POST")
	router.HandleFunc("/api/v1/issuer/{issuer}/users/{user}", Welcome).Methods("DELETE")
	router.HandleFunc("/api/v1/issuer/{issuer}/users/{user}/validate/{token}", Welcome).Methods("GET")
	router.HandleFunc("/api/v1/issuer/{issuer}/users/{user}/recreate", Welcome).Methods("GET")

	return router
}

// Welcome will return a single Hello World
func Welcome(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Context-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// send the response
	json.NewEncoder(w).Encode("Hello, World")
}

func ListAllIssuers(w http.ResponseWriter, r *http.Request) {
	fmt.Println("list all issuers")
	w.Header().Set("Context-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	issuers, err := middleware.GetIssuers()
	if err != nil {
		json.NewEncoder(w).Encode(err)
	}
	// send the response
	json.NewEncoder(w).Encode(issuers)
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
