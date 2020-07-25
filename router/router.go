package router

import (
	"encoding/json"
	"fmt"
	"go-tiny-mfa/middleware"
	"go-tiny-mfa/structs"
	"net/http"

	"github.com/gorilla/mux"
)

// Router is exported and used in main.go
func Router() *mux.Router {
	router := mux.NewRouter()

	router.HandleFunc("/", Welcome).Methods("GET")
	router.HandleFunc("/api/v1/issuer", ListIssuers).Methods("GET")
	router.HandleFunc("/api/v1/issuer", CreateIssuer).Methods("POST")
	router.HandleFunc("/api/v1/issuer/{issuer}", GetIssuer).Methods("GET")
	router.HandleFunc("/api/v1/issuer/{issuer}", UpdateIssuer).Methods("POST")
	router.HandleFunc("/api/v1/issuer/{issuer}", DeleteIssuer).Methods("DELETE")
	router.HandleFunc("/api/v1/issuer/{issuer}/users", Welcome).Methods("GET")
	router.HandleFunc("/api/v1/issuer/{issuer}/users", Welcome).Methods("POST")
	router.HandleFunc("/api/v1/issuer/{issuer}/users/{user}", Welcome).Methods("GET")
	router.HandleFunc("/api/v1/issuer/{issuer}/users/{user}", Welcome).Methods("POST")
	router.HandleFunc("/api/v1/issuer/{issuer}/users/{user}", Welcome).Methods("DELETE")
	router.HandleFunc("/api/v1/issuer/{issuer}/users/{user}/validate/{token}", Welcome).Methods("GET")
	router.HandleFunc("/api/v1/issuer/{issuer}/users/{user}/qrcode/recreate", Welcome).Methods("GET")
	router.HandleFunc("/api/v1/issuer/{issuer}/users/{user}/qrcode", Welcome).Methods("GET")

	return router
}

// Welcome will return a single Hello World
func Welcome(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Context-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// send the response
	message := structs.Message{Success: true, Message: "Hello, World"}
	json.NewEncoder(w).Encode(message)
}

func ListIssuers(w http.ResponseWriter, r *http.Request) {
	fmt.Println("LIST issuers")
	w.Header().Set("Context-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	issuers, err := middleware.GetIssuers()
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		json.NewEncoder(w).Encode(message)
	} else {
		// send the response
		json.NewEncoder(w).Encode(issuers)
	}
}

func GetIssuer(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	issuer := vars["issuer"]
	fmt.Println("GET issuer ", issuer)

	issuerStruct, err := middleware.GetIssuer(issuer)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		json.NewEncoder(w).Encode(message)
	} else {
		json.NewEncoder(w).Encode(issuerStruct)
	}
}

func DeleteIssuer(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	issuer := vars["issuer"]
	fmt.Println("DELETE issuer ", issuer)

	if issuer == "" {
		message := structs.Message{Success: false, Message: "issuer not set in url"}
		json.NewEncoder(w).Encode(message)
	}
	result, err := middleware.DeleteIssuer(issuer)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		json.NewEncoder(w).Encode(message)
	} else {
		message := structs.Message{Success: result}
		json.NewEncoder(w).Encode(message)
	}
}

func CreateIssuer(w http.ResponseWriter, r *http.Request) {
	fmt.Println("CREATE issuer")
	w.Header().Set("Context-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	var issuer structs.Issuer
	decoder := json.NewDecoder(r.Body)
	decoder.Decode(&issuer)

	fmt.Println(issuer)
	issuerStruct, err := middleware.InsertIssuer(issuer)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		json.NewEncoder(w).Encode(message)
	} else {
		json.NewEncoder(w).Encode(issuerStruct)
	}
}

func UpdateIssuer(w http.ResponseWriter, r *http.Request) {
	fmt.Println("UPDATE issuer")
	w.Header().Set("Context-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	var issuer structs.Issuer
	decoder := json.NewDecoder(r.Body)
	decoder.Decode(&issuer)

	fmt.Println(issuer)

	if issuer.ID == "" {
		message := structs.Message{Success: false, Message: "ID not set in struct"}
		json.NewEncoder(w).Encode(message)
	}

	result, err := middleware.UpdateIssuer(issuer)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		json.NewEncoder(w).Encode(message)
	} else {
		message := structs.Message{Success: result}
		json.NewEncoder(w).Encode(message)
	}
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
