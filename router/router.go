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
	router.HandleFunc("/api/v1/issuer", GetIssuers).Methods("GET")
	router.HandleFunc("/api/v1/issuer", CreateIssuer).Methods("POST")
	router.HandleFunc("/api/v1/issuer/{issuer}", GetIssuer).Methods("GET")
	router.HandleFunc("/api/v1/issuer/{issuer}", UpdateIssuer).Methods("POST")
	router.HandleFunc("/api/v1/issuer/{issuer}", DeleteIssuer).Methods("DELETE")
	router.HandleFunc("/api/v1/issuer/{issuer}/users", GetUsers).Methods("GET")
	router.HandleFunc("/api/v1/issuer/{issuer}/users", CreateUser).Methods("POST")
	router.HandleFunc("/api/v1/issuer/{issuer}/users/{user}", GetUser).Methods("GET")
	router.HandleFunc("/api/v1/issuer/{issuer}/users/{user}", UpdateUser).Methods("POST")
	router.HandleFunc("/api/v1/issuer/{issuer}/users/{user}", DeleteUser).Methods("DELETE")
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

//GetIssuers returns all issuers
func GetIssuers(w http.ResponseWriter, r *http.Request) {
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

//CreateIssuer creates a new issuer
func CreateIssuer(w http.ResponseWriter, r *http.Request) {
	fmt.Println("CREATE issuer")
	w.Header().Set("Context-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	var issuer structs.Issuer
	decoder := json.NewDecoder(r.Body)
	decoder.Decode(&issuer)

	fmt.Println(issuer)
	issuerStruct, err := middleware.CreateIssuer(issuer)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		json.NewEncoder(w).Encode(message)
	} else {
		json.NewEncoder(w).Encode(issuerStruct)
	}
}

//GetIssuer returns the issuer given in the URL
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

//UpdateIssuer updates an existing issuer
func UpdateIssuer(w http.ResponseWriter, r *http.Request) { //TODO: NOT CORRECT!!!
	vars := mux.Vars(r)
	issuer := vars["issuer"]
	fmt.Println("UPDATE issuer ", issuer)

	if issuer == "" {
		message := structs.Message{Success: false, Message: "issuer not set in url"}
		json.NewEncoder(w).Encode(message)
	}

	w.Header().Set("Context-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	var issuerStruct structs.Issuer
	decoder := json.NewDecoder(r.Body)
	decoder.Decode(&issuerStruct)

	/*
		if issuer.ID == "" {
			message := structs.Message{Success: false, Message: "ID not set in struct"}
			json.NewEncoder(w).Encode(message)
		}
	*/

	currentIssuer, err := middleware.GetIssuer(issuer)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		json.NewEncoder(w).Encode(message)
	} else {
		issuerStruct.ID = currentIssuer.ID

		result, err := middleware.UpdateIssuer(issuerStruct)
		if err != nil {
			message := structs.Message{Success: false, Message: err.Error()}
			json.NewEncoder(w).Encode(message)
		} else {
			message := structs.Message{Success: result}
			json.NewEncoder(w).Encode(message)
		}
	}
}

//DeleteIssuer deletes an existing issuer
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

//GetUsers returns all users for a given issuer
func GetUsers(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	issuer := vars["issuer"]
	fmt.Println("LIST users for issuer", issuer)

	w.Header().Set("Context-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	issuerStruct, err := middleware.GetIssuer(issuer)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		json.NewEncoder(w).Encode(message)
	} else {
		users, err := middleware.GetUsers(issuerStruct)
		if err != nil {
			message := structs.Message{Success: false, Message: err.Error()}
			json.NewEncoder(w).Encode(message)
		} else {
			json.NewEncoder(w).Encode(users)
		}
	}
}

//CreateUser creates a new user in the scope of the given issuer
func CreateUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	issuer := vars["issuer"]
	fmt.Println("CREATE user for issuer", issuer)

	w.Header().Set("Context-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	issuerStruct, err := middleware.GetIssuer(issuer)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		json.NewEncoder(w).Encode(message)
	} else {
		var user structs.User
		decoder := json.NewDecoder(r.Body)
		decoder.Decode(&user)
		user.Issuer = issuerStruct

		userStruct, err := middleware.CreateUser(user)
		if err != nil {
			message := structs.Message{Success: false, Message: err.Error()}
			json.NewEncoder(w).Encode(message)
		} else {
			json.NewEncoder(w).Encode(userStruct)
		}
	}
}

//GetUser returns a distinct user in the scope of the given issuer
func GetUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	issuer := vars["user"]
	user := vars["user"]
	fmt.Println("GET user ", user)

	issuerStruct, err := middleware.GetIssuer(issuer)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		json.NewEncoder(w).Encode(message)
		return
	}

	userStruct, err := middleware.GetUser(user, issuerStruct)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		json.NewEncoder(w).Encode(message)
		return
	}

	json.NewEncoder(w).Encode(userStruct)
}

//UpdateUser updates a user
func UpdateUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	issuer := vars["issuer"]
	user := vars["user"]
	fmt.Println("UPDATE user ", user, issuer)

	w.Header().Set("Context-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	issuerStruct, err := middleware.GetIssuer(issuer)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		json.NewEncoder(w).Encode(message)
		return
	}

	userStruct, err := middleware.GetUser(user, issuerStruct)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		json.NewEncoder(w).Encode(message)
		return
	}

	var jsonUser structs.User
	decoder := json.NewDecoder(r.Body)
	decoder.Decode(&jsonUser)

	if jsonUser.Email != "" {
		userStruct.Email = jsonUser.Email
	}

	userStruct.Enabled = jsonUser.Enabled

	result, err := middleware.UpdateUser(userStruct)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		json.NewEncoder(w).Encode(message)
	} else {
		message := structs.Message{Success: result}
		json.NewEncoder(w).Encode(message)
	}
}

//DeleteUser deletes a user in the scope of the given issuer
func DeleteUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	issuer := vars["user"]
	user := vars["user"]
	fmt.Println("DELETE user ", user)

	if issuer == "" {
		message := structs.Message{Success: false, Message: "issuer not set in url"}
		json.NewEncoder(w).Encode(message)
	}

	if user == "" {
		message := structs.Message{Success: false, Message: "user not set in url"}
		json.NewEncoder(w).Encode(message)
	}

	issuerStruct, err := middleware.GetIssuer(issuer)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		json.NewEncoder(w).Encode(message)
		return
	}

	userStruct, err := middleware.GetUser(user, issuerStruct)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		json.NewEncoder(w).Encode(message)
		return
	}

	result, err := middleware.DeleteUser(userStruct)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		json.NewEncoder(w).Encode(message)
	} else {
		message := structs.Message{Success: result}
		json.NewEncoder(w).Encode(message)
	}
}
