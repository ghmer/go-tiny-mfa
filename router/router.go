package router

import (
	"encoding/json"
	"errors"
	"fmt"
	"go-tiny-mfa/core"
	"go-tiny-mfa/middleware"
	"go-tiny-mfa/qrcode"
	"go-tiny-mfa/structs"
	"io"
	"net/http"
	"strconv"

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
	router.HandleFunc("/api/v1/issuer/{issuer}/users/{user}/validate/{token}", ValidateUserToken).Methods("GET")
	router.HandleFunc("/api/v1/issuer/{issuer}/users/{user}/qrcode", GenerateQrCode).Methods("GET")

	return router
}

func mapJSON(reader io.Reader) (map[string]interface{}, error) {
	// Define empty interface
	var e interface{}

	// Unmarshal json data structure
	err := json.NewDecoder(reader).Decode(&e)
	if err != nil {
		return nil, err
	}

	// Use type assertion to access underlying map[string]interface{}
	m := e.(map[string]interface{})

	return m, nil
}

// Welcome will return a single Hello World
func Welcome(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// send the response
	message := structs.Message{Success: true, Message: "Hello, World!"}
	json.NewEncoder(w).Encode(message)
}

//GetIssuers returns all issuers
func GetIssuers(w http.ResponseWriter, r *http.Request) {
	fmt.Println("LIST issuers")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	issuers, err := middleware.GetIssuers()
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(message)
		return
	}

	// send the response
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(issuers)
}

//CreateIssuer creates a new issuer
func CreateIssuer(w http.ResponseWriter, r *http.Request) {
	fmt.Println("CREATE issuer")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	var issuer structs.Issuer
	decoder := json.NewDecoder(r.Body)
	decoder.Decode(&issuer)

	fmt.Println(issuer)
	issuerStruct, err := middleware.CreateIssuer(issuer)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		w.WriteHeader(405)
		json.NewEncoder(w).Encode(message)
		return
	}

	w.WriteHeader(200)
	json.NewEncoder(w).Encode(issuerStruct)
}

//GetIssuer returns the issuer given in the URL
func GetIssuer(w http.ResponseWriter, r *http.Request) {
	fmt.Println("GET issuer")
	issuerStruct, err := getIssuerStructByVars(r)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		w.WriteHeader(404)
		json.NewEncoder(w).Encode(message)
		return
	}

	json.NewEncoder(w).Encode(issuerStruct)
}

//UpdateIssuer updates an existing issuer
func UpdateIssuer(w http.ResponseWriter, r *http.Request) { //TODO: NOT CORRECT!!!
	fmt.Println("UPDATE issuer ")

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	jsonMap, err := mapJSON(r.Body)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		json.NewEncoder(w).Encode(message)
		return
	}

	currentIssuer, err := getIssuerStructByVars(r)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		json.NewEncoder(w).Encode(message)
		return
	}

	if val, ok := jsonMap["enabled"]; ok {
		currentIssuer.Enabled = val.(bool)
	}

	if val, ok := jsonMap["contact"]; ok {
		currentIssuer.Contact = val.(string)
	}

	result, err := middleware.UpdateIssuer(currentIssuer)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		json.NewEncoder(w).Encode(message)
		return
	}

	message := structs.Message{Success: result}
	json.NewEncoder(w).Encode(message)
}

//DeleteIssuer deletes an existing issuer
func DeleteIssuer(w http.ResponseWriter, r *http.Request) {
	fmt.Println("DELETE issuer")
	issuerStruct, err := getIssuerStructByVars(r)
	result, err := middleware.DeleteIssuer(issuerStruct)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		w.WriteHeader(404)
		json.NewEncoder(w).Encode(message)
		return
	}

	message := structs.Message{Success: result}
	json.NewEncoder(w).Encode(message)
}

//GetUsers returns all users for a given issuer
func GetUsers(w http.ResponseWriter, r *http.Request) {
	fmt.Println("LIST users for issuer")

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	issuerStruct, err := getIssuerStructByVars(r)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		json.NewEncoder(w).Encode(message)
		return
	}

	users, err := middleware.GetUsers(issuerStruct)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		json.NewEncoder(w).Encode(message)
		return
	}

	json.NewEncoder(w).Encode(users)
}

//CreateUser creates a new user in the scope of the given issuer
func CreateUser(w http.ResponseWriter, r *http.Request) {
	fmt.Println("CREATE user for issuer")

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	issuerStruct, err := getIssuerStructByVars(r)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		json.NewEncoder(w).Encode(message)
		return
	}

	var user structs.User
	decoder := json.NewDecoder(r.Body)
	decoder.Decode(&user)
	user.Issuer = issuerStruct

	userStruct, err := middleware.CreateUser(user)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		json.NewEncoder(w).Encode(message)
		return
	}

	json.NewEncoder(w).Encode(userStruct)
}

//GetUser returns a distinct user in the scope of the given issuer
func GetUser(w http.ResponseWriter, r *http.Request) {
	fmt.Println("GET user")

	userStruct, err := getUserStructByVars(r)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		json.NewEncoder(w).Encode(message)
		return
	}

	json.NewEncoder(w).Encode(userStruct)
}

//ValidateUserToken validates a given token
func ValidateUserToken(w http.ResponseWriter, r *http.Request) {
	fmt.Println("VALIDATE token")

	userStruct, err := getUserStructByVars(r)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		json.NewEncoder(w).Encode(message)
		return
	}

	vars := mux.Vars(r)
	token := vars["token"]

	if token == "" {
		message := structs.Message{Success: false, Message: "no token provided."}
		json.NewEncoder(w).Encode(message)
		return
	}

	plainkey, err := middleware.GetUserKey(userStruct)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		json.NewEncoder(w).Encode(message)
		return
	}

	tokenInt, err := strconv.Atoi(token)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		json.NewEncoder(w).Encode(message)
		return
	}

	validated, err := core.ValidateTokenCurrentTimestamp(tokenInt, plainkey)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		json.NewEncoder(w).Encode(message)
		return
	}

	message := structs.Message{Success: validated}
	if !validated {
		message.Message = "token was NOT validated."
	} else {
		message.Message = "token successfully validated."
	}
	json.NewEncoder(w).Encode(message)
}

//UpdateUser updates a user
func UpdateUser(w http.ResponseWriter, r *http.Request) {
	fmt.Println("UPDATE user")

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	userStruct, err := getUserStructByVars(r)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		json.NewEncoder(w).Encode(message)
		return
	}

	jsonMap, err := mapJSON(r.Body)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		json.NewEncoder(w).Encode(message)
		return
	}

	if val, ok := jsonMap["email"]; ok {
		userStruct.Email = val.(string)
	}
	if val, ok := jsonMap["enabled"]; ok {
		userStruct.Enabled = val.(bool)
	}

	result, err := middleware.UpdateUser(userStruct)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		json.NewEncoder(w).Encode(message)
		return
	}

	message := structs.Message{Success: result}
	json.NewEncoder(w).Encode(message)
}

//DeleteUser deletes a user in the scope of the given issuer
func DeleteUser(w http.ResponseWriter, r *http.Request) {
	fmt.Println("DELETE user")
	userStruct, err := getUserStructByVars(r)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		json.NewEncoder(w).Encode(message)
		return
	}
	result, err := middleware.DeleteUser(userStruct)

	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		json.NewEncoder(w).Encode(message)
		return
	}

	message := structs.Message{Success: result}
	json.NewEncoder(w).Encode(message)
}

func getIssuerStructByVars(r *http.Request) (structs.Issuer, error) {
	vars := mux.Vars(r)
	issuer := vars["issuer"]

	if issuer == "" {
		return structs.Issuer{}, errors.New("issuer not set in url.")
	}

	issuerStruct, err := middleware.GetIssuer(issuer)
	if err != nil {
		return structs.Issuer{}, err
	}

	return issuerStruct, nil
}

func getUserStructByVars(r *http.Request) (structs.User, error) {
	issuerStruct, err := getIssuerStructByVars(r)
	if err != nil {
		return structs.User{}, err
	}

	vars := mux.Vars(r)
	user := vars["user"]
	if user == "" {
		return structs.User{}, errors.New("user not set in url.")
	}

	userStruct, err := middleware.GetUser(user, issuerStruct)
	if err != nil {
		return structs.User{}, err
	}

	return userStruct, nil
}

//GenerateQrCode generates a QrCode
func GenerateQrCode(w http.ResponseWriter, r *http.Request) {
	userStruct, err := getUserStructByVars(r)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		json.NewEncoder(w).Encode(message)
		w.WriteHeader(500)
		return
	}

	png, err := qrcode.GenerateQrCode(userStruct)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		json.NewEncoder(w).Encode(message)
		w.WriteHeader(500)
		return
	}

	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	w.Write(png)
}
