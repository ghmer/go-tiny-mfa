package router

import (
	"encoding/json"
	"errors"
	"go-tiny-mfa/core"
	"go-tiny-mfa/middleware"
	"go-tiny-mfa/qrcode"
	"go-tiny-mfa/structs"
	"go-tiny-mfa/utils"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

//VerifyTokenHeaderKey defines the header key to look for the access token
const VerifyTokenHeaderKey string = "tiny-mfa-access-token"

// Router is exported and used in main.go
func Router() *mux.Router {
	router := mux.NewRouter()

	router.HandleFunc("/", Welcome).Methods("GET")

	//API Endpoints
	//Return audit entries
	router.HandleFunc("/api/v1/system/audit", GetAuditEntries).Methods("GET")
	//Return current system configuration
	router.HandleFunc("/api/v1/system/configuration", GetSystemConfiguration).Methods("GET")
	//Updates the system configuration
	router.HandleFunc("/api/v1/system/configuration", UpdateSystemConfiguration).Methods("POST")
	//Return all registered issuers
	router.HandleFunc("/api/v1/issuer", GetIssuers).Methods("GET")
	//Create a new issuer using a POST request
	router.HandleFunc("/api/v1/issuer", CreateIssuer).Methods("POST")
	//Return a distinct issuer by its name
	router.HandleFunc("/api/v1/issuer/{issuer}", GetIssuer).Methods("GET")
	//Updates a distinct issuer using a POST request
	router.HandleFunc("/api/v1/issuer/{issuer}", UpdateIssuer).Methods("POST")
	//Deletes a distinct issuer using a DELETE request
	router.HandleFunc("/api/v1/issuer/{issuer}", DeleteIssuer).Methods("DELETE")

	//Return all users belonging to the scope of a distinct issuer
	router.HandleFunc("/api/v1/issuer/{issuer}/users", GetUsers).Methods("GET")
	//Create a new user in the scope of a distinct issuer
	router.HandleFunc("/api/v1/issuer/{issuer}/users", CreateUser).Methods("POST")
	//Return a distinct user in the scope of a distinct issuer
	router.HandleFunc("/api/v1/issuer/{issuer}/users/{user}", GetUser).Methods("GET")
	//Update a distinct user in the scope of a distinct issuer
	router.HandleFunc("/api/v1/issuer/{issuer}/users/{user}", UpdateUser).Methods("POST")
	//Deletes a distinct user in the scope of a distinct issuer
	router.HandleFunc("/api/v1/issuer/{issuer}/users/{user}", DeleteUser).Methods("DELETE")
	//Validates a given token in the scope of a distinct user and issuer
	router.HandleFunc("/api/v1/issuer/{issuer}/users/{user}/validate/{token}", ValidateUserToken).Methods("GET")
	//Generates and returns a PNG image of a QRCode in the scope of a distinct user and issuer
	router.HandleFunc("/api/v1/issuer/{issuer}/users/{user}/qrcode", GenerateQrCode).Methods("GET")

	return router
}

// Welcome will return a single Hello World
func Welcome(w http.ResponseWriter, r *http.Request) {
	writeStandardHeaders(w)

	// send the response
	message := structs.Message{Success: true, Message: "tiny-mfa alive!"}
	json.NewEncoder(w).Encode(message)
}

//GetAuditEntries returns all audit entries
func GetAuditEntries(w http.ResponseWriter, r *http.Request) {
	writeStandardHeaders(w)
	err := verifyMasterToken(r)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(message)
		return
	}

	parameters := structs.NewAuditQueryParameter()

	//look for query parameter "before" in the url
	before, ok := r.URL.Query()["before"]
	if ok {
		variable := strings.Join(before, ":")
		dateObj, err := time.Parse(parameters.SourceDateFormat, variable)
		if err == nil {
			parameters.Before = dateObj
		}
	}

	//look for query parameter "after" in the url
	after, ok := r.URL.Query()["after"]
	if ok {
		variable := strings.Join(after, ":")
		dateObj, err := time.Parse(parameters.SourceDateFormat, variable)
		if err == nil {
			parameters.After = dateObj
		}
	}

	audits, err := middleware.GetAuditEntries(parameters)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(message)
		return
	}
	// send the response
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(audits)
}

//GetSystemConfiguration returns the system configuration
func GetSystemConfiguration(w http.ResponseWriter, r *http.Request) {
	writeStandardHeaders(w)

	err := verifyMasterToken(r)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(message)
		return
	}

	configuration, err := middleware.GetSystemConfiguration()
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(message)
		return
	}

	// send the response
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(configuration)
}

//UpdateSystemConfiguration updates the system configuration
func UpdateSystemConfiguration(w http.ResponseWriter, r *http.Request) {
	writeStandardHeaders(w)
	err := verifyMasterToken(r)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(message)
		return
	}

	jsonMap, err := mapJSON(r.Body)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(message)
		return
	}

	configuration, err := middleware.GetSystemConfiguration()
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(message)
		return
	}

	if val, ok := jsonMap[middleware.RouterPortKey]; ok {
		configuration.RouterPort = val.(uint16)
	}
	if val, ok := jsonMap[middleware.DenyLimitKey]; ok {
		configuration.DenyLimit = val.(uint8)
	}
	if val, ok := jsonMap[middleware.VerifyTokenKey]; ok {
		configuration.VerifyTokens = val.(bool)
	}

	configuration, err = middleware.UpdateSystemConfiguration(configuration)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(message)
		return
	}

	// send the response
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(configuration)
}

//GetIssuers returns all issuers
func GetIssuers(w http.ResponseWriter, r *http.Request) {
	writeStandardHeaders(w)
	err := verifyMasterToken(r)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(message)
		return
	}

	issuers, err := middleware.GetIssuers()
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(message)
		return
	}
	for i := range issuers {
		defer utils.ScrubIssuerStruct(&(issuers)[i])
	}

	// send the response
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(issuers)
}

//CreateIssuer creates a new issuer
func CreateIssuer(w http.ResponseWriter, r *http.Request) {
	writeStandardHeaders(w)
	err := verifyMasterToken(r)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(message)
		return
	}

	var issuer structs.Issuer
	decoder := json.NewDecoder(r.Body)
	decoder.Decode(&issuer)

	resultmap, err := middleware.CreateIssuer(issuer)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		w.WriteHeader(405)
		json.NewEncoder(w).Encode(message)
		return
	}

	issuerStruct := resultmap["issuer"].(structs.Issuer)
	defer utils.ScrubIssuerStruct(&issuerStruct)

	w.WriteHeader(200)
	json.NewEncoder(w).Encode(resultmap)
}

//GetIssuer returns the issuer given in the URL
func GetIssuer(w http.ResponseWriter, r *http.Request) {
	writeStandardHeaders(w)

	issuerStruct, err := getIssuerStructByVars(r)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		w.WriteHeader(404)
		json.NewEncoder(w).Encode(message)
		return
	}
	defer utils.ScrubIssuerStruct(&issuerStruct)

	err = verifyIssuerAccessHeader(issuerStruct, r)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(message)
		return
	}

	w.WriteHeader(200)
	json.NewEncoder(w).Encode(issuerStruct)
}

//UpdateIssuer updates an existing issuer
func UpdateIssuer(w http.ResponseWriter, r *http.Request) { //TODO: NOT CORRECT!!!
	writeStandardHeaders(w)

	jsonMap, err := mapJSON(r.Body)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(message)
		return
	}

	issuerStruct, err := getIssuerStructByVars(r)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		w.WriteHeader(404)
		json.NewEncoder(w).Encode(message)
		return
	}
	defer utils.ScrubIssuerStruct(&issuerStruct)

	err = verifyIssuerAccessHeader(issuerStruct, r)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(message)
		return
	}

	if val, ok := jsonMap["enabled"]; ok {
		issuerStruct.Enabled = val.(bool)
	}

	if val, ok := jsonMap["contact"]; ok {
		issuerStruct.Contact = val.(string)
	}

	result, err := middleware.UpdateIssuer(issuerStruct)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(message)
		return
	}

	w.WriteHeader(200)
	message := structs.Message{Success: result}
	json.NewEncoder(w).Encode(message)
}

//DeleteIssuer deletes an existing issuer
func DeleteIssuer(w http.ResponseWriter, r *http.Request) {
	writeStandardHeaders(w)

	issuerStruct, err := getIssuerStructByVars(r)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		w.WriteHeader(404)
		json.NewEncoder(w).Encode(message)
		return
	}
	defer utils.ScrubIssuerStruct(&issuerStruct)

	err = verifyIssuerAccessHeader(issuerStruct, r)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(message)
		return
	}

	result, err := middleware.DeleteIssuer(issuerStruct)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(message)
		return
	}

	w.WriteHeader(200)
	message := structs.Message{Success: result}
	json.NewEncoder(w).Encode(message)
}

//GetUsers returns all users for a given issuer
func GetUsers(w http.ResponseWriter, r *http.Request) {
	writeStandardHeaders(w)

	issuerStruct, err := getIssuerStructByVars(r)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		w.WriteHeader(404)
		json.NewEncoder(w).Encode(message)
		return
	}

	err = verifyIssuerAccessHeader(issuerStruct, r)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(message)
		return
	}

	users, err := middleware.GetUsers(issuerStruct)
	for i := range users {
		defer utils.ScrubUserStruct(&(users)[i])
	}
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(message)
		return
	}

	w.WriteHeader(200)
	json.NewEncoder(w).Encode(users)
}

//CreateUser creates a new user in the scope of the given issuer
func CreateUser(w http.ResponseWriter, r *http.Request) {
	writeStandardHeaders(w)

	issuerStruct, err := getIssuerStructByVars(r)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		w.WriteHeader(404)
		json.NewEncoder(w).Encode(message)
		return
	}

	err = verifyIssuerAccessHeader(issuerStruct, r)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(message)
		return
	}

	var user structs.User
	decoder := json.NewDecoder(r.Body)
	decoder.Decode(&user)
	user.Issuer = issuerStruct

	resultmap, err := middleware.CreateUser(user)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(message)
		return
	}

	userStruct := resultmap["user"].(structs.User)
	defer utils.ScrubUserStruct(&userStruct)

	w.WriteHeader(200)
	json.NewEncoder(w).Encode(resultmap)
}

//GetUser returns a distinct user in the scope of the given issuer
func GetUser(w http.ResponseWriter, r *http.Request) {
	writeStandardHeaders(w)

	userStruct, err := getUserStructByVars(r)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		w.WriteHeader(404)
		json.NewEncoder(w).Encode(message)
		return
	}

	err = verifyUserAccessHeader(userStruct, r)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(message)
		return
	}

	defer utils.ScrubUserStruct(&userStruct)
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(userStruct)
}

//UpdateUser updates a user
func UpdateUser(w http.ResponseWriter, r *http.Request) {
	writeStandardHeaders(w)

	userStruct, err := getUserStructByVars(r)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		json.NewEncoder(w).Encode(message)
		return
	}
	defer utils.ScrubUserStruct(&userStruct)

	err = verifyUserAccessHeader(userStruct, r)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		w.WriteHeader(404)
		json.NewEncoder(w).Encode(message)
		return
	}

	jsonMap, err := mapJSON(r.Body)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		w.WriteHeader(500)
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
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(message)
		return
	}

	message := structs.Message{Success: result}
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(message)
}

//DeleteUser deletes a user in the scope of the given issuer
func DeleteUser(w http.ResponseWriter, r *http.Request) {
	writeStandardHeaders(w)

	userStruct, err := getUserStructByVars(r)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		w.WriteHeader(404)
		json.NewEncoder(w).Encode(message)
		return
	}
	//Scrubbing data, then further processing
	defer utils.ScrubUserStruct(&userStruct)

	err = verifyUserAccessHeader(userStruct, r)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(message)
		return
	}

	result, err := middleware.DeleteUser(userStruct)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(message)
		return
	}

	message := structs.Message{Success: result}
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(message)
}

//ValidateUserToken validates a given token
func ValidateUserToken(w http.ResponseWriter, r *http.Request) {
	writeStandardHeaders(w)

	//initializing base variables
	timestamp := time.Now().Unix()

	//getting token from url
	vars := mux.Vars(r)
	token := vars["token"]

	//No token provided?
	if token == "" {
		message := structs.Message{Success: false, Message: "no token provided."}
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(message)
		return
	}

	//can the submitted token be converted to an integer?
	tokenInt, err := strconv.Atoi(token)
	if err != nil {
		message := structs.Message{Success: false, Message: "no valid token provided."}
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(message)
		return
	}

	//is there actually a user?
	userStruct, err := getUserStructByVars(r)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		w.WriteHeader(404)
		json.NewEncoder(w).Encode(message)
		return
	}
	defer utils.ScrubUserStruct(&userStruct)

	err = verifyUserAccessHeader(userStruct, r)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(message)
		return
	}

	//is either user or issuer disabled?
	if userStruct.Enabled == false || userStruct.Issuer.Enabled == false {
		message := structs.Message{Success: false, Message: "Issuer or User is disabled"}
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(message)
		return
	}

	//how many times did someone try to authenticate in this timeslot?
	message := core.GenerateMessage(timestamp, core.Present)
	failedCount, err := middleware.GetFailedValidationCount(userStruct, message)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(message)
		return
	}

	denyCountStr, _ := middleware.GetSystemProperty(middleware.DenyLimitKey)
	denyCount, _ := strconv.Atoi(denyCountStr)
	if failedCount >= denyCount {
		message := structs.Message{Success: false, Message: "Too many authentication attempts. Please wait 30 seconds"}
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(message)
		return
	}

	//primary checks green, decrypting user key
	plainkey, err := middleware.GetUserKey(userStruct)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(message)
		return
	}

	//validate token against user key and current system time
	validation := core.ValidateTokenWithTimestamp(tokenInt, plainkey, timestamp)
	//Scrubbing data, then further processing
	defer utils.ScrubInformation(&userStruct, &plainkey)
	if validation.Error != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(message)
		return
	}

	//audit validation
	middleware.CreateAuditEntry(userStruct, validation)

	//build result message
	result := structs.Message{Success: validation.Success}
	if !validation.Success {
		result.Message = "token was NOT validated."
		w.WriteHeader(401)
	} else {
		result.Message = "token successfully validated."
		w.WriteHeader(200)
	}
	json.NewEncoder(w).Encode(result)
}

//GenerateQrCode generates a QrCode
func GenerateQrCode(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	userStruct, err := getUserStructByVars(r)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		json.NewEncoder(w).Encode(message)
		w.WriteHeader(500)
		return
	}
	defer utils.ScrubUserStruct(&userStruct)

	err = verifyUserAccessHeader(userStruct, r)
	if err != nil {
		message := structs.Message{Success: false, Message: err.Error()}
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(message)
		return
	}

	if userStruct.Enabled == false || userStruct.Issuer.Enabled == false {
		message := structs.Message{Success: false, Message: "Issuer or User is disabled"}
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

	w.WriteHeader(200)
	w.Write(png)
}

//writes some standard Headers. These accompany a returned json object
func writeStandardHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
}

//takes in variables of the url and tries to return the corresponding issuer struct
func getIssuerStructByVars(r *http.Request) (structs.Issuer, error) {
	vars := mux.Vars(r)
	issuer := vars["issuer"]

	if issuer == "" {
		return structs.Issuer{}, errors.New("issuer not set in url")
	}

	issuerStruct, err := middleware.GetIssuer(issuer)
	if err != nil {
		return structs.Issuer{}, err
	}

	return issuerStruct, nil
}

//takes in variables of the url and tries to return the corresponding user struct
func getUserStructByVars(r *http.Request) (structs.User, error) {
	issuerStruct, err := getIssuerStructByVars(r)
	if err != nil {
		return structs.User{}, err
	}

	vars := mux.Vars(r)
	user := vars["user"]
	if user == "" {
		return structs.User{}, errors.New("user not set in url")
	}

	userStruct, err := middleware.GetUser(user, issuerStruct)
	if err != nil {
		return structs.User{}, err
	}

	return userStruct, nil
}

// map a JSON object to a generic map
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

func verifyTokenEnabled() bool {
	verifyTokenStr, err := middleware.GetSystemProperty(middleware.VerifyTokenKey)
	if err != nil {
		return true
	}

	if verifyTokenStr == "" {
		verifyTokenStr = "false"
	}
	verifyToken, err := strconv.ParseBool(verifyTokenStr)
	if err != nil {
		return true
	}

	return verifyToken
}

func verifyMasterToken(r *http.Request) error {
	//check if token verification has been enabled.
	verifyToken := verifyTokenEnabled()
	if verifyToken {
		masterToken, err := middleware.GetSystemProperty(middleware.MasterTokenKey)
		if err != nil {
			return err
		}

		tokens := r.Header.Values(VerifyTokenHeaderKey)
		if len(tokens) != 1 {
			return errors.New("no access token provided in request")
		}

		token := tokens[0]
		if token != masterToken {
			return errors.New("wrong access token provided")
		}
	}

	return nil
}

func verifyIssuerAccessHeader(issuer structs.Issuer, r *http.Request) error {
	//check if token verification has been enabled.
	verifyToken := verifyTokenEnabled()
	if verifyToken {
		tokens := r.Header.Values(VerifyTokenHeaderKey)
		if len(tokens) != 1 {
			return errors.New("no access token provided in request")
		}

		token := tokens[0]
		if token != issuer.ID {
			masterToken, err := middleware.GetSystemProperty(middleware.MasterTokenKey)
			if err != nil {
				return err
			}
			if token != masterToken {
				return errors.New("wrong access token provided for issuer")
			}

		}
	}

	return nil
}

func verifyUserAccessHeader(user structs.User, r *http.Request) error {
	//check if token verification has been enabled.
	verifyToken := verifyTokenEnabled()
	if verifyToken {
		tokens := r.Header.Values(VerifyTokenHeaderKey)
		if len(tokens) != 1 {
			return errors.New("no access token provided in request")
		}

		token := tokens[0]
		if token != user.ID && token != user.Issuer.ID {
			masterToken, err := middleware.GetSystemProperty(middleware.MasterTokenKey)
			if err != nil {
				return err
			}
			if token != masterToken {
				return errors.New("wrong access token provided for issuer")
			}
		}
	}
	return nil
}
