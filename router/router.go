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

	//Return all registered access tokens for a given issuer
	router.HandleFunc("/api/v1/issuer/{issuer}/token", GetIssuerAccessTokens).Methods("GET")
	//Creates a new access token for the given issuer using a PUT request
	router.HandleFunc("/api/v1/issuer/{issuer}/token", CreateIssuerAccessToken).Methods("POST")
	//Deletes a distinct access token in the scope of a distinct issuer
	router.HandleFunc("/api/v1/issuer/{issuer}/token/{tokenid}", DeleteIssuerAccessToken).Methods("DELETE")

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
	//Generates and returns a PNG image of a QRCode in the scope of a distinct user and issuer
	router.HandleFunc("/api/v1/issuer/{issuer}/users/{user}/totp", GenerateQrCode).Methods("GET")
	//Validates a given token in the scope of a distinct user and issuer
	router.HandleFunc("/api/v1/issuer/{issuer}/users/{user}/totp", ValidateUserToken).Methods("POST")

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
	err := verifyRootToken(r)
	if err != nil {
		returnError(err, 401, w)
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
		returnError(err, 500, w)
		return
	}
	// send the response
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(audits)
}

//GetSystemConfiguration returns the system configuration
func GetSystemConfiguration(w http.ResponseWriter, r *http.Request) {
	writeStandardHeaders(w)

	err := verifyRootToken(r)
	if err != nil {
		returnError(err, 401, w)
		return
	}

	configuration, err := middleware.GetSystemConfiguration()
	if err != nil {
		returnError(err, 500, w)
		return
	}

	// send the response
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(configuration)
}

//UpdateSystemConfiguration updates the system configuration
func UpdateSystemConfiguration(w http.ResponseWriter, r *http.Request) {
	writeStandardHeaders(w)
	err := verifyRootToken(r)
	if err != nil {
		returnError(err, 401, w)
		return
	}

	jsonMap, err := mapJSON(r.Body)
	if err != nil {
		returnError(err, 500, w)
		return
	}

	configuration, err := middleware.GetSystemConfiguration()
	if err != nil {
		returnError(err, 500, w)
		return
	}

	if val, ok := jsonMap[middleware.RouterPortKey]; ok {
		localval := val.(float64)
		configuration.RouterPort = uint16(localval)
	}
	if val, ok := jsonMap[middleware.DenyLimitKey]; ok {
		localval := val.(float64)
		configuration.DenyLimit = uint8(localval)
	}
	if val, ok := jsonMap[middleware.VerifyTokenKey]; ok {
		configuration.VerifyTokens = val.(bool)
	}

	configuration, err = middleware.UpdateSystemConfiguration(configuration)
	if err != nil {
		returnError(err, 500, w)
		return
	}

	// send the response
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(configuration)
}

//GetIssuers returns all issuers
func GetIssuers(w http.ResponseWriter, r *http.Request) {
	writeStandardHeaders(w)
	err := verifyRootToken(r)
	if err != nil {
		returnError(err, 401, w)
		return
	}

	issuers, err := middleware.GetIssuers()
	if err != nil {
		returnError(err, 500, w)
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
	err := verifyRootToken(r)
	if err != nil {
		returnError(err, 401, w)
		return
	}

	var issuer structs.Issuer
	decoder := json.NewDecoder(r.Body)
	decoder.Decode(&issuer)

	resultmap, err := middleware.CreateIssuer(issuer)
	if err != nil {
		returnError(err, 405, w)
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
		returnError(err, 404, w)
		return
	}
	defer utils.ScrubIssuerStruct(&issuerStruct)

	err = verifyIssuerToken(issuerStruct, r)
	if err != nil {
		returnError(err, 401, w)
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
		returnError(err, 500, w)
		return
	}

	issuerStruct, err := getIssuerStructByVars(r)
	if err != nil {
		returnError(err, 404, w)
		return
	}
	defer utils.ScrubIssuerStruct(&issuerStruct)

	err = verifyIssuerToken(issuerStruct, r)
	if err != nil {
		returnError(err, 401, w)
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
		returnError(err, 500, w)
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
		returnError(err, 404, w)
		return
	}
	defer utils.ScrubIssuerStruct(&issuerStruct)

	err = verifyIssuerToken(issuerStruct, r)
	if err != nil {
		returnError(err, 401, w)
		return
	}

	result, err := middleware.DeleteIssuer(issuerStruct)
	if err != nil {
		returnError(err, 500, w)
		return
	}

	w.WriteHeader(200)
	message := structs.Message{Success: result}
	json.NewEncoder(w).Encode(message)
}

//GetIssuerAccessTokens returns all access tokens for a given issuer
func GetIssuerAccessTokens(w http.ResponseWriter, r *http.Request) {
	writeStandardHeaders(w)

	issuerStruct, err := getIssuerStructByVars(r)
	if err != nil {
		returnError(err, 404, w)
		return
	}
	defer utils.ScrubIssuerStruct(&issuerStruct)

	err = verifyIssuerToken(issuerStruct, r)
	if err != nil {
		returnError(err, 401, w)
		return
	}

	result, err := middleware.GetIssuerAccessTokens(issuerStruct)
	if err != nil {
		returnError(err, 500, w)
		return
	}

	w.WriteHeader(200)
	json.NewEncoder(w).Encode(result)
}

//CreateIssuerAccessToken adds an access token to a distinct issuer
func CreateIssuerAccessToken(w http.ResponseWriter, r *http.Request) {
	writeStandardHeaders(w)

	jsonMap, err := mapJSON(r.Body)
	if err != nil {
		returnError(err, 500, w)
		return
	}

	issuerStruct, err := getIssuerStructByVars(r)
	if err != nil {
		returnError(err, 404, w)
		return
	}
	defer utils.ScrubIssuerStruct(&issuerStruct)

	err = verifyIssuerToken(issuerStruct, r)
	if err != nil {
		returnError(err, 401, w)
		return
	}

	var description string
	if val, ok := jsonMap["description"]; ok {
		description = val.(string)

	}

	if description == "" {
		returnError(errors.New("description must be provided for an access token"), 500, w)
		return
	}

	token := structs.NewAccessToken(issuerStruct.ID, description)
	err = middleware.InsertToken(token)
	if err != nil {
		returnError(err, 500, w)
		return
	}

	w.WriteHeader(200)
	result := make(map[string]interface{}, 2)
	result["message"] = structs.Message{Success: true, Message: "token successfully created"}
	result["token"] = token
	json.NewEncoder(w).Encode(result)

}

//DeleteIssuerAccessToken deletes a token from the database
func DeleteIssuerAccessToken(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	tokenid := vars["tokenid"]
	if tokenid == "" {
		returnError(errors.New("token id not set in url"), 500, w)
		return
	}

	if tokenid == "*" {
		returnError(errors.New("please don't do that"), 500, w)
		return
	}

	writeStandardHeaders(w)

	issuerStruct, err := getIssuerStructByVars(r)
	if err != nil {
		returnError(err, 404, w)
		return
	}
	defer utils.ScrubIssuerStruct(&issuerStruct)

	err = verifyIssuerToken(issuerStruct, r)
	if err != nil {
		returnError(err, 401, w)
		return
	}

	err = middleware.DeleteToken(issuerStruct.ID, tokenid)
	if err != nil {
		returnError(err, 500, w)
		return
	}

	w.WriteHeader(200)
	message := structs.Message{Success: true, Message: "token successfully deleted"}
	json.NewEncoder(w).Encode(message)
}

//GetUsers returns all users for a given issuer
func GetUsers(w http.ResponseWriter, r *http.Request) {
	writeStandardHeaders(w)

	issuerStruct, err := getIssuerStructByVars(r)
	if err != nil {
		returnError(err, 404, w)
		return
	}

	err = verifyIssuerToken(issuerStruct, r)
	if err != nil {
		returnError(err, 401, w)
		return
	}

	users, err := middleware.GetUsers(issuerStruct)
	for i := range users {
		defer utils.ScrubUserStruct(&(users)[i])
	}
	if err != nil {
		returnError(err, 500, w)
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
		returnError(err, 404, w)
		return
	}

	err = verifyIssuerToken(issuerStruct, r)
	if err != nil {
		returnError(err, 401, w)
		return
	}

	var user structs.User
	decoder := json.NewDecoder(r.Body)
	decoder.Decode(&user)
	user.Issuer = issuerStruct

	userStruct, err := middleware.CreateUser(user)
	if err != nil {
		returnError(err, 500, w)
		return
	}
	defer utils.ScrubUserStruct(&userStruct)

	w.WriteHeader(200)
	json.NewEncoder(w).Encode(userStruct)
}

//GetUser returns a distinct user in the scope of the given issuer
func GetUser(w http.ResponseWriter, r *http.Request) {
	writeStandardHeaders(w)

	userStruct, err := getUserStructByVars(r)
	if err != nil {
		returnError(err, 404, w)
		return
	}

	err = verifyIssuerToken(userStruct.Issuer, r)
	if err != nil {
		returnError(err, 401, w)
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
		returnError(err, 404, w)
		return
	}
	defer utils.ScrubUserStruct(&userStruct)

	err = verifyIssuerToken(userStruct.Issuer, r)
	if err != nil {
		returnError(err, 401, w)
		return
	}

	jsonMap, err := mapJSON(r.Body)
	if err != nil {
		returnError(err, 500, w)
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
		returnError(err, 500, w)
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
		returnError(err, 404, w)
		return
	}
	//Scrubbing data, then further processing
	defer utils.ScrubUserStruct(&userStruct)

	err = verifyIssuerToken(userStruct.Issuer, r)
	if err != nil {
		returnError(err, 401, w)
		return
	}

	result, err := middleware.DeleteUser(userStruct)
	if err != nil {
		returnError(err, 500, w)
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

	jsonMap, err := mapJSON(r.Body)
	if err != nil {
		returnError(err, 500, w)
		return
	}

	var token string
	if val, ok := jsonMap["token"]; ok {
		token = val.(string)
	}

	//No token provided?
	if token == "" {
		returnError(errors.New("no token provided"), 500, w)
		return
	}

	//can the submitted token be converted to an integer?
	tokenInt, err := strconv.Atoi(token)
	if err != nil {
		returnError(errors.New("no valid token provided"), 500, w)
		return
	}

	//is there actually a user?
	userStruct, err := getUserStructByVars(r)
	if err != nil {
		returnError(err, 404, w)
		return
	}
	defer utils.ScrubUserStruct(&userStruct)

	err = verifyIssuerToken(userStruct.Issuer, r)
	if err != nil {
		returnError(err, 401, w)
		return
	}

	//is either user or issuer disabled?
	if userStruct.Enabled == false || userStruct.Issuer.Enabled == false {
		returnError(err, 500, w)
		return
	}

	//how many times did someone try to authenticate in this timeslot?
	message := core.GenerateMessage(timestamp, core.Present)
	failedCount, err := middleware.GetFailedValidationCount(userStruct, message)
	if err != nil {
		returnError(err, 500, w)
		return
	}

	denyCountStr, _ := middleware.GetSystemProperty(middleware.DenyLimitKey)
	denyCount, _ := strconv.Atoi(denyCountStr)
	if failedCount >= denyCount {
		returnError(errors.New("too many authentication attempts. Please wait 30 seconds"), 401, w)
		return
	}

	//primary checks green, decrypting user key
	plainkey, err := middleware.GetUserKey(userStruct)
	if err != nil {
		returnError(err, 500, w)
		return
	}

	//validate token against user key and current system time
	validation := core.ValidateTokenWithTimestamp(tokenInt, plainkey, timestamp)
	//Scrubbing data, then further processing
	defer utils.ScrubInformation(&userStruct, &plainkey)
	if validation.Error != nil {
		returnError(err, 500, w)
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
		returnError(err, 500, w)
		return
	}
	defer utils.ScrubUserStruct(&userStruct)

	err = verifyIssuerToken(userStruct.Issuer, r)
	if err != nil {
		returnError(err, 401, w)
		return
	}

	if userStruct.Enabled == false || userStruct.Issuer.Enabled == false {
		returnError(errors.New("issuer or user is disabled"), 500, w)
		return
	}

	png, err := qrcode.GenerateQrCode(userStruct)
	if err != nil {
		returnError(err, 500, w)
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

//returns true if the token verification has been enabled
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

//verify whether the root token was part of the request
func verifyRootToken(r *http.Request) error {
	//check if token verification has been enabled.
	verifyToken := verifyTokenEnabled()
	if verifyToken {
		rootToken, err := middleware.GetSystemProperty(middleware.RootTokenKey)
		if err != nil {
			return err
		}

		tokens := r.Header.Values(VerifyTokenHeaderKey)
		if len(tokens) != 1 {
			return errors.New("no access token provided in request")
		}

		token := tokens[0]

		err = utils.BycrptVerify([]byte(rootToken), []byte(token))

		if err != nil {
			return errors.New("wrong access token provided")
		}
	}

	return nil
}

//verify whether a valid issuer token was part of the request
func verifyIssuerToken(issuer structs.Issuer, r *http.Request) error {
	//check if token verification has been enabled.
	verifyToken := verifyTokenEnabled()
	if verifyToken {
		tokens := r.Header.Values(VerifyTokenHeaderKey)
		if len(tokens) != 1 {
			return errors.New("no access token provided in request")
		}

		token := tokens[0]
		validated, err := middleware.ValidateToken(issuer, token)
		if !validated && err.Error() == "token not verified" {
			err = verifyRootToken(r)
			if err != nil {
				return err
			}
		} else if !validated {
			return err
		}
	}

	return nil
}

//return the error via the http ResponseWriter
func returnError(err error, statuscode int, w http.ResponseWriter) {
	message := structs.Message{Success: false, Message: err.Error()}
	w.WriteHeader(statuscode)
	json.NewEncoder(w).Encode(message)
}
