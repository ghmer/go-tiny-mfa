package router

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ghmer/go-tiny-mfa/middleware"
	"github.com/ghmer/go-tiny-mfa/qrcode"
	"github.com/ghmer/go-tiny-mfa/structs"
	"github.com/ghmer/go-tiny-mfa/tinymfa"
	"github.com/ghmer/go-tiny-mfa/utils"

	"github.com/gorilla/mux"
)

//VerifyTokenHeaderKey defines the header key to look for the access token
const VerifyTokenHeaderKey string = "tiny-mfa-access-token"

// Router is exported and used in main.go
func Router() *mux.Router {
	router := mux.NewRouter()

	//API Endpoints
	//Return health
	router.HandleFunc("/api/v1/health", Healthcheck).Methods("GET")
	//Return audit entries
	router.HandleFunc("/api/v1/system/audit", GetAuditEntries).Methods("GET")
	//Return current system configuration
	router.HandleFunc("/api/v1/system/configuration", GetSystemConfiguration).Methods("GET")
	//Updates the system configuration
	router.HandleFunc("/api/v1/system/configuration", UpdateSystemConfiguration).Methods("POST")
	//Get the OIDC configuration
	router.HandleFunc("/api/v1/system/oidc", GetOidcConfiguration).Methods("GET")
	//Updates th OIDC configuration
	router.HandleFunc("/api/v1/system/oidc", UpdateOidcConfiguration).Methods("POST")
	//Get the QRCode configuration
	router.HandleFunc("/api/v1/system/qrcode", GetQrCodeConfiguration).Methods("GET")
	//Updates th QRCode configuration
	router.HandleFunc("/api/v1/system/qrcode", UpdateQrCodeConfiguration).Methods("POST")

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

// Healthcheck will return a json object if tiny-mfa is alive
func Healthcheck(w http.ResponseWriter, r *http.Request) {
	writeStandardHeaders(w)

	// send the response
	message := structs.Message{Success: true, Message: "tiny-mfa is alive!"}
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

	//casting map values
	if val, ok := jsonMap[middleware.RouterPortKey]; ok {
		switch val := val.(type) {
		case float64:
			localval := val
			if localval >= 0 && localval <= math.MaxUint16 {
				var castedval uint16 = uint16(localval)
				configuration.RouterPort = castedval
			}
		default:
			{
				returnError(fmt.Errorf("supplied value for router-port is not a number"), 500, w)
				return
			}
		}
	}
	if val, ok := jsonMap[middleware.DenyLimitKey]; ok {
		switch val := val.(type) {
		case float64:
			localval := val
			if localval >= 0 && localval <= math.MaxUint16 {
				var castedval uint8 = uint8(localval)
				configuration.DenyLimit = castedval
			}
		default:
			{
				returnError(fmt.Errorf("supplied value for deny-limit is not a number"), 500, w)
				return
			}
		}
	}
	if val, ok := jsonMap[middleware.VerifyTokenKey]; ok {
		switch val := val.(type) {
		case bool:
			configuration.VerifyTokens = val
		default:
			{
				returnError(err, 500, w)
				return
			}
		}
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

//GetQrCodeConfiguration returns the qrcode configuration
func GetQrCodeConfiguration(w http.ResponseWriter, r *http.Request) {
	writeStandardHeaders(w)

	err := verifyRootToken(r)
	if err != nil {
		returnError(err, 401, w)
		return
	}

	configuration, err := middleware.GetQrCodeConfiguration()
	if err != nil {
		returnError(err, 500, w)
		return
	}

	// send the response
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(configuration)
}

//UpdateQrCodeConfiguration updates the qrcode configuration
func UpdateQrCodeConfiguration(w http.ResponseWriter, r *http.Request) {
	writeStandardHeaders(w)
	err := verifyRootToken(r)
	if err != nil {
		returnError(err, 401, w)
		return
	}

	var qrcodeconfig structs.QrCodeConfig
	decoder := json.NewDecoder(r.Body)
	err = decoder.Decode(&qrcodeconfig)
	if err != nil {
		returnError(err, 500, w)
		return
	}

	_, err = middleware.UpdateQrCodeConfiguration(qrcodeconfig)
	if err != nil {
		returnError(err, 500, w)
		return
	}
	result, err := middleware.GetQrCodeConfiguration()
	if err != nil {
		returnError(err, 500, w)
		return
	}

	// send the response
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(result)
}

//GetOidcConfiguration returns the oidc configuration
func GetOidcConfiguration(w http.ResponseWriter, r *http.Request) {
	writeStandardHeaders(w)

	err := verifyRootToken(r)
	if err != nil {
		returnError(err, 401, w)
		return
	}

	configuration, err := middleware.GetOidcConfiguration()
	if err != nil {
		returnError(err, 500, w)
		return
	}

	// send the response
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(configuration)
}

//UpdateOidcConfiguration updates the oidc configuration
func UpdateOidcConfiguration(w http.ResponseWriter, r *http.Request) {
	writeStandardHeaders(w)
	err := verifyRootToken(r)
	if err != nil {
		returnError(err, 401, w)
		return
	}

	var oidcconfig structs.OidcConfig
	decoder := json.NewDecoder(r.Body)
	err = decoder.Decode(&oidcconfig)
	if err != nil {
		returnError(err, 500, w)
		return
	}

	if !oidcconfig.IsSafe() {
		returnError(errors.New("object not safe"), 500, w)
		return
	}

	_, err = middleware.UpdateOidcConfiguration(oidcconfig)
	if err != nil {
		returnError(err, 500, w)
		return
	}

	result, err := middleware.GetOidcConfiguration()
	if err != nil {
		returnError(err, 500, w)
		return
	}

	// send the response
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(result)
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

	if !issuer.IsSafe() {
		returnError(errors.New("object not safe"), 405, w)
		return
	}

	result, err := middleware.CreateIssuer(issuer)
	if err != nil {
		returnError(err, 405, w)
		return
	}

	issuerStruct := result.Issuer
	defer utils.ScrubIssuerStruct(&issuerStruct)

	w.WriteHeader(200)
	json.NewEncoder(w).Encode(result)
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
		switch val := val.(type) {
		case bool:
			issuerStruct.Enabled = val
		default:
			{
				returnError(fmt.Errorf("supplied value for enabled is not a boolean"), 500, w)
				return
			}
		}
	}

	if val, ok := jsonMap["contact"]; ok {
		switch val := val.(type) {
		case string:
			var mailregex string = `[^@ \t\r\n]+@[^@ \t\r\n]+\.[^@ \t\r\n]+`
			ok, _ := regexp.MatchString(mailregex, val)
			if !ok {
				returnError(fmt.Errorf("supplied value for contact is not a valid email address"), 500, w)
				return
			}
			issuerStruct.Contact = val
		default:
			{
				returnError(fmt.Errorf("supplied value for contact is not a string"), 500, w)
				return
			}
		}
	}

	if val, ok := jsonMap["token_length"]; ok {
		switch val := val.(type) {
		case float64:
			localval := val
			if localval < 5 || localval > 8 {
				returnError(fmt.Errorf("%f is not a valid length for a token. try something between 5-8", localval), 500, w)
			}
			var castedval uint8 = uint8(localval)
			issuerStruct.TokenLength = castedval
		default:
			{
				returnError(fmt.Errorf("supplied value for token_length is not a number"), 500, w)
				return
			}
		}
	}

	result, err := middleware.UpdateIssuer(issuerStruct)
	if err != nil {
		returnError(err, 500, w)
		return
	}

	w.WriteHeader(200)
	message := structs.Message{Success: result, Message: "issuer successfully updated"}
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
	message := structs.Message{Success: result, Message: "issuer successfully deleted"}
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
		switch val := val.(type) {
		case string:
			var strregex string = `^[\w]*$`
			ok, _ = regexp.MatchString(strregex, val)
			if !ok {
				returnError(fmt.Errorf("supplied value for description is not valid"), 500, w)
				return
			}
			issuerStruct.Contact = val
		default:
			{
				returnError(fmt.Errorf("supplied value for description is not a string"), 500, w)
				return
			}
		}
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

	if !user.IsSafe() {
		returnError(errors.New("object not safe"), 500, w)
		return
	}

	_, err = middleware.CreateUser(user)
	if err != nil {
		returnError(err, 500, w)
		return
	}
	userStruct, err := middleware.GetUser(user.Name, issuerStruct)
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
		switch val := val.(type) {
		case string:
			var mailregex string = `[^@ \t\r\n]+@[^@ \t\r\n]+\.[^@ \t\r\n]+`
			ok, _ = regexp.MatchString(mailregex, val)
			if !ok {
				returnError(fmt.Errorf("supplied value for email is not valid"), 500, w)
				return
			}
			userStruct.Email = val
		default:
			{
				returnError(fmt.Errorf("supplied value for email is not a string"), 500, w)
				return
			}
		}

	}
	if val, ok := jsonMap["enabled"]; ok {
		switch val := val.(type) {
		case bool:
			userStruct.Enabled = val
		default:
			{
				returnError(fmt.Errorf("supplied value for enabled is not a boolean"), 500, w)
				return
			}
		}

	}

	result, err := middleware.UpdateUser(userStruct)
	if err != nil {
		returnError(err, 500, w)
		return
	}

	message := structs.Message{Success: result, Message: "user successfully updated"}
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

	message := structs.Message{Success: result, Message: "user successfully deleted"}
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
		switch val := val.(type) {
		case string:
			token = val
		default:
			{
				returnError(fmt.Errorf("supplied value for token is not a string"), 500, w)
				return
			}
		}
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
	if !userStruct.Enabled || !userStruct.Issuer.Enabled {
		returnError(err, 500, w)
		return
	}

	//how many times did someone try to authenticate in this timeslot?
	message := tinymfa.GenerateMessage(timestamp, tinymfa.Present)
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

	tokenlength, err := middleware.GetTokenLength(userStruct.Issuer)
	if err != nil {
		returnError(err, 500, w)
		return
	}

	//validate token against user key and current system time
	validation := tinymfa.ValidateTokenWithTimestamp(tokenInt, plainkey, timestamp, tokenlength)
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

	if !userStruct.Enabled || !userStruct.Issuer.Enabled {
		returnError(errors.New("issuer or user is disabled"), 500, w)
		return
	}

	tokenlength, err := middleware.GetTokenLength(userStruct.Issuer)
	if err != nil {
		returnError(err, 500, w)
		return
	}

	qrconfig, err := middleware.GetQrCodeConfiguration()
	if err != nil {
		returnError(err, 500, w)
		return
	}

	png, err := qrcode.GenerateQrCode(userStruct, qrconfig.BgColor, qrconfig.FgColor, tokenlength)
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
