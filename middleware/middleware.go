package middleware

import (
	"database/sql"
	"encoding/base32"
	"errors"
	"fmt"
	"go-tiny-mfa/structs"
	"go-tiny-mfa/utils"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"

	// SQL Driver package
	_ "github.com/lib/pq"
)

const (
	//RouterPortKey the key of the router port entry in serverconfig table
	RouterPortKey = "http_port"
	//DenyLimitKey the key of the deny limit entry in serverconfig table
	DenyLimitKey = "deny_limit"
	//MasterTokenKey is the key of the master token entry in serverconfig table
	MasterTokenKey = "root_token"
	//VerifyTokenKey is the key of the verify token entry in serverconfig table
	VerifyTokenKey = "verify_tokens"
)

//SecretFilePath location of the master key
const SecretFilePath string = "/opt/go-tiny-mfa/secrets/key"

// CreateConnection creates a connection to a postgres DB
func CreateConnection() *sql.DB {
	dbuser := os.Getenv("POSTGRES_USER")
	dbpass := os.Getenv("POSTGRES_PASSWORD")
	dbhost := os.Getenv("POSTGRES_HOST")
	dbname := os.Getenv("POSTGRES_DB")

	dbURL := fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=disable", dbuser, dbpass, dbhost, dbname)

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		panic(err)
	}
	// check the connection
	err = db.Ping()
	if err != nil {
		panic(err)
	}

	return db
}

//InitializeSystem will initialize the database and the master key
func InitializeSystem() error {
	err := initializeDatabase()
	if err != nil {
		return err
	}

	err = initializeMasterKey()
	if err != nil {
		return err
	}

	return nil
}

//initializeDatabase will create the issuer and user tables
func initializeDatabase() error {
	err := initializeSystemTable()
	if err != nil {
		return err
	}
	err = initializeIssuerTable()
	if err != nil {
		return err
	}
	err = initializeUserTable()
	if err != nil {
		return err
	}
	err = initializeAuditTable()
	if err != nil {
		return err
	}
	err = initializeActionsTable()
	if err != nil {
		return err
	}
	err = initializeAccessTokenTable()
	if err != nil {
		return err
	}

	return nil
}

//initializes the user table in the database
func initializeUserTable() error {
	db := CreateConnection()
	defer db.Close()
	createstring := `CREATE TABLE IF NOT EXISTS accounts (
		id varchar(45) NOT NULL,
		username varchar(32) NOT NULL,
		email varchar(128) NOT NULL,
		issuer_id varchar(45) NOT NULL,
		key varchar(128) NOT NULL UNIQUE,
		enabled boolean DEFAULT '1',
		unique (username, email, issuer_id),
		PRIMARY KEY (id)
	);`
	_, err := db.Exec(createstring)
	if err != nil {
		return err
	}
	return nil
}

//initializes the audit table in the database
func initializeAuditTable() error {
	db := CreateConnection()
	defer db.Close()
	createstring := `CREATE TABLE IF NOT EXISTS audit (
		id serial NOT NULL,
		issuer varchar(32) NOT NULL,
		username varchar(32) NOT NULL,
		message varchar(16) NOT NULL,
		success boolean DEFAULT '0',
		validated_on timestamp NOT NULL,
		PRIMARY KEY (id)
	);`
	_, err := db.Exec(createstring)
	if err != nil {
		return err
	}
	return nil
}

//CreateAuditEntry creates an audit in the database
func CreateAuditEntry(user structs.User, validation structs.Validation) error {
	db := CreateConnection()
	defer db.Close()

	insertString := `INSERT INTO audit(issuer, username, message, validated_on, success)
					 VALUES($1, $2, $3, $4, $5)`

	_, err := db.Exec(insertString, user.Issuer.Name, user.Name, validation.Message, time.Now(), validation.Success)
	if err != nil {
		return err
	}
	return nil
}

//GetFailedValidationCount returns the number of times a user failed validation for a given message
func GetFailedValidationCount(user structs.User, message int64) (int, error) {
	db := CreateConnection()
	defer db.Close()
	queryString := `SELECT COUNT(id) FROM audit WHERE issuer=$1 AND username=$2 AND message=$3 AND success=$4`
	rows, err := db.Query(queryString, user.Issuer.Name, user.Name, message, false)
	if err != nil {
		return -1, err
	}

	var count int
	if rows.Next() {
		rows.Scan(&count)
	}

	return count, nil
}

//dynamically creates a query string based on the supplied audit query parameters
func createAuditQueryString(parameters structs.AuditQueryParameter) (string, int, []time.Time) {
	builder := strings.Builder{}
	var params []time.Time = make([]time.Time, 2)

	paramID := 0
	builder.WriteString(parameters.BaseQuery)
	if (parameters.Before != time.Time{} || parameters.After != time.Time{}) {
		builder.WriteString(" WHERE ")
		paramID++
		if (parameters.Before != time.Time{}) {
			builder.WriteString(fmt.Sprintf("validated_on < $%d", paramID))
			params[paramID-1] = parameters.Before
		}

		if (parameters.Before != time.Time{} && parameters.After != time.Time{}) {
			builder.WriteString(" AND ")
			paramID++
		}

		if (parameters.After != time.Time{}) {
			builder.WriteString(fmt.Sprintf("validated_on > $%d", paramID))
			params[paramID-1] = parameters.After
		}
	}
	return builder.String(), paramID, params
}

func countAuditEntries(parameters structs.AuditQueryParameter) (int, error) {
	db := CreateConnection()
	defer db.Close()

	parameters.BaseQuery = `SELECT COUNT(id) FROM audit`
	sqlCountSelect, paramID, params := createAuditQueryString(parameters)

	var res *sql.Rows
	var err error
	switch paramID {
	case 0:
		res, err = db.Query(sqlCountSelect)
	case 1:
		res, err = db.Query(sqlCountSelect, params[0].Format(parameters.TargetDateFormat))
	case 2:
		res, err = db.Query(sqlCountSelect, params[0].Format(parameters.TargetDateFormat), params[1].Format(parameters.TargetDateFormat))
	}

	if err != nil {
		return -1, err
	}
	defer res.Close()

	count, err := checkCount(res)
	if err != nil {
		return -1, err
	}

	return count, nil
}

//GetAuditEntries returns all audit entries from the db
func GetAuditEntries(parameters structs.AuditQueryParameter) ([]structs.AuditEntry, error) {
	count, err := countAuditEntries(parameters)
	if err != nil {
		return nil, err
	}
	audits := make([]structs.AuditEntry, count)

	db := CreateConnection()
	defer db.Close()
	parameters.BaseQuery = `SELECT id, issuer, username, message, success, validated_on FROM audit`
	sqlQuery, paramID, params := createAuditQueryString(parameters)

	var rows *sql.Rows
	switch paramID {
	case 0:
		rows, err = db.Query(sqlQuery)
	case 1:
		rows, err = db.Query(sqlQuery, params[0].Format(parameters.TargetDateFormat))
	case 2:
		rows, err = db.Query(sqlQuery, params[0].Format(parameters.TargetDateFormat), params[1].Format(parameters.TargetDateFormat))
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	loop := 0
	for rows.Next() {
		var id int
		var issuer string
		var name string
		var message int64
		var success bool
		var date string
		rows.Scan(&id, &issuer, &name, &message, &success, &date)

		auditEntry := structs.AuditEntry{ID: id, Issuer: issuer, Username: name, Message: message, ValidatedOn: date, Success: success}
		audits[loop] = auditEntry
		loop++
	}

	return audits, nil
}

//initializes the issuer table in the database
func initializeIssuerTable() error {
	db := CreateConnection()
	defer db.Close()
	createstring := `CREATE TABLE IF NOT EXISTS issuer (
		id varchar(45) NOT NULL,
		name varchar(32) NOT NULL UNIQUE,
		contact varchar(255) NOT NULL,
		key varchar(128) NOT NULL UNIQUE,
		enabled boolean DEFAULT '1',
		PRIMARY KEY (id)
	);`
	_, err := db.Exec(createstring)
	if err != nil {
		return err
	}
	return nil
}

//initializes the access_token table
func initializeAccessTokenTable() error {
	db := CreateConnection()
	defer db.Close()
	createstring := `CREATE TABLE IF NOT EXISTS access_tokens (
		id serial NOT NULL,
		ref_id_action smallint,
		ref_id_object varchar(45),
		access_token varchar(64) NOT NULL,
		PRIMARY KEY (access_token)
	);`
	_, err := db.Exec(createstring)
	if err != nil {
		return err
	}
	return nil
}

//initializes the system table in the database
func initializeSystemTable() error {
	db := CreateConnection()
	defer db.Close()
	createstring := `CREATE TABLE IF NOT EXISTS serverconfig (
		id serial NOT NULL,
		http_port integer NOT NULL,
		deny_limit smallint NOT NULL,
		verify_tokens bool DEFAULT false,
		root_token varchar(64) NOT NULL,
		PRIMARY KEY (id)
	);`
	_, err := db.Exec(createstring)
	if err != nil {
		return err
	}

	queryKey := "SELECT COUNT(id) FROM serverconfig"
	count, err := checkCountWithQuery(queryKey)
	if err != nil {
		return err
	}

	if count < 1 {
		err = initializeStandardConfiguration()
		if err != nil {
			return err
		}
	}

	return nil
}

//initialize standard configuration
func initializeStandardConfiguration() error {
	db := CreateConnection()
	defer db.Close()

	var config = structs.StandardServerConfig()
	hashedtoken, err := utils.BcryptHash([]byte(config.RootToken))
	if err != nil {
		return err
	}

	insertQuery := `INSERT INTO serverconfig 
	(http_port,deny_limit,verify_tokens,root_token) 
	VALUES($1,$2,$3,$4);`
	_, err = db.Exec(insertQuery, config.RouterPort, config.DenyLimit, config.VerifyTokens, string(hashedtoken))
	if err != nil {
		return err
	}

	printSystemConfiguration(config)

	return nil
}

//initializes the actions level table
func initializeActionsTable() error {
	db := CreateConnection()
	defer db.Close()
	createstring := `CREATE TABLE IF NOT EXISTS actions (
		id smallint NOT NULL,
		action varchar(16)
	);`
	_, err := db.Exec(createstring)
	if err != nil {
		return err
	}

	queryKey := "SELECT COUNT(id) FROM actions"
	count, err := checkCountWithQuery(queryKey)
	if err != nil {
		return err
	}

	if count < 1 {
		err = initializeStandardActions()
		if err != nil {
			return err
		}
	}

	return nil
}

//initialize standard actions
func initializeStandardActions() error {
	db := CreateConnection()
	defer db.Close()

	var configuration = map[int]string{
		1: "GET",
		2: "POST",
		3: "DELETE",
		4: "FULL",
	}

	for key, value := range configuration {
		insertQuery := `INSERT INTO actions(id,action) VALUES($1,$2);`
		_, err := db.Exec(insertQuery, key, value)
		if err != nil {
			return err
		}
	}

	return nil
}

func printSystemConfiguration(config structs.ServerConfig) {
	fmt.Println("tiny-mfa configuration")
	fmt.Println("------------------------------------------------")
	fmt.Println("router port  ", config.RouterPort)
	fmt.Println("deny limit   ", config.DenyLimit)
	fmt.Println("verify tokens", config.VerifyTokens)
	fmt.Println("root token   ", config.RootToken)
}

//GetSystemProperty returns the value for the given key
func GetSystemProperty(key string) (string, error) {
	db := CreateConnection()
	defer db.Close()

	var value string
	queryKey := fmt.Sprintf("SELECT %s FROM serverconfig;", key)
	res, err := db.Query(queryKey)
	if err != nil {
		return value, err
	}
	defer res.Close()

	if res.Next() {
		res.Scan(&value)
	}

	fmt.Println(value)
	return value, nil
}

//GetSystemConfiguration returns the system config
func GetSystemConfiguration() (structs.ServerConfig, error) {
	db := CreateConnection()
	defer db.Close()

	queryKey := "SELECT http_port,deny_limit,verify_tokens,root_token FROM serverconfig"
	res, err := db.Query(queryKey)
	if err != nil {
		return structs.ServerConfig{}, err
	}
	defer res.Close()
	var config structs.ServerConfig
	if res.Next() {
		var httpPort uint16
		var denyLimit uint8
		var verifyTokens bool
		var rootToken string

		res.Scan(&httpPort, &denyLimit, &verifyTokens, &rootToken)
		config = structs.ServerConfig{
			RouterPort:   httpPort,
			DenyLimit:    denyLimit,
			VerifyTokens: verifyTokens,
			RootToken:    rootToken,
		}
	}

	return config, nil
}

//UpdateSystemConfiguration updates the system configuration
func UpdateSystemConfiguration(config structs.ServerConfig) (structs.ServerConfig, error) {
	db := CreateConnection()
	defer db.Close()

	sqlQuery := `UPDATE serverconfig 
					SET 
					http_port=$1, 
					deny_limit=$2,
					verify_tokens=$3`
	_, err := db.Exec(sqlQuery, config.RouterPort, config.DenyLimit, config.VerifyTokens)
	if err != nil {
		return structs.ServerConfig{}, err
	}

	return GetSystemConfiguration()
}

//checks whether the master key exists on the file system
//will create it if this is not the case
func initializeMasterKey() error {
	_, err := os.Stat(SecretFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			// key does not exist
			fmt.Println("Warning: No master key found. A new one is being generated")
			base32MasterKey, err := utils.GenerateExtendedKeyBase32()
			if err != nil {
				return err
			}
			file, err := os.Create(SecretFilePath)
			if err != nil {
				return err
			}

			// Defer is used for purposes of cleanup like
			// closing a running file after the file has
			// been written and main //function has
			// completed execution
			defer file.Close()

			// len variable captures the length
			// of the string written to the file.
			_, err = file.WriteString(base32MasterKey)
			if err != nil {
				return err
			}

			defer os.Chmod(SecretFilePath, 0400)

			return nil
		}
	}

	return err
}

//GetMasterKey retrieves the key generated on system initialization
func GetMasterKey() ([]byte, error) {
	encodedMasterKey, err := ioutil.ReadFile(SecretFilePath)
	if err != nil {
		log.Panicf("failed reading data from file: %s", err)
	}

	masterKey, err := utils.DecodeBase32Key(string(encodedMasterKey))
	return masterKey, err
}

//GetIssuerKey returns the decrypted issuer key as byte array
func GetIssuerKey(issuer structs.Issuer) ([]byte, error) {
	cryptedKey, err := utils.DecodeBase32Key(issuer.Key)
	if err != nil {
		return nil, err
	}

	masterKey, err := GetMasterKey()
	if err != nil {
		return nil, err
	}
	defer utils.ScrubKey(&masterKey)

	plainKey := utils.Decrypt(cryptedKey, masterKey)
	return plainKey, nil
}

//GetUserKey returns the decrypted user key as byte array
func GetUserKey(user structs.User) ([]byte, error) {
	cryptedKey, err := utils.DecodeBase32Key(user.Key)
	if err != nil {
		return nil, err
	}

	issuerKey, err := GetIssuerKey(user.Issuer)
	if err != nil {
		return nil, err
	}
	defer utils.ScrubKey(&issuerKey)

	plainKey := utils.Decrypt(cryptedKey, issuerKey)
	return plainKey, nil
}

//GetUserKeyBase32 returns the decrypted user key in base32 encoding
func GetUserKeyBase32(user structs.User) (string, error) {
	plainKey, err := GetUserKey(user)
	if err != nil {
		return "", err
	}

	return base32.StdEncoding.EncodeToString(plainKey), nil
}

func checkCount(rows *sql.Rows) (int, error) {
	var count int
	for rows.Next() {
		err := rows.Scan(&count)
		if err != nil {
			return -1, err
		}
	}
	return count, nil
}

func checkCountWithQuery(sqlQuery string) (int, error) {
	db := CreateConnection()
	defer db.Close()

	res, err := db.Query(sqlQuery)
	if err != nil {
		return -1, err
	}
	defer res.Close()

	count, err := checkCount(res)
	if err != nil {
		return -1, err
	}

	return count, nil
}

func countIssuers() (int, error) {
	db := CreateConnection()
	defer db.Close()
	sqlCountSelect := `SELECT COUNT(name) FROM issuer;`
	res, err := db.Query(sqlCountSelect)
	if err != nil {
		return -1, err
	}
	defer res.Close()

	count, err := checkCount(res)
	if err != nil {
		return -1, err
	}

	return count, err
}

//GetIssuers returns all Issuers from the database
func GetIssuers() ([]structs.Issuer, error) {
	count, err := countIssuers()
	if err != nil {
		return nil, err
	}
	issuers := make([]structs.Issuer, count)
	db := CreateConnection()
	defer db.Close()

	sqlSelect := `SELECT id, name, contact, key, enabled FROM issuer`
	rows, errorMessage := db.Query(sqlSelect)
	if errorMessage != nil {
		return issuers, errorMessage
	}
	defer rows.Close()

	loop := 0
	for rows.Next() {
		var id string
		var name string
		var contact string
		var key string
		var enabled bool
		rows.Scan(&id, &name, &contact, &key, &enabled)

		issuerStruct := structs.Issuer{ID: id, Name: name, Contact: contact, Key: key, Enabled: enabled}
		issuers[loop] = issuerStruct
		loop++
	}

	return issuers, nil
}

//CreateIssuer inserts a Issuer struct to the database
func CreateIssuer(issuer structs.Issuer) (map[string]interface{}, error) {
	db := CreateConnection()
	defer db.Close()

	var result map[string]interface{} = make(map[string]interface{})

	issuer.ID = uuid.New().String()
	masterKey, err := GetMasterKey()

	if err != nil {
		result["error"] = err
		return result, err
	}
	cryptedKey, err := utils.GenerateCryptedKeyBase32(masterKey)
	if err != nil {
		result["error"] = err
		return result, err
	}
	issuer.Key = cryptedKey

	sqlInsert := `INSERT INTO issuer (id, name, contact, key, enabled)
				VALUES ($1, $2, $3, $4, $5)
				RETURNING id`
	res, err := db.Exec(sqlInsert, issuer.ID, issuer.Name, issuer.Contact, issuer.Key, issuer.Enabled)
	if err != nil {
		result["error"] = err
		return result, err
	}

	rows, _ := res.RowsAffected()
	if rows != 1 {
		result["error"] = errors.New("Insert Operation was not successful")
		return result, err
	}

	token := structs.NewFullAccessToken(issuer.ID)
	err = InsertToken(token)
	if err != nil {
		result["error"] = err
		return result, err
	}

	result["issuer"] = issuer
	result["token"] = token

	return result, nil
}

//GetIssuer returns the requested issuer from the database as Issuer struct
func GetIssuer(issuer string) (structs.Issuer, error) {
	db := CreateConnection()
	defer db.Close()
	sqlSelect := `SELECT id, name, contact, key, enabled FROM issuer where name=$1`
	res, err := db.Query(sqlSelect, issuer)
	if err != nil {
		return structs.Issuer{}, err
	}
	defer res.Close()

	var id string
	var name string
	var contact string
	var key string
	var enabled bool
	if res.Next() {
		res.Scan(&id, &name, &contact, &key, &enabled)
	} else {
		return structs.Issuer{}, errors.New("issuer not found in db")
	}

	issuerStruct := structs.Issuer{ID: id, Name: name, Contact: contact, Key: key, Enabled: enabled}
	return issuerStruct, nil
}

//GetIssuerByID returns the requested issuer from the database as Issuer struct
func GetIssuerByID(issuerID string) (structs.Issuer, error) {
	db := CreateConnection()
	defer db.Close()
	sqlSelect := `SELECT id, name, contact, key, enabled FROM issuer where id=$1`
	res, err := db.Query(sqlSelect, issuerID)
	if err != nil {
		return structs.Issuer{}, err
	}
	defer res.Close()

	var id string
	var name string
	var contact string
	var key string
	var enabled bool
	if res.Next() {
		res.Scan(&id, &name, &contact, &key, &enabled)
	}

	issuerStruct := structs.Issuer{ID: id, Name: name, Contact: contact, Key: key, Enabled: enabled}
	return issuerStruct, nil
}

//UpdateIssuer updates an existing issuer
func UpdateIssuer(issuer structs.Issuer) (bool, error) {
	db := CreateConnection()
	defer db.Close()

	sqlUpdate := `UPDATE issuer 
				  SET 
				  	contact=$1, 
				  	enabled=$2 
				  WHERE 
				  	id=$3`
	res, err := db.Exec(sqlUpdate, issuer.Contact, issuer.Enabled, issuer.ID)
	if err != nil {
		return false, err
	}

	rows, _ := res.RowsAffected()
	if rows != 1 {
		return false, errors.New("Update Operation was not successful")
	}
	return true, nil
}

//DeleteIssuer deletes an issuer from the database
func DeleteIssuer(issuer structs.Issuer) (bool, error) {
	db := CreateConnection()
	defer db.Close()

	sqlDelete := `DELETE FROM issuer WHERE id=$1`
	res, err := db.Exec(sqlDelete, issuer.ID)
	if err != nil {
		return false, err
	}

	err = DeleteTokens(issuer.ID)
	if err != nil {
		return false, err
	}

	err = DeleteUsers(issuer.ID)
	if err != nil {
		return false, err
	}

	rows, _ := res.RowsAffected()
	if rows != 1 {
		return false, fmt.Errorf("Operation affected %d rows", rows)
	}

	return true, nil
}

//GetUsers returns all users for a given issuer
func GetUsers(issuer structs.Issuer) ([]structs.User, error) {
	db := CreateConnection()
	defer db.Close()
	sqlCountSelect := `SELECT COUNT(username) FROM accounts WHERE issuer_id=$1;`
	res, err := db.Query(sqlCountSelect, issuer.ID)

	if err != nil {
		return nil, err
	}
	count, err := checkCount(res)
	if err != nil {
		return nil, err
	}
	defer res.Close()
	users := make([]structs.User, count)

	sqlSelect := `SELECT id, username, email, issuer_id, key, enabled FROM accounts WHERE issuer_id=$1`
	rows, errorMessage := db.Query(sqlSelect, issuer.ID)
	if errorMessage != nil {
		return nil, errorMessage
	}
	defer rows.Close()

	loop := 0
	for rows.Next() {
		var id string
		var username string
		var email string
		var issuerID string
		var key string
		var enabled bool
		rows.Scan(&id, &username, &email, &issuerID, &key, &enabled)

		userStruct := structs.User{ID: id, Name: username, Email: email, Key: key, Issuer: issuer, Enabled: enabled}
		users[loop] = userStruct
		loop++
	}

	return users, nil
}

//CreateUser inserts a userstruct to the DB
func CreateUser(user structs.User) (map[string]interface{}, error) {
	if user.ID == "" {
		user.ID = uuid.New().String()
	}

	var result map[string]interface{} = make(map[string]interface{})

	if user.Key == "" {
		issuerKey, err := GetIssuerKey(user.Issuer)
		if err != nil {
			result["error"] = err
			return result, err
		}
		cryptedKey, err := utils.GenerateCryptedKeyBase32(issuerKey)
		if err != nil {
			result["error"] = err
			return result, err
		}
		user.Key = cryptedKey
	}

	db := CreateConnection()
	defer db.Close()
	sqlInsert := `INSERT INTO accounts (id, username, email, issuer_id, key, enabled)
				VALUES ($1, $2, $3, $4, $5, $6)
				RETURNING id`
	res, err := db.Exec(sqlInsert, user.ID, user.Name, user.Email, user.Issuer.ID, user.Key, user.Enabled)
	if err != nil {
		result["error"] = err
		return result, err
	}

	rows, _ := res.RowsAffected()
	if rows != 1 {
		result["error"] = errors.New("Insert Operation was not successful")
		return result, err
	}

	token := structs.NewFullAccessToken(user.ID)
	err = InsertToken(token)
	if err != nil {
		result["error"] = err
		return result, err
	}

	result["user"] = user
	result["token"] = token

	return result, nil
}

//GetUser returns a User struct from the database
func GetUser(user string, issuer structs.Issuer) (structs.User, error) {
	db := CreateConnection()
	defer db.Close()
	sqlSelect := `SELECT id, username, email, key, enabled FROM accounts where username=$1 and issuer_id=$2`
	res, err := db.Query(sqlSelect, user, issuer.ID)
	if err != nil {
		return structs.User{}, err
	}
	defer res.Close()

	var id string
	var name string
	var email string
	var key string
	var enabled bool
	if res.Next() {
		res.Scan(&id, &name, &email, &key, &enabled)
	} else {
		return structs.User{}, errors.New("issuer not found in db")
	}

	userStruct := structs.User{ID: id, Name: name, Email: email, Key: key, Enabled: enabled, Issuer: issuer}
	return userStruct, nil
}

//UpdateUser updates an existing user
func UpdateUser(user structs.User) (bool, error) {
	db := CreateConnection()
	defer db.Close()

	sqlUpdate := `UPDATE accounts 
				  SET 
				  	email=$1, 
				  	enabled=$2 
				  WHERE 
				  	id=$3`
	res, err := db.Exec(sqlUpdate, user.Email, user.Enabled, user.ID)
	if err != nil {
		return false, err
	}

	rows, _ := res.RowsAffected()
	if rows != 1 {
		return false, errors.New("Update Operation was not successful")
	}
	return true, nil
}

//DeleteUser deletes a user from the database
func DeleteUser(user structs.User) (bool, error) {
	db := CreateConnection()
	defer db.Close()
	sqlDelete := `DELETE FROM accounts WHERE id=$1 and issuer_id=$2`
	res, err := db.Exec(sqlDelete, user.ID, user.Issuer.ID)
	if err != nil {
		return false, err
	}

	err = DeleteTokens(user.ID)
	if err != nil {
		return false, err
	}

	rows, _ := res.RowsAffected()
	if rows != 1 {
		return false, fmt.Errorf("Operation affected %d rows", rows)
	}

	return true, nil
}

//InsertToken inserts an access token to the database
func InsertToken(token structs.Token) error {
	db := CreateConnection()
	defer db.Close()

	hashedToken, _ := utils.BcryptHash([]byte(token.Token))
	sqlInsert := `INSERT INTO access_tokens(ref_id_action, ref_id_object, access_token)
				VALUES ($1, $2, $3)
				RETURNING id`
	res, err := db.Exec(sqlInsert, token.ActionRefID, token.ObjectRefID, string(hashedToken))
	if err != nil {
		return err
	}

	rows, _ := res.RowsAffected()
	if rows != 1 {
		return errors.New("Insert Operation was not successful")
	}

	return nil
}

//DeleteTokens deletes all tokens for a given object id
func DeleteTokens(objectid string) error {
	db := CreateConnection()
	defer db.Close()

	sqlDelete := `DELETE FROM access_tokens WHERE ref_id_object=$1`
	_, err := db.Exec(sqlDelete, objectid)
	return err
}

//DeleteUsers deletes all tokens for a given object id
func DeleteUsers(objectid string) error {
	db := CreateConnection()
	defer db.Close()

	sqlDelete := `DELETE FROM accounts WHERE issuer_id=$1`
	_, err := db.Exec(sqlDelete, objectid)
	return err
}
