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
	//RootTokenKey is the key of the root token entry in serverconfig table
	RootTokenKey = "root_token"
	//VerifyTokenKey is the key of the verify token entry in serverconfig table
	VerifyTokenKey = "verify_tokens"
)

//SecretFilePath location of the root key
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

//InitializeSystem will initialize the database and the root key
func InitializeSystem() error {
	err := initializeDatabase()
	if err != nil {
		return err
	}

	err = initializeRootKey()
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
		id varchar(45) NOT NULL,
		ref_id_issuer varchar(45),
		access_token varchar(64) NOT NULL,
		description varchar(255),
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

func printSystemConfiguration(config structs.ServerConfig) {
	log.Println()
	log.Println("----------------------------------------------------------------")
	log.Println("tiny-mfa configuration")
	log.Println("----------------------------------------------------------------")
	log.Println("router port  ", config.RouterPort)
	log.Println("deny limit   ", config.DenyLimit)
	log.Println("verify tokens", config.VerifyTokens)
	log.Println("root token   ", config.RootToken)
	log.Println("----------------------------------------------------------------")
	log.Println()
}

func escape(source string) string {
	var j int = 0
	if len(source) == 0 {
		return ""
	}
	tempStr := source[:]
	desc := make([]byte, len(tempStr)*2)
	for i := 0; i < len(tempStr); i++ {
		flag := false
		var escape byte
		switch tempStr[i] {
		case '\r':
			flag = true
			escape = '\r'
			break
		case '\n':
			flag = true
			escape = '\n'
			break
		case '\\':
			flag = true
			escape = '\\'
			break
		case '\'':
			flag = true
			escape = '\''
			break
		case '"':
			flag = true
			escape = '"'
			break
		case '\032':
			flag = true
			escape = 'Z'
			break
		default:
		}
		if flag {
			desc[j] = '\\'
			desc[j+1] = escape
			j = j + 2
		} else {
			desc[j] = tempStr[i]
			j = j + 1
		}
	}
	return string(desc[0:j])
}

//GetSystemProperty returns the value for the given key
func GetSystemProperty(key string) (string, error) {
	db := CreateConnection()
	defer db.Close()

	var value string
	queryKey := fmt.Sprintf("SELECT %s FROM serverconfig;", escape(key))
	res, err := db.Query(queryKey)
	if err != nil {
		return value, err
	}
	defer res.Close()

	if res.Next() {
		res.Scan(&value)
	}

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

//checks whether the root key exists on the file system
//will create it if this is not the case
func initializeRootKey() error {
	_, err := os.Stat(SecretFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			// key does not exist
			log.Println("Warning: No root key found. A new one is being generated")
			base32RootKey, err := utils.GenerateExtendedKeyBase32()
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
			_, err = file.WriteString(base32RootKey)
			if err != nil {
				return err
			}

			defer os.Chmod(SecretFilePath, 0400)

			return nil
		}
	}

	return err
}

//GetRootKey retrieves the key generated on system initialization
func GetRootKey() ([]byte, error) {
	encodedRootKey, err := ioutil.ReadFile(SecretFilePath)
	if err != nil {
		log.Panicf("failed reading data from file: %s", err)
	}

	rootKey, err := utils.DecodeBase32Key(string(encodedRootKey))
	return rootKey, err
}

//GetIssuerKey returns the decrypted issuer key as byte array
func GetIssuerKey(issuer structs.Issuer) ([]byte, error) {
	cryptedKey, err := utils.DecodeBase32Key(issuer.Key)
	if err != nil {
		return nil, err
	}

	rootKey, err := GetRootKey()
	if err != nil {
		return nil, err
	}
	defer utils.ScrubKey(&rootKey)

	plainKey := utils.Decrypt(cryptedKey, rootKey)
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

func countIssuerAccessTokens(issuer structs.Issuer) (int, error) {
	db := CreateConnection()
	defer db.Close()
	sqlCountSelect := `SELECT COUNT(id) FROM access_tokens where ref_id_issuer=$1;`
	res, err := db.Query(sqlCountSelect, issuer.ID)
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

//GetIssuerAccessTokens returns all access tokens for a given issuer from the database
func GetIssuerAccessTokens(issuer structs.Issuer) ([]structs.Token, error) {
	count, err := countIssuerAccessTokens(issuer)
	if err != nil {
		return nil, err
	}
	tokens := make([]structs.Token, count)
	db := CreateConnection()
	defer db.Close()

	sqlSelect := `SELECT id, description FROM access_tokens`
	rows, errorMessage := db.Query(sqlSelect)
	if errorMessage != nil {
		return tokens, errorMessage
	}
	defer rows.Close()

	loop := 0
	for rows.Next() {
		var id string
		var description string
		rows.Scan(&id, &description)

		token := structs.Token{ID: id, Description: description}
		tokens[loop] = token
		loop++
	}

	return tokens, nil
}

//CreateIssuer inserts a Issuer struct to the database
func CreateIssuer(issuer structs.Issuer) (map[string]interface{}, error) {
	db := CreateConnection()
	defer db.Close()

	var result map[string]interface{} = make(map[string]interface{})

	issuer.ID = uuid.New().String()
	rootKey, err := GetRootKey()

	if err != nil {
		result["error"] = err
		return result, err
	}
	cryptedKey, err := utils.GenerateCryptedKeyBase32(rootKey)
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

	token := structs.NewAccessToken(issuer.ID)
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

	token := structs.NewAccessToken(user.ID)
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
	sqlInsert := `INSERT INTO access_tokens(id, ref_id_issuer, access_token, description)
				VALUES ($1, $2, $3)
				RETURNING id`
	res, err := db.Exec(sqlInsert, token.ID, token.ObjectRefID, string(hashedToken), token.Description)
	if err != nil {
		return err
	}

	rows, _ := res.RowsAffected()
	if rows != 1 {
		return errors.New("Insert Operation was not successful")
	}

	return nil
}

//DeleteTokens deletes all tokens for a given issuer id
func DeleteTokens(issuerid string) error {
	db := CreateConnection()
	defer db.Close()

	sqlDelete := `DELETE FROM access_tokens WHERE ref_id_issuer=$1`
	_, err := db.Exec(sqlDelete, issuerid)
	return err
}

//DeleteToken deletes all tokens for a given issuer id
func DeleteToken(issuerid, tokenid string) error {
	db := CreateConnection()
	defer db.Close()

	sqlDelete := `DELETE FROM access_tokens WHERE ref_id_issuer=$1 and id=$2`
	_, err := db.Exec(sqlDelete, issuerid, tokenid)
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

//ValidateToken returns true if a token could be looked up in the db
func ValidateToken(issuer structs.Issuer, submittedToken string) (bool, error) {
	db := CreateConnection()
	defer db.Close()

	sqlCount := `SELECT COUNT(access_token) FROM access_tokens where ref_id_issuer=$1`
	countresult, err := db.Query(sqlCount, issuer.ID)
	if err != nil {
		return false, err
	}
	defer countresult.Close()

	count, err := checkCount(countresult)
	if err != nil {
		return false, err
	}

	if count < 1 {
		return false, errors.New("there are no tokens defined for the given issuer")
	}

	sqlSelect := `SELECT access_token FROM access_tokens where ref_id_issuer=$1`
	tokenresult, err := db.Query(sqlSelect, issuer.ID)
	if err != nil {
		return false, err
	}
	defer tokenresult.Close()

	var tokens []string = make([]string, count)
	var index int = 0
	for tokenresult.Next() {
		var token string
		tokenresult.Scan(&token)
		tokens[index] = token
		index++
	}

	for _, token := range tokens {
		err = utils.BycrptVerify([]byte(token), []byte(submittedToken))
		if err == nil {
			return true, nil
		}
	}

	return false, errors.New("token not verified")
}
