package middleware

import (
	"database/sql"
	"encoding/base32"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"

	"github.com/ghmer/go-tiny-mfa/structs"
	"github.com/ghmer/go-tiny-mfa/utils"

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
	//SchemaVersionKey is the key of the schema version entry in serverconfig table
	SchemaVersionKey = "schema_version"
	//SecretFilePath location of the root key
	SecretFilePath string = "/opt/go-tiny-mfa/secrets/key"
	//RootTokenFilePath location of the root-token export
	RootTokenFilePath string = "/opt/go-tiny-mfa/secrets/root-token.readanddelete"
)

// CreateConnection creates a connection to a postgres DB
func CreateConnection() (*sql.DB, error) {
	dbuser := os.Getenv("POSTGRES_USER")
	dbpass := os.Getenv("POSTGRES_PASSWORD")
	dbhost := os.Getenv("POSTGRES_HOST")
	dbname := os.Getenv("POSTGRES_DB")

	dbURL := fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=disable", dbuser, dbpass, dbhost, dbname)

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		return nil, err
	}
	// check the connection
	err = db.Ping()
	if err != nil {
		return nil, err
	}

	return db, nil
}

//PingDatabase tries to establish a connection
func PingDatabase() error {
	db, err := CreateConnection()
	if err != nil {
		return err
	}
	defer db.Close()

	return db.Ping()
}

//CreateAuditEntry creates an audit in the database
func CreateAuditEntry(user structs.User, validation structs.Validation) error {
	db, err := CreateConnection()
	if err != nil {
		return err
	}
	defer db.Close()

	insertString := `INSERT INTO audit(issuer, username, message, validated_on, success)
					 VALUES($1, $2, $3, $4, $5)`

	_, err = db.Exec(insertString, user.Issuer.Name, user.Name, validation.Message, time.Now(), validation.Success)
	if err != nil {
		return err
	}
	return nil
}

//GetFailedValidationCount returns the number of times a user failed validation for a given message
func GetFailedValidationCount(user structs.User, message int64) (int, error) {
	db, err := CreateConnection()
	if err != nil {
		return -1, err
	}
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
	db, err := CreateConnection()
	if err != nil {
		return -1, err
	}
	defer db.Close()

	parameters.BaseQuery = `SELECT COUNT(id) FROM audit`
	sqlCountSelect, paramID, params := createAuditQueryString(parameters)

	var res *sql.Rows
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

	db, err := CreateConnection()
	if err != nil {
		return nil, err
	}
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
		case '\n':
			flag = true
			escape = '\n'
		case '\\':
			flag = true
			escape = '\\'
		case '\'':
			flag = true
			escape = '\''
		case '"':
			flag = true
			escape = '"'
		case '\032':
			flag = true
			escape = 'Z'
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

func GetSchemaVersion() (uint8, error) {
	var value uint8
	db, err := CreateConnection()
	if err != nil {
		return value, err
	}
	defer db.Close()

	query := "SELECT schema_version from serverconfig"
	res, err := db.Query(query)
	if err != nil {
		return value, err
	}
	defer res.Close()

	if res.Next() {
		res.Scan(&value)
	}

	return value, nil
}

//GetSystemProperty returns the value for the given key
func GetSystemProperty(key string) (string, error) {
	var value string
	db, err := CreateConnection()
	if err != nil {
		return value, err
	}
	defer db.Close()

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
	db, err := CreateConnection()
	if err != nil {
		return structs.ServerConfig{}, err
	}
	defer db.Close()

	queryKey := "SELECT http_port,deny_limit,verify_tokens,root_token,schema_version FROM serverconfig"
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
		var schemaVersion uint8

		res.Scan(&httpPort, &denyLimit, &verifyTokens, &rootToken, &schemaVersion)
		config = structs.ServerConfig{
			RouterPort:    httpPort,
			DenyLimit:     denyLimit,
			VerifyTokens:  verifyTokens,
			RootToken:     rootToken,
			SchemaVersion: schemaVersion,
		}
	}

	return config, nil
}

//GetQrCodeConfiguration returns the configured qr colors
func GetQrCodeConfiguration() (structs.QrCodeConfig, error) {
	db, err := CreateConnection()
	if err != nil {
		return structs.QrCodeConfig{}, err
	}
	defer db.Close()

	queryKey := "SELECT qrcode_bgcolor,qrcode_fgcolor FROM qr_code_config"
	res, err := db.Query(queryKey)
	if err != nil {
		return structs.QrCodeConfig{}, err
	}
	defer res.Close()
	var qrcodeconfig structs.QrCodeConfig
	if res.Next() {
		var bgcolor string
		var fgcolor string

		res.Scan(&bgcolor, &fgcolor)
		qrcodeconfig.BgColor = structs.ColorSettingFromString(bgcolor)
		qrcodeconfig.FgColor = structs.ColorSettingFromString(fgcolor)
	}

	return qrcodeconfig, nil
}

//UpdateQrCodeConfiguration returns the configured qr colors
func UpdateQrCodeConfiguration(qrcodeconfig structs.QrCodeConfig) (structs.QrCodeConfig, error) {
	db, err := CreateConnection()
	if err != nil {
		return structs.QrCodeConfig{}, err
	}
	defer db.Close()

	sqlQuery := "UPDATE qr_code_config SET qrcode_bgcolor=$1,qrcode_fgcolor=$2"
	_, err = db.Exec(sqlQuery,
		qrcodeconfig.BgColor.ToString(),
		qrcodeconfig.FgColor.ToString())
	if err != nil {
		return structs.QrCodeConfig{}, err
	}

	return qrcodeconfig, nil
}

//UpdateSystemConfiguration updates the system configuration
func UpdateSystemConfiguration(config structs.ServerConfig) (structs.ServerConfig, error) {
	db, err := CreateConnection()
	if err != nil {
		return structs.ServerConfig{}, err
	}
	defer db.Close()

	sqlQuery := `UPDATE serverconfig 
					SET 
					http_port=$1, 
					deny_limit=$2,
					verify_tokens=$3,
					schema_version=$4`
	_, err = db.Exec(sqlQuery,
		config.RouterPort,
		config.DenyLimit,
		config.VerifyTokens,
		config.SchemaVersion)
	if err != nil {
		return structs.ServerConfig{}, err
	}

	return GetSystemConfiguration()
}

//GetTokenLength returns the length of the desired token
func GetTokenLength(issuer structs.Issuer) (uint8, error) {
	db, err := CreateConnection()
	if err != nil {
		return 99, err
	}
	defer db.Close()

	sqlSelect := `SELECT token_length from issuer where id=$1;`
	result, err := db.Query(sqlSelect, issuer.ID)
	if err != nil {
		return 99, err
	}

	var length uint8 = 6
	if result.Next() {
		result.Scan(&length)
	}

	return length, nil
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

func countIssuers() (int, error) {
	db, err := CreateConnection()
	if err != nil {
		return -1, err
	}
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
	db, err := CreateConnection()
	if err != nil {
		return -1, err
	}
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
	db, err := CreateConnection()
	if err != nil {
		return issuers, err
	}
	defer db.Close()

	sqlSelect := `SELECT id, name, contact, key, token_length, enabled FROM issuer`
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
		var tokenLength uint8
		var enabled bool
		rows.Scan(&id, &name, &contact, &key, &tokenLength, &enabled)

		issuerStruct := structs.Issuer{ID: id, Name: name, Contact: contact, Key: key, TokenLength: tokenLength, Enabled: enabled}
		issuers[loop] = issuerStruct
		loop++
	}

	return issuers, nil
}

//GetIssuerAccessTokens returns all access tokens for a given issuer from the database
func GetIssuerAccessTokens(issuer structs.Issuer) ([]structs.TokenEntry, error) {
	count, err := countIssuerAccessTokens(issuer)
	if err != nil {
		return nil, err
	}
	tokens := make([]structs.TokenEntry, count)
	db, err := CreateConnection()
	if err != nil {
		return tokens, err
	}
	defer db.Close()

	sqlSelect := `SELECT id, description, created_on, last_access_time FROM access_tokens where ref_id_issuer=$1`
	rows, errorMessage := db.Query(sqlSelect, issuer.ID)
	if errorMessage != nil {
		return tokens, errorMessage
	}
	defer rows.Close()

	loop := 0
	for rows.Next() {
		var token structs.TokenEntry
		rows.Scan(&token.Id, &token.Description, &token.CreatedOn, &token.LastAccessTime)
		tokens[loop] = token
		loop++
	}

	return tokens, nil
}

//CreateIssuer inserts a Issuer struct to the database
func CreateIssuer(issuer structs.Issuer) (map[string]interface{}, error) {
	var result map[string]interface{} = make(map[string]interface{})
	db, err := CreateConnection()
	if err != nil {
		return result, err
	}
	defer db.Close()

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

	sqlInsert := `INSERT INTO issuer (id, name, contact, key, token_length, enabled)
				VALUES ($1, $2, $3, $4, $5, $6)
				RETURNING id`
	res, err := db.Exec(sqlInsert, issuer.ID, issuer.Name, issuer.Contact, issuer.Key, issuer.TokenLength, issuer.Enabled)
	if err != nil {
		result["error"] = err
		return result, err
	}

	rows, _ := res.RowsAffected()
	if rows != 1 {
		result["error"] = errors.New("insert operation was not successful")
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
	db, err := CreateConnection()
	if err != nil {
		return structs.Issuer{}, err
	}
	defer db.Close()
	sqlSelect := `SELECT id, name, contact, key, token_length, enabled FROM issuer where name=$1`
	res, err := db.Query(sqlSelect, issuer)
	if err != nil {
		return structs.Issuer{}, err
	}
	defer res.Close()

	var id string
	var name string
	var contact string
	var key string
	var tokenLength uint8
	var enabled bool
	if res.Next() {
		res.Scan(&id, &name, &contact, &key, &tokenLength, &enabled)
	} else {
		return structs.Issuer{}, errors.New("issuer not found in db")
	}

	issuerStruct := structs.Issuer{ID: id, Name: name, Contact: contact, Key: key, TokenLength: tokenLength, Enabled: enabled}
	return issuerStruct, nil
}

//GetIssuerByID returns the requested issuer from the database as Issuer struct
func GetIssuerByID(issuerID string) (structs.Issuer, error) {
	db, err := CreateConnection()
	if err != nil {
		return structs.Issuer{}, err
	}
	defer db.Close()
	sqlSelect := `SELECT id, name, contact, key, token_length, enabled FROM issuer where id=$1`
	res, err := db.Query(sqlSelect, issuerID)
	if err != nil {
		return structs.Issuer{}, err
	}
	defer res.Close()

	var id string
	var name string
	var contact string
	var key string
	var tokenLength uint8
	var enabled bool
	if res.Next() {
		res.Scan(&id, &name, &contact, &key, &tokenLength, &enabled)
	}

	issuerStruct := structs.Issuer{ID: id, Name: name, Contact: contact, Key: key, TokenLength: tokenLength, Enabled: enabled}
	return issuerStruct, nil
}

//UpdateIssuer updates an existing issuer
func UpdateIssuer(issuer structs.Issuer) (bool, error) {
	db, err := CreateConnection()
	if err != nil {
		return false, err
	}
	defer db.Close()

	sqlUpdate := `UPDATE issuer 
				  SET 
					contact=$1,
					token_length=$2, 
				  	enabled=$3
				  WHERE 
				  	id=$4`
	res, err := db.Exec(sqlUpdate, issuer.Contact, issuer.TokenLength, issuer.Enabled, issuer.ID)
	if err != nil {
		return false, err
	}

	rows, _ := res.RowsAffected()
	if rows != 1 {
		return false, errors.New("update operation was not successful")
	}
	return true, nil
}

//DeleteIssuer deletes an issuer from the database
func DeleteIssuer(issuer structs.Issuer) (bool, error) {
	db, err := CreateConnection()
	if err != nil {
		return false, err
	}
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
		return false, fmt.Errorf("operation affected %d rows", rows)
	}

	return true, nil
}

//GetUsers returns all users for a given issuer
func GetUsers(issuer structs.Issuer) ([]structs.User, error) {
	db, err := CreateConnection()
	if err != nil {
		return make([]structs.User, 0), err
	}
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
func CreateUser(user structs.User) (structs.User, error) {
	if user.ID == "" {
		user.ID = uuid.New().String()
	}

	if user.Key == "" {
		issuerKey, err := GetIssuerKey(user.Issuer)
		if err != nil {
			return structs.User{}, err
		}
		cryptedKey, err := utils.GenerateCryptedKeyBase32(issuerKey)
		if err != nil {
			return structs.User{}, err
		}
		user.Key = cryptedKey
	}

	db, err := CreateConnection()
	if err != nil {
		return structs.User{}, err
	}
	defer db.Close()
	sqlInsert := `INSERT INTO accounts (id, username, email, issuer_id, key, enabled)
				VALUES ($1, $2, $3, $4, $5, $6)
				RETURNING id`
	res, err := db.Exec(sqlInsert, user.ID, user.Name, user.Email, user.Issuer.ID, user.Key, user.Enabled)
	if err != nil {
		return structs.User{}, err
	}

	rows, _ := res.RowsAffected()
	if rows != 1 {
		return structs.User{}, errors.New("insert operation was not successful")
	}

	return user, nil
}

//GetUser returns a User struct from the database
func GetUser(user string, issuer structs.Issuer) (structs.User, error) {
	db, err := CreateConnection()
	if err != nil {
		return structs.User{}, err
	}
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
	db, err := CreateConnection()
	if err != nil {
		return false, err
	}
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
		return false, errors.New("update operation was not successful")
	}
	return true, nil
}

//DeleteUser deletes a user from the database
func DeleteUser(user structs.User) (bool, error) {
	db, err := CreateConnection()
	if err != nil {
		return false, err
	}
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
		return false, fmt.Errorf("operation affected %d rows", rows)
	}

	return true, nil
}

//InsertToken inserts an access token to the database
func InsertToken(token structs.Token) error {
	db, err := CreateConnection()
	if err != nil {
		return err
	}
	defer db.Close()

	hashedToken, _ := utils.BcryptHash([]byte(token.Token))
	sqlInsert := `INSERT INTO access_tokens(id, ref_id_issuer, access_token, description, created_on)
				VALUES ($1, $2, $3, $4, $5)
				RETURNING id`
	res, err := db.Exec(sqlInsert, token.ID, token.ObjectRefID, string(hashedToken), token.Description, time.Now())
	if err != nil {
		return err
	}

	rows, _ := res.RowsAffected()
	if rows != 1 {
		return errors.New("insert operation was not successful")
	}

	return nil
}

//DeleteTokens deletes all tokens for a given issuer id
func DeleteTokens(issuerid string) error {
	db, err := CreateConnection()
	if err != nil {
		return err
	}
	defer db.Close()

	sqlDelete := `DELETE FROM access_tokens WHERE ref_id_issuer=$1`
	_, err = db.Exec(sqlDelete, issuerid)
	return err
}

//DeleteToken deletes all tokens for a given issuer id
func DeleteToken(issuerid, tokenid string) error {
	db, err := CreateConnection()
	if err != nil {
		return err
	}
	defer db.Close()

	sqlDelete := `DELETE FROM access_tokens WHERE ref_id_issuer=$1 and id=$2`
	_, err = db.Exec(sqlDelete, issuerid, tokenid)
	return err
}

//DeleteUsers deletes all tokens for a given object id
func DeleteUsers(objectid string) error {
	db, err := CreateConnection()
	if err != nil {
		return err
	}
	defer db.Close()

	sqlDelete := `DELETE FROM accounts WHERE issuer_id=$1`
	_, err = db.Exec(sqlDelete, objectid)
	return err
}

//ValidateToken returns true if a token could be looked up in the db
func ValidateToken(issuer structs.Issuer, submittedToken string) (bool, error) {
	db, err := CreateConnection()
	if err != nil {
		return false, err
	}
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
			err = updateTokenAccessTime(token)
			return true, err
		}
	}

	return false, errors.New("token not verified")
}

func updateTokenAccessTime(token string) error {
	db, err := CreateConnection()
	if err != nil {
		return err
	}
	defer db.Close()

	sqlCount := `UPDATE access_tokens SET last_access_time=$1 where access_token=$2`
	db.Exec(sqlCount, time.Now(), token)
	return nil
}
