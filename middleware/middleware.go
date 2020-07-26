package middleware

import (
	"database/sql"
	"encoding/base32"
	"errors"
	"fmt"
	"go-tiny-mfa/structs"
	"go-tiny-mfa/utils"
	"os"

	"github.com/google/uuid"

	// SQL Driver package
	_ "github.com/lib/pq"
)

// CreateConnection creates a connection to a postgres DB
func CreateConnection() *sql.DB {
	dbuser := os.Getenv("POSTGRES_USER")
	dbpass := os.Getenv("POSTGRES_PASSWORD")
	dbname := os.Getenv("POSTGRES_DATABASE")

	dbURL := fmt.Sprintf("postgres://%s:%s@localhost/%s?sslmode=disable", dbuser, dbpass, dbname)

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

//InitializeDatabase will create the issuer and user tables
func InitializeDatabase() error {
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

	return nil
}

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

func initializeSystemTable() error {
	db := CreateConnection()
	defer db.Close()
	createstring := `CREATE TABLE IF NOT EXISTS system (
		id serial,
		key varchar(128) NOT NULL UNIQUE,
		PRIMARY KEY (key)
	);`
	_, err := db.Exec(createstring)
	if err != nil {
		return err
	}

	queryKey := "SELECT COUNT(key) FROM system"
	count, err := checkCountWithQuery(queryKey)
	if err != nil {
		return err
	}

	if count != 1 {
		createMasterKey()
	}

	return nil
}

func createMasterKey() error {
	base32MasterKey, err := utils.GenerateExtendedKeyBase32()
	if err != nil {
		return err
	}
	db := CreateConnection()
	defer db.Close()
	insertQuery := `INSERT INTO system(key) VALUES($1);`
	_, err = db.Exec(insertQuery, base32MasterKey)
	if err != nil {
		return err
	}

	return nil
}

//GetMasterKey retrieves the key generated on system initialization
func GetMasterKey() ([]byte, error) {
	db := CreateConnection()
	defer db.Close()
	selectQuery := "SELECT key FROM system WHERE id=1"
	result, err := db.Query(selectQuery)
	if err != nil {
		return nil, err
	}
	defer result.Close()

	var encodedMasterKey string
	if result.Next() {
		result.Scan(&encodedMasterKey)
	}

	masterKey, err := utils.DecodeBase32Key(encodedMasterKey)
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

//GetIssuers returns all Issuers from the database
func GetIssuers() ([]structs.Issuer, error) {
	db := CreateConnection()
	defer db.Close()
	sqlCountSelect := `SELECT COUNT(name) FROM issuer;`
	res, err := db.Query(sqlCountSelect)
	if err != nil {
		return nil, err
	}
	defer res.Close()

	count, err := checkCount(res)
	if err != nil {
		return nil, err
	}
	issuers := make([]structs.Issuer, count)

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
func CreateIssuer(issuer structs.Issuer) (structs.Issuer, error) {
	db := CreateConnection()
	defer db.Close()
	issuer.ID = uuid.New().String()

	masterKey, err := GetMasterKey()
	if err != nil {
		return structs.Issuer{}, err
	}
	cryptedKey, err := utils.GenerateCryptedKeyBase32(masterKey)
	if err != nil {
		return structs.Issuer{}, err
	}
	issuer.Key = cryptedKey

	sqlInsert := `INSERT INTO issuer (id, name, contact, key, enabled)
				VALUES ($1, $2, $3, $4, $5)
				RETURNING id`
	res, err := db.Exec(sqlInsert, issuer.ID, issuer.Name, issuer.Contact, issuer.Key, issuer.Enabled)
	if err != nil {
		return structs.Issuer{}, err
	}

	rows, _ := res.RowsAffected()
	if rows != 1 {
		return issuer, errors.New("Insert Operation was not successful")
	}
	return issuer, nil
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
func CreateUser(user structs.User) (structs.User, error) {
	if user.ID == "" {
		user.ID = uuid.New().String()
	}

	if user.Key == "" {
		issuerKey, err := GetIssuerKey(user.Issuer)
		if err != nil {
			return user, err
		}
		cryptedKey, err := utils.GenerateCryptedKeyBase32(issuerKey)
		if err != nil {
			return user, err
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
		return structs.User{}, err
	}

	rows, _ := res.RowsAffected()
	if rows != 1 {
		return structs.User{}, errors.New("Insert Operation was not successful")
	}
	return user, nil
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

	rows, _ := res.RowsAffected()
	if rows != 1 {
		return false, fmt.Errorf("Operation affected %d rows", rows)
	}

	return true, nil
}
