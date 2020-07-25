package middleware

import (
	"database/sql"
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

func initializeUserTable() {
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
		fmt.Println(err)
	}
}

func initializeIssuerTable() {
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
		fmt.Println(err)
	}
}

func initializeSystemTable() {
	db := CreateConnection()
	defer db.Close()
	createstring := `CREATE TABLE IF NOT EXISTS system (
		id serial,
		key varchar(128) NOT NULL UNIQUE,
		PRIMARY KEY (key)
	);`
	_, err := db.Exec(createstring)
	if err != nil {
		fmt.Println(err)
	}

	queryKey := "SELECT COUNT(key) FROM system"
	count, err := checkCountWithQuery(queryKey)
	if err != nil {
		fmt.Println(err)
	}

	if count != 1 {
		createMasterKey()
	}
}

func createMasterKey() {
	base32MasterKey, err := utils.GenerateExtendedKeyBase32()
	if err != nil {
		panic(err)
	}
	db := CreateConnection()
	defer db.Close()
	insertQuery := `INSERT INTO system(key) VALUES($1);`
	res, err := db.Exec(insertQuery, base32MasterKey)
	if err != nil {
		fmt.Println(err)
	}

	rows, _ := res.RowsAffected()
	fmt.Println("insert operation result: ", rows)
}

//GetMasterKey retrieves the key generated on system initialization
func GetMasterKey() ([]byte, error) {
	db := CreateConnection()
	defer db.Close()
	selectQuery := "SELECT key FROM system WHERE id=1"
	result, err := db.Query(selectQuery)
	defer result.Close()
	if err != nil {
		return nil, err
	}

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

//InitializeDatabase will create the issuer and user tables
func InitializeDatabase() {
	initializeSystemTable()
	initializeIssuerTable()
	initializeUserTable()
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
	defer res.Close()

	if err != nil {
		return -1, err
	}

	count, err := checkCount(res)
	if err != nil {
		return -1, err
	}

	return count, nil
}

/*
//CreateIssuer returns a Issuer struct with the values provided
func CreateIssuer(issuer, contact string, enabled bool) structs.Issuer {
	id := uuid.New().String()
	issuerStruct := structs.Issuer{ID: id, Name: issuer, Contact: contact, Enabled: enabled}

	return issuerStruct
}
*/

//GetIssuers returns all Issuers from the database
func GetIssuers() ([]structs.Issuer, error) {
	db := CreateConnection()
	defer db.Close()
	sqlCountSelect := `SELECT COUNT(name) FROM issuer;`
	res, err := db.Query(sqlCountSelect)
	defer res.Close()

	if err != nil {
		return []structs.Issuer{}, err
	}

	count, err := checkCount(res)
	if err != nil {
		return []structs.Issuer{}, err
	}
	fmt.Println("Current Count: ", count)
	issuers := make([]structs.Issuer, count)

	sqlSelect := `SELECT id, name, contact, key, enabled FROM issuer`
	rows, errorMessage := db.Query(sqlSelect)
	defer rows.Close()
	if errorMessage != nil {
		return issuers, errorMessage
	}

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
	if issuer.ID == "" {
		fmt.Print("ID emtpy. using ")
		issuer.ID = uuid.New().String()
		fmt.Println(issuer.ID)
	}
	if issuer.Key == "" {
		fmt.Print("key emtpy. using ")
		masterKey, err := GetMasterKey()
		if err != nil {
			return structs.Issuer{}, err
		}
		cryptedKey, err := utils.GenerateCryptedKeyBase32(masterKey)
		if err != nil {
			return structs.Issuer{}, err
		}
		issuer.Key = cryptedKey
		fmt.Println(issuer.Key)
	}

	sqlInsert := `INSERT INTO issuer (id, name, contact, key, enabled)
				VALUES ($1, $2, $3, $4)
				RETURNING id`
	res, err := db.Exec(sqlInsert, issuer.ID, issuer.Name, issuer.Contact, issuer.Key, issuer.Enabled)
	if err != nil {
		fmt.Println("Error ", err)
		return structs.Issuer{}, err
	}

	rows, _ := res.RowsAffected()
	if rows != 1 {
		return issuer, errors.New("Insert Operation was not successful")
	}
	fmt.Println("insert operation result: ", rows)
	return issuer, nil
}

//GetIssuer returns the requested issuer from the database as Issuer struct
func GetIssuer(issuer string) (structs.Issuer, error) {
	db := CreateConnection()
	defer db.Close()
	sqlSelect := `SELECT id, name, contact, key, enabled FROM issuer where name=$1`
	res, err := db.Query(sqlSelect, issuer)
	defer res.Close()

	if err != nil {
		return structs.Issuer{}, err
	}

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
	defer res.Close()

	if err != nil {
		return structs.Issuer{}, err
	}

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

	currentIssuer, err := GetIssuerByID(issuer.ID)
	if err != nil {
		return false, err
	}

	if issuer.Contact == "" {
		issuer.Contact = currentIssuer.Contact
	}

	sqlUpdate := `UPDATE issuer 
				  SET 
				  	contact=$1, 
				  	enabled=$2 
				  WHERE 
				  	id=$3`
	res, err := db.Exec(sqlUpdate, issuer.Contact, issuer.Enabled, issuer.ID)
	if err != nil {
		fmt.Println("Error ", err)
		return false, err
	}

	rows, _ := res.RowsAffected()
	if rows != 1 {
		return false, errors.New("Update Operation was not successful")
	}
	fmt.Println("insert operation result: ", rows)
	return true, nil
}

//DeleteIssuer deletes an issuer from the database
func DeleteIssuer(issuer string) (bool, error) {
	db := CreateConnection()
	defer db.Close()
	sqlDelete := `DELETE FROM issuer WHERE name=$1`
	res, err := db.Exec(sqlDelete, issuer)
	if err != nil {
		return false, err
	}

	rows, _ := res.RowsAffected()
	fmt.Println("insert operation result: ", rows)
	if rows != 1 {
		return false, fmt.Errorf("Operation affected %d rows", rows)
	}

	return true, nil
}

//GetUsers returns all users for a given issuer
func GetUsers(issuer structs.Issuer) ([]structs.User, error) {
	db := CreateConnection()
	defer db.Close()
	sqlCountSelect := `SELECT COUNT(name) FROM users WHERE issuer_id=$1;`
	res, err := db.Query(sqlCountSelect, issuer.ID)
	defer res.Close()
	if err != nil {
		return []structs.User{}, err
	}

	count, err := checkCount(res)
	if err != nil {
		return []structs.User{}, err
	}
	fmt.Println("Current Count: ", count)
	users := make([]structs.User, count)

	sqlSelect := `SELECT id, username, email, issuer_id, key, enabled FROM users WHERE issuer_id=$1`
	rows, errorMessage := db.Query(sqlSelect, issuer)
	defer rows.Close()
	if errorMessage != nil {
		return []structs.User{}, errorMessage
	}

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
		fmt.Print("ID emtpy. using ")
		user.ID = uuid.New().String()
		fmt.Println(user.ID)
	}

	if user.Key == "" {
		fmt.Print("Key empty. using ")
		issuerKey, err := GetIssuerKey(user.Issuer)
		if err != nil {
			return user, err
		}
		cryptedKey, err := utils.GenerateCryptedKeyBase32(issuerKey)
		if err != nil {
			return user, err
		}
		user.Key = cryptedKey
		fmt.Println(user.Key)
	}

	db := CreateConnection()
	defer db.Close()
	sqlInsert := `INSERT INTO accounts (id, username, email, issuer_id, key, enabled)
				VALUES ($1, $2, $3, $4, $5)
				RETURNING id`
	res, err := db.Exec(sqlInsert, user.ID, user.Name, user.Email, user.Issuer.ID, user.Key, user.Enabled)
	if err != nil {
		fmt.Println("Error ", err)
		return structs.User{}, err
	}

	rows, _ := res.RowsAffected()
	if rows != 1 {
		return structs.User{}, errors.New("Insert Operation was not successful")
	}
	fmt.Println("insert operation result: ", rows)
	return user, nil
}

//GetUser returns a User struct from the database
func GetUser(user string, issuer structs.Issuer) (structs.User, error) {
	db := CreateConnection()
	defer db.Close()
	sqlSelect := `SELECT id, username, email, key, enabled FROM user where name=$1 and issuer_id=$2`
	res, err := db.Query(sqlSelect, user, issuer.ID)
	defer res.Close()

	if err != nil {
		return structs.User{}, err
	}

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

	sqlUpdate := `UPDATE user 
				  SET 
				  	email=$1, 
				  	enabled=$2 
				  WHERE 
				  	id=$3`
	res, err := db.Exec(sqlUpdate, user.Email, user.Enabled, user.ID)
	if err != nil {
		fmt.Println("Error ", err)
		return false, err
	}

	rows, _ := res.RowsAffected()
	if rows != 1 {
		return false, errors.New("Update Operation was not successful")
	}
	fmt.Println("insert operation result: ", rows)
	return true, nil
}

//DeleteUser deletes a user from the database
func DeleteUser(user structs.User) (bool, error) {
	db := CreateConnection()
	defer db.Close()
	sqlDelete := `DELETE FROM users WHERE id=$1 and issuer_id=$2`
	res, err := db.Exec(sqlDelete, user.ID, user.Issuer.ID)
	if err != nil {
		return false, err
	}

	rows, _ := res.RowsAffected()
	fmt.Println("insert operation result: ", rows)
	if rows != 1 {
		return false, fmt.Errorf("Operation affected %d rows", rows)
	}

	return true, nil
}
