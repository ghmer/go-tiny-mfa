package middleware

import (
	"database/sql"
	"errors"
	"fmt"
	"go-tiny-mfa/structs"
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
		key varchar(128) NOT NULL,
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
		key varchar(128) NOT NULL,
		enabled boolean DEFAULT '1',
		PRIMARY KEY (id)
	);`
	_, err := db.Exec(createstring)
	if err != nil {
		fmt.Println(err)
	}
}

//InitializeDatabase will create the issuer and user tables
func InitializeDatabase() {
	initializeIssuerTable()
	initializeUserTable()
}

//InsertUser inserts a userstruct to the DB
func InsertUser(user structs.User) {
	db := CreateConnection()
	defer db.Close()
	sqlInsert := `INSERT INTO accounts (id, username, email, issuer_id, key, enabled)
				VALUES ($1, $2, $3, $4, $5)
				RETURNING id`
	res, err := db.Exec(sqlInsert, user.ID, user.Name, user.Email, user.Issuer.ID, user.Key, true)
	if err != nil {
		panic(err)
	}

	rows, _ := res.RowsAffected()
	fmt.Println("insert operation result: ", rows)
}

//CreateIssuer returns a Issuer struct with the values provided
func CreateIssuer(issuer, contact string, enabled bool) structs.Issuer {
	id := uuid.New().String()
	issuerStruct := structs.Issuer{ID: id, Name: issuer, Contact: contact, Enabled: enabled}

	return issuerStruct
}

//InsertIssuer inserts a Issuer struct to the database
func InsertIssuer(issuer structs.Issuer) (structs.Issuer, error) {
	db := CreateConnection()
	defer db.Close()
	if issuer.ID == "" {
		fmt.Print("ID emtpy. using ")
		issuer.ID = uuid.New().String()
		fmt.Println(issuer.ID)
	}
	sqlInsert := `INSERT INTO issuer (id, name, contact, enabled)
				VALUES ($1, $2, $3, $4)
				RETURNING id`
	res, err := db.Exec(sqlInsert, issuer.ID, issuer.Name, issuer.Contact, issuer.Enabled)
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

//GetIssuer returns the requested issuer from the database as Issuer struct
func GetIssuer(issuer string) (structs.Issuer, error) {
	db := CreateConnection()
	defer db.Close()
	sqlSelect := `SELECT * FROM issuer where name=$1`
	res, err := db.Query(sqlSelect, issuer)
	if err != nil {
		return structs.Issuer{}, err
	}

	var id string
	var name string
	var contact string
	var enabled bool
	if res.Next() {
		res.Scan(&id, &name, &contact, &enabled)
	}

	issuerStruct := structs.Issuer{ID: id, Name: name, Contact: contact, Enabled: enabled}
	return issuerStruct, nil
}

//GetIssuer returns the requested issuer from the database as Issuer struct
func GetIssuerByID(issuerID string) (structs.Issuer, error) {
	db := CreateConnection()
	defer db.Close()
	sqlSelect := `SELECT * FROM issuer where id=$1`
	res, err := db.Query(sqlSelect, issuerID)
	if err != nil {
		return structs.Issuer{}, err
	}

	var id string
	var name string
	var contact string
	var enabled bool
	if res.Next() {
		res.Scan(&id, &name, &contact, &enabled)
	}

	issuerStruct := structs.Issuer{ID: id, Name: name, Contact: contact, Enabled: enabled}
	return issuerStruct, nil
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

//GetIssuers returns all Issuers from the database
func GetIssuers() ([]structs.Issuer, error) {
	db := CreateConnection()
	defer db.Close()
	sqlCountSelect := `SELECT COUNT(name) FROM issuer;`
	res, err := db.Query(sqlCountSelect)
	if err != nil {
		return []structs.Issuer{}, err
	}

	count, err := checkCount(res)
	if err != nil {
		return []structs.Issuer{}, err
	}
	fmt.Println("Current Count: ", count)
	issuers := make([]structs.Issuer, count)

	sqlSelect := `SELECT id, name, contact, enabled FROM issuer`
	rows, errorMessage := db.Query(sqlSelect)
	if errorMessage != nil {
		return issuers, errorMessage
	}

	loop := 0
	for rows.Next() {
		var id string
		var name string
		var contact string
		var enabled bool
		rows.Scan(&id, &name, &contact, &enabled)

		issuerStruct := structs.Issuer{ID: id, Name: name, Contact: contact, Enabled: enabled}
		issuers[loop] = issuerStruct
		loop++
	}

	rows.Close()

	return issuers, nil
}

//GetUser returns a User struct based on given username and issuer
func GetUser(username, issuer string) {

}
