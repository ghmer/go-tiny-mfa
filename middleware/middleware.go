package middleware

import (
	"database/sql"
	"fmt"
	"go-tiny-mfa/structs"

	"github.com/google/uuid"

	// SQL Driver package
	_ "github.com/lib/pq"
)

// CreateConnection creates a connection to a postgres DB
func CreateConnection(connectionURL string) *sql.DB {
	db, err := sql.Open("postgres", connectionURL)
	if err != nil {
		panic(err)
	}
	// check the connection
	err = db.Ping()
	if err != nil {
		panic(err)
	}

	fmt.Println("Successfully connected!")
	initializeDatabase(db)
	// return the connection
	return db
}

// CloseConnection closes the connection to the db
func CloseConnection(db *sql.DB) error {
	fmt.Println("closing connection!")
	return db.Close()
}

func initializeUserTable(db *sql.DB) {
	createstring := `CREATE TABLE IF NOT EXISTS accounts (
		id varchar(45) NOT NULL,
		username varchar(32) NOT NULL,
		email varchar(128) NOT NULL,
		issuer_id varchar(45) NOT NULL,
		key varchar(255) NOT NULL,
		enabled boolean DEFAULT '1',
		unique (username, email, issuer_id),
		PRIMARY KEY (id)
	);`
	_, err := db.Exec(createstring)
	if err != nil {
		fmt.Println(err)
	}
}

func initializeIssuerTable(db *sql.DB) {
	createstring := `CREATE TABLE IF NOT EXISTS issuer (
		id varchar(45) NOT NULL,
		name varchar(32) NOT NULL UNIQUE,
		contact varchar(255) NOT NULL
		enabled boolean DEFAULT '1',
		PRIMARY KEY (id)
	);`
	_, err := db.Exec(createstring)
	if err != nil {
		fmt.Println(err)
	}
}

func initializeDatabase(db *sql.DB) {
	initializeIssuerTable(db)
	initializeUserTable(db)
}

//InsertUser inserts a userstruct to the DB
func InsertUser(user structs.User, db *sql.DB) {
	sqlInsert := `INSERT INTO accounts (id, username, email, issuer_id, key, enabled)
				VALUES ($1, $2, $3, $4, $5)
				RETURNING id`
	res, err := db.Exec(sqlInsert, user.ID, user.Username, user.Email, user.Issuer.ID, user.CryptedBase32Key, true)
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
func InsertIssuer(issuer structs.Issuer, db *sql.DB) {
	sqlInsert := `INSERT INTO issuer (id, name, contact, enabled)
				VALUES ($1, $2, $3, $4)
				RETURNING id`
	res, err := db.Exec(sqlInsert, issuer.ID, issuer.Name, issuer.Contact, issuer.Enabled)
	if err != nil {
		panic(err)
	}

	rows, _ := res.RowsAffected()
	fmt.Println("insert operation result: ", rows)
}

//DeleteIssuer deletes an issuer from the database
func DeleteIssuer(issuer string, db *sql.DB) {
	sqlDelete := `DELETE FROM issuer WHERE name=$1`
	res, err := db.Exec(sqlDelete, issuer)
	if err != nil {
		panic(err)
	}

	rows, _ := res.RowsAffected()
	fmt.Println("insert operation result: ", rows)
}

//GetIssuer returns the requested issuer from the database as Issuer struct
func GetIssuer(issuer string, db *sql.DB) (structs.Issuer, error) {
	sqlSelect := `SELECT * FROM issuer where name=$1`
	res, err := db.Query(sqlSelect, issuer)
	if err != nil {
		return structs.Issuer{}, err
	}

	var id string
	var name string
	var contact string
	var enabled bool
	res.Scan(&id, &name, &contact, &enabled)

	issuerStruct := structs.Issuer{ID: id, Name: name, Contact: contact, Enabled: enabled}
	return issuerStruct, nil
}

//GetUser returns a User struct based on given username and issuer
func GetUser(username, issuer string, db *sql.DB) {

}
