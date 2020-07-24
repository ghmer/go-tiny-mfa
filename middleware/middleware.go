package middleware

import (
	"database/sql"
	"fmt"
	"go-tiny-mfa/structs"

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
		username varchar(32) NOT NULL UNIQUE,
		email varchar(128) NOT NULL UNIQUE,
		issuer_id varchar(45) NOT NULL,
		key varchar(255) NOT NULL,
		enabled boolean DEFAULT '1',
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

//GetUser returns a User struct based on given username and issuer
func GetUser(username, issuer string, db *sql.DB) {

}
