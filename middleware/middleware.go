package middleware

import (
	"database/sql"
	"fmt"

	// SQL Driver package
	_ "github.com/lib/pq"
)

// CreateConnection creates a connection to a postgres DB
func CreateConnection() *sql.DB {
	db, err := sql.Open("postgres", "postgres://postgres:SidN1bP.@localhost/tinymfadb?sslmode=disable")
	if err != nil {
		panic(err)
	}
	// check the connection
	err = db.Ping()
	if err != nil {
		panic(err)
	}

	fmt.Println("Successfully connected!")
	// return the connection
	return db
}

// CloseConnection closes the connection to the db
func CloseConnection(db *sql.DB) error {
	fmt.Println("closing connection!")
	return db.Close()
}
