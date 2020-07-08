package middleware

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"

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
	// return the connection
	return db
}

// CloseConnection closes the connection to the db
func CloseConnection(db *sql.DB) error {
	fmt.Println("closing connection!")
	return db.Close()
}

// Welcome will return a single Hello World
func Welcome(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Context-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// send the response
	json.NewEncoder(w).Encode("Hello, World")
}
