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
	initializeDatabase(db)
	// return the connection
	return db
}

// CloseConnection closes the connection to the db
func CloseConnection(db *sql.DB) error {
	fmt.Println("closing connection!")
	return db.Close()
}

func initializeDatabase(db *sql.DB) {
	createstring := `CREATE TABLE IF NOT EXISTS accounts (
						id varchar(45) NOT NULL,
						username varchar(32) NOT NULL,
						issuer varchar(48) NOT NULL,
						key varchar(64) NOT NULL,
						enabled boolean DEFAULT '1',
						PRIMARY KEY (id)
					);`
	_, err := db.Exec(createstring)
	if err != nil {
		fmt.Println(err)
	}
}

// Welcome will return a single Hello World
func Welcome(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Context-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// send the response
	json.NewEncoder(w).Encode("Hello, World")
}
