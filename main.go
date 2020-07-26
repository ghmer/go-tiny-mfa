package main

import (
	"errors"
	"fmt"
	"go-tiny-mfa/middleware"
	"go-tiny-mfa/router"
	"log"
	"net/http"
	"os"
)

func main() {
	// Check if needed environment variables have been set
	log.Fatal(checkEnvironmentVariables())

	// Initialize Database
	log.Fatal(middleware.InitializeDatabase())

	// Create the router
	r := router.Router()
	fmt.Println("Start serving on port 57687")
	log.Fatal(http.ListenAndServe(":57687", r))

}

func checkEnvironmentVariables() error {
	dbuser := os.Getenv("POSTGRES_USER")
	dbpass := os.Getenv("POSTGRES_PASSWORD")
	dbname := os.Getenv("POSTGRES_DATABASE")

	if dbuser == "" || dbpass == "" || dbname == "" {
		return errors.New("environment variables not defined")
	}

	return nil
}
