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
	fmt.Println("initializing")
	// Check if needed environment variables have been set
	err := checkEnvironmentVariables()
	if err != nil {
		log.Fatal(err)
	}

	// Initialize System
	err = middleware.InitializeSystem()
	if err != nil {
		log.Fatal(err)
	}

	// Create the router
	r := router.Router()
	config, err := middleware.GetSystemConfiguration()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Start serving on port", config.RouterPort)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", config.RouterPort), r))

}

//check whether all variables needed for a proper system startup are set
func checkEnvironmentVariables() error {
	dbuser := os.Getenv("POSTGRES_USER")
	dbpass := os.Getenv("POSTGRES_PASSWORD")
	dbhost := os.Getenv("POSTGRES_HOST")
	dbname := os.Getenv("POSTGRES_DB")

	if dbuser == "" || dbpass == "" || dbhost == "" || dbname == "" {
		return errors.New("environment variables not defined")
	}

	return nil
}
