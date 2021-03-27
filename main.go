package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"go-tiny-mfa/middleware"
	"go-tiny-mfa/router"
	"go-tiny-mfa/structs"
	"log"
	"net/http"
	"os"
	"time"
)

// Healthcheck defines whether we run the router or a simple healthcheck
var DoHealthcheck bool = false

// HealthchechUrl is the url we are using to retrieve the status
var HealthcheckUrl string = "http://127.0.0.1:57687/api/v1/health"

func init() {
	if len(os.Args) == 2 && os.Args[1] == "--healthcheck" {
		// we are a healthcheck call, not initializing db
		DoHealthcheck = true
	} else {
		log.Println("initializing")
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
	}

	log.Println("initialization finished")
}

func main() {
	// Either a healthcheck or a router
	if DoHealthcheck {
		returncode := Healthcheck()
		os.Exit(returncode)
	} else {
		// Create the router
		r := router.Router()
		config, err := middleware.GetSystemConfiguration()
		if err != nil {
			log.Fatal(err)
		}

		log.Println("Start serving on port", config.RouterPort)
		log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", config.RouterPort), r))
	}
}

// check whether all variables needed for a proper system startup are set
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

// Healthcheck tries to connect to the health api endpoint
func Healthcheck() int {
	// initialize returncode with error value
	var returncode int = 1

	// check database connectivity
	err := middleware.PingDatabase()
	if err != nil {
		returncode = 1
		return returncode
	}

	// connection to db established, check api endpoint
	client := http.Client{
		Transport: nil,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return nil
		},
		Jar:     nil,
		Timeout: time.Duration(5 * time.Second),
	}

	result, err := client.Get(HealthcheckUrl)
	if err != nil {
		returncode = 1
		return returncode
	}

	var message structs.Message
	decoder := json.NewDecoder(result.Body)
	decoder.Decode(&message)

	// check health message
	if message.Success {
		// setting returncode to success
		returncode = 0
	}

	return returncode
}
