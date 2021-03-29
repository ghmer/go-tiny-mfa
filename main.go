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

func init() {
	// check whether we shall act as a healthchecker
	if len(os.Args) == 2 && os.Args[1] == "--healthcheck" {
		// we are a healthcheck call, not initializing db
		DoHealthcheck = true
	}

	// initializing system
	if !DoHealthcheck {
		log.Println("initializing tinymfa")

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

		log.Println("initialization finished")
	}
}

func main() {
	// Either a healthcheck or a router
	if DoHealthcheck {
		returncode := Healthcheck()
		os.Exit(returncode)
	}

	// Create the router
	r := router.Router()
	config, err := middleware.GetSystemConfiguration()
	if err != nil {
		log.Fatal(err)
	}

	log.Println("tinymfa starts serving on port", config.RouterPort)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", config.RouterPort), r))
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

	routerport, err := middleware.GetSystemProperty(middleware.RouterPortKey)
	if err != nil {
		returncode = 1
		return returncode
	}

	// healthchechUrl is the url we are using to retrieve the status
	var healthcheckUrl string = fmt.Sprintf("http://127.0.0.1:%s/api/v1/health", routerport)

	result, err := client.Get(healthcheckUrl)
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
