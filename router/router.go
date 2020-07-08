package router

import (
	"go-tiny-mfa/middleware"

	"github.com/gorilla/mux"
)

// Router is exported and used in main.go
func Router() *mux.Router {
	router := mux.NewRouter()

	router.HandleFunc("/", middleware.Welcome).Methods("GET")

	return router
}
