package main

import (
	"fmt"
	"go-tiny-mfa/middleware"
	"go-tiny-mfa/router"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

func cleanup() {
	fmt.Println("Cleanup called")
}
func main() {
	var connURL string = os.Args[1]
	var port string = os.Args[2]

	db := middleware.CreateConnection(connURL)
	defer middleware.CloseConnection(db)

	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		cleanup()
		middleware.CloseConnection(db)
		os.Exit(1)
	}()

	r := router.Router()
	// fs := http.FileServer(http.Dir("build"))
	// http.Handle("/", fs)
	fmt.Println(fmt.Sprintf("Start serving on port %s", port))
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", port), r))
}
