package main

import (
	"auth-service/routes"
	"auth-service/services"
	"log"
	"net/http"
)

func main() {
	// Initialize the database connection using lib/pq
	services.InitDB()

	// Setup routes
	router := routes.SetupRouter()

	// Start the server
	log.Println("Starting server on :8081")
	log.Fatal(http.ListenAndServe(":8081", router))
}

// connStr := "postgres://authuser:authpassword@db-auth-service:5432/authdb?sslmode=disable"
