package main

import (
	"auth-service/routes"
	"auth-service/services"
	"log"
	"net/http"

	"github.com/gorilla/handlers"
)

func main() {
	// Initialize the database connection using lib/pq
	services.InitDB()

	// Setup routes
	router := routes.SetupRouter()

	// Allow CORS for localhost:3000 during development
	headersOk := handlers.AllowedHeaders([]string{"X-Requested-With", "Content-Type", "Authorization"})
	originsOk := handlers.AllowedOrigins([]string{"http://localhost:3000", "https://localhost:3000"}) // Frontend URL in development
	methodsOk := handlers.AllowedMethods([]string{"GET", "POST", "PUT", "DELETE", "OPTIONS"})

	// Start the server
	log.Println("Starting server on :5002")
	log.Fatal(http.ListenAndServe(":5002", handlers.CORS(headersOk, originsOk, methodsOk)(router))) // Apply CORS settings to the router))
}

// connStr := "postgres://authuser:authpassword@db-auth-service:5432/authdb?sslmode=disable"
