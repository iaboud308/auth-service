package main

import (
	"auth-service/routes"
	"log"
	"net/http"

	"github.com/gorilla/handlers"
)

func main() {
	// Initialize the database
	// services.InitDB()

	// Setup the router
	router := routes.SetupRouter()

	// CORS settings
	headersOk := handlers.AllowedHeaders([]string{"X-Requested-With", "X-System-Id", "X-Tenant-Id", "Content-Type", "Authorization"})
	originsOk := handlers.AllowedOrigins([]string{"http://localhost:3000", "https://app.alithron.com"})
	methodsOk := handlers.AllowedMethods([]string{"GET", "POST", "PUT", "DELETE", "OPTIONS"})

	// Start the server
	log.Println("Server starting on port 5002")
	log.Fatal(http.ListenAndServe(":5002", handlers.CORS(headersOk, originsOk, methodsOk)(router)))
}
