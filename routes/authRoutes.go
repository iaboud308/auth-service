package routes

import (
	"auth-service/controllers"

	"github.com/gorilla/mux"
)

func SetupRouter() *mux.Router {
	router := mux.NewRouter()

	// Health check
	router.HandleFunc("/", controllers.HealthCheck).Methods("GET")

	// Register and Login
	router.HandleFunc("/auth/register", controllers.Register).Methods("POST")
	router.HandleFunc("/auth/login", controllers.Login).Methods("POST")

	// Token validation
	router.HandleFunc("/auth/validate", controllers.ValidateToken).Methods("GET")

	// User logout
	router.HandleFunc("/auth/logout", controllers.Logout).Methods("POST")

	// Get user info
	router.HandleFunc("/auth/userinfo", controllers.GetUserInfo).Methods("GET")

	return router
}
