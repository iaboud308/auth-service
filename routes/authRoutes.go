package routes

import (
	"auth-service/controllers"
	"auth-service/middleware"

	"github.com/gorilla/mux"
)

func SetupRouter() *mux.Router {
	router := mux.NewRouter()

	// Health check
	router.HandleFunc("/", controllers.HealthCheck).Methods("GET")

	// Register and Login
	router.HandleFunc("/auth/register", controllers.Register).Methods("POST")
	router.HandleFunc("/auth/login", controllers.Login).Methods("POST")

	router.HandleFunc("/auth/users", controllers.GetUsersList).Methods("GET")
	router.HandleFunc("/auth/users/{id}", controllers.DeleteUser).Methods("DELETE")

	// Token validation
	router.HandleFunc("/auth/validate", controllers.ValidateToken).Methods("GET")

	// User logout
	router.HandleFunc("/auth/logout", controllers.Logout).Methods("POST")

	// Get user info
	router.HandleFunc("/auth/userinfo", controllers.GetUserInfo).Methods("GET")

	// Approve and Decline User (admin only)
	router.HandleFunc("/auth/user/approve/{userID}", middleware.RequireAdmin(controllers.ApproveUser)).Methods("POST")
	router.HandleFunc("/auth/user/decline/{userID}", middleware.RequireAdmin(controllers.DeclineUser)).Methods("POST")

	return router
}
