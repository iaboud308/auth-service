package routes

import (
	"auth-service/controllers"
	"auth-service/middleware"

	"github.com/gorilla/mux"
)

// SetupRouter sets up all the routes for the authentication service
func SetupRouter() *mux.Router {
	router := mux.NewRouter()

	// Public routes (registration and login)
	router.HandleFunc("/auth/register", controllers.Register).Methods("POST")
	router.HandleFunc("/auth/login", controllers.Login).Methods("POST")

	// Token validation route (requires valid JWT)
	router.HandleFunc("/auth/validate", middleware.ValidateJWT(controllers.ValidateToken)).Methods("GET")

	// Route for fetching user info based on JWT
	router.HandleFunc("/auth/userinfo", middleware.ValidateJWT(controllers.GetUserInfo)).Methods("GET")

	// Admin routes (require admin role)
	router.HandleFunc("/auth/user/approve/{userID}", middleware.RequireAdmin(controllers.ApproveUser)).Methods("POST")
	router.HandleFunc("/auth/user/decline/{userID}", middleware.RequireAdmin(controllers.DeclineUser)).Methods("POST")
	router.HandleFunc("/auth/user/edit", middleware.RequireAdmin(controllers.EditUser)).Methods("PUT")
	router.HandleFunc("/auth/user/role", middleware.RequireAdmin(controllers.EditUserRole)).Methods("PUT")
	router.HandleFunc("/auth/user/permissions", middleware.RequireAdmin(controllers.EditUserPermissions)).Methods("PUT")
	router.HandleFunc("/auth/user/ward-permissions", middleware.RequireAdmin(controllers.EditUserWardPermissions)).Methods("PUT")

	// Admin route for deleting a user
	router.HandleFunc("/auth/users/{id}", middleware.RequireAdmin(controllers.DeleteUser)).Methods("DELETE")

	// Fetch all users for a specific system and hospital (requires admin)
	router.HandleFunc("/auth/users", middleware.RequireAdmin(controllers.GetUsersList)).Methods("GET")

	return router
}
