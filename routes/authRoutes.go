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
	router.HandleFunc("/register", controllers.Register).Methods("POST")
	router.HandleFunc("/login", controllers.Login).Methods("POST")
	router.HandleFunc("/roles", middleware.ValidateJWT(controllers.GetRoles)).Methods("GET")
	router.HandleFunc("/permissions", middleware.ValidateJWT(controllers.GetPermissions)).Methods("GET")

	// Token validation route (requires valid JWT)
	router.HandleFunc("/validate", middleware.ValidateJWT(controllers.ValidateToken)).Methods("GET")

	// Route for fetching user info based on JWT
	router.HandleFunc("/userinfo", middleware.ValidateJWT(controllers.GetUserInfo)).Methods("GET")

	// Admin routes (require admin role)
	router.HandleFunc("/user/approve/{userID}", middleware.RequireAdmin(controllers.ApproveUser)).Methods("POST")
	router.HandleFunc("/user/decline/{userID}", middleware.RequireAdmin(controllers.DeclineUser)).Methods("POST")
	router.HandleFunc("/user/edit", middleware.RequireAdmin(controllers.EditUser)).Methods("PUT")
	router.HandleFunc("/user/role", middleware.RequireAdmin(controllers.EditUserRole)).Methods("PUT")
	router.HandleFunc("/user/permissions", middleware.RequireAdmin(controllers.EditUserPermissions)).Methods("PUT")
	// Route to assign wards to users (admin required)
	router.HandleFunc("/user/assign-wards", middleware.RequireAdmin(controllers.AssignWardsToUser)).Methods("POST")
	router.HandleFunc("/user/ward-permissions", middleware.RequireAdmin(controllers.EditUserWardPermissions)).Methods("PUT")

	// Admin route for deleting a user
	router.HandleFunc("/users/{id}", middleware.RequireAdmin(controllers.DeleteUser)).Methods("DELETE")

	// Fetch all users for a specific system and hospital (requires admin)
	router.HandleFunc("/users", middleware.RequireAdmin(controllers.GetUsersList)).Methods("GET")

	return router
}
