package controllers

import (
	"auth-service/models"
	"auth-service/services"
	"encoding/json"
	"log"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

// Handles user registration
func Register(w http.ResponseWriter, r *http.Request) {
	var user models.User
	_ = json.NewDecoder(r.Body).Decode(&user)

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)

	if err != nil {
		log.Println(err)
		http.Error(w, "Error creating user", http.StatusInternalServerError)
		return
	}
	user.Password = string(hashedPassword)

	// Create user in the database
	if err := services.CreateUser(&user); err != nil {
		log.Println(err)
		http.Error(w, "Failed to register user", http.StatusInternalServerError)
		return
	}

	// Respond with success message
	json.NewEncoder(w).Encode(map[string]string{"message": "User created"})
}

// Handles user login
func Login(w http.ResponseWriter, r *http.Request) {
	var credentials struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		System   string `json:"system"`
		Hospital string `json:"hospital"`
	}

	_ = json.NewDecoder(r.Body).Decode(&credentials)

	// Retrieve the user from the database
	user, err := services.GetUserByEmail(credentials.Email, credentials.Hospital)

	if err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Compare the password

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(credentials.Password))
	log.Println("Login Controller", err)
	if err != nil {
		http.Error(w, "Invalid password", http.StatusUnauthorized)
		return
	}

	// Get User Permissions
	var permissions []string
	permissions, err = services.GetUserPermissions(user.ID, user.System)
	if err != nil {
		http.Error(w, "Failed to get user permissions", http.StatusInternalServerError)
		return
	}

	// Generate JWT token
	token, err := services.GenerateJWT(user)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	var response models.LoginResponse
	response.ID = user.ID
	response.FirstName = user.FirstName
	response.LastName = user.LastName
	response.Email = user.Email
	response.System = user.System
	response.Role = user.Role
	response.Hospital = user.Hospital
	response.Status = user.Status
	response.JWT = token
	response.Permsions = permissions

	// Respond with the JWT token
	json.NewEncoder(w).Encode(map[string]models.LoginResponse{"User": response})
}

// Handles token validation
func ValidateToken(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	if token == "" {
		http.Error(w, "Token missing", http.StatusUnauthorized)
		return
	}

	// Validate the JWT token
	valid, err := services.ValidateJWT(token)
	if err != nil || !valid {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	// Respond with success message
	json.NewEncoder(w).Encode(map[string]string{"message": "Token is valid"})
}

// Handles user logout
func Logout(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	if token == "" {
		http.Error(w, "Token missing", http.StatusBadRequest)
		return
	}

	// Optionally, revoke the token
	err := services.RevokeToken(token)
	if err != nil {
		http.Error(w, "Failed to log out", http.StatusInternalServerError)
		return
	}

	// Respond with success message
	json.NewEncoder(w).Encode(map[string]string{"message": "Successfully logged out"})
}

// Handles retrieving user information
func GetUserInfo(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	if token == "" {
		http.Error(w, "Token missing", http.StatusUnauthorized)
		return
	}

	// Parse the JWT and get user info
	user, err := services.GetUserFromToken(token)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	// Respond with user info
	json.NewEncoder(w).Encode(user)
}

// ApproveUser is the controller function to approve a user
func ApproveUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID, err := strconv.Atoi(vars["userID"])
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	err = services.ApproveUser(uint(userID))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("User approved"))
}

// DeclineUser is the controller function to decline a user
func DeclineUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID, err := strconv.Atoi(vars["userID"])
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	err = services.DeclineUser(uint(userID))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("User declined"))
}

// GetUsersList retrieves users based on system and hospital from headers
func GetUsersList(w http.ResponseWriter, r *http.Request) {
	// Get system and hospital from headers
	system := r.Header.Get("X-System-Name")
	hospital := r.Header.Get("X-Hospital-Name")

	// Check if headers are present
	if system == "" || hospital == "" {
		http.Error(w, "Missing system or hospital in headers", http.StatusBadRequest)
		return
	}

	log.Println("GetUsersList Controller System", system, "Hospital", hospital)

	// Call the service function to retrieve users
	users, err := services.GetUsersList(system, hospital)

	log.Println("GetUsersList Controller Users", users, "Error", err)

	if err != nil {
		http.Error(w, "Failed to retrieve users", http.StatusInternalServerError)
		return
	}

	// Respond with the list of users
	json.NewEncoder(w).Encode(users)
}

// DeleteUser deletes a user by their ID
func DeleteUser(w http.ResponseWriter, r *http.Request) {
	// Get the user ID from the URL path
	vars := mux.Vars(r)
	userIDStr := vars["id"]

	// Convert the userID from string to integer
	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	// Call the service to delete the user
	err = services.DeleteUser(userID)
	if err != nil {
		http.Error(w, "Failed to delete user", http.StatusInternalServerError)
		return
	}

	// Respond with success message
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("User deleted successfully"))
}
