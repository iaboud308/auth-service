package controllers

import (
	"auth-service/models"
	"auth-service/services"
	"encoding/json"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

// Handles user registration
func Register(w http.ResponseWriter, r *http.Request) {
	var user models.User
	_ = json.NewDecoder(r.Body).Decode(&user)

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Error creating user", http.StatusInternalServerError)
		return
	}
	user.Password = string(hashedPassword)

	// Create user in the database
	if err := services.CreateUser(&user); err != nil {
		http.Error(w, "Failed to register user", http.StatusInternalServerError)
		return
	}

	// Respond with success message
	json.NewEncoder(w).Encode(map[string]string{"message": "User created"})
}

// Handles user login
func Login(w http.ResponseWriter, r *http.Request) {
	var credentials struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	_ = json.NewDecoder(r.Body).Decode(&credentials)

	// Retrieve the user from the database
	user, err := services.GetUserByUsername(credentials.Username)

	if err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Compare the password

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(credentials.Password))
	if err != nil {
		http.Error(w, "Invalid password", http.StatusUnauthorized)
		return
	}

	// Generate JWT token
	token, err := services.GenerateJWT(user)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	// Respond with the JWT token
	json.NewEncoder(w).Encode(map[string]string{"token": token})
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
