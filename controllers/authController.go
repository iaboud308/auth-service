package controllers

import (
	"auth-service/models"
	"auth-service/services"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

// logAction centralizes the logging logic for HTTP responses and actions
func logAction(action string, logLevel string, message string, user models.User) {
	services.LogEntry(action, user.System, user.Hospital, logLevel, message, user.ID, map[string]interface{}{
		"Email":     user.Email,
		"FirstName": user.FirstName,
		"LastName":  user.LastName,
		"RoleID":    user.RoleID,
	})
}

// Handles user registration
func Register(w http.ResponseWriter, r *http.Request) {
	var user models.User

	// Decode the request body into the user struct
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid request data", http.StatusBadRequest)
		logAction("Register in auth controller", "error", "Failed to decode request body", user)
		return
	}

	// Validate required fields
	if user.FirstName == "" || user.LastName == "" || user.Email == "" || user.Password == "" || user.System == "" || user.Hospital == "" || user.RoleID == 0 {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		logAction("Register in auth controller", "error", "Missing required fields", user)
		return
	}

	// Validate role ID
	if err := services.ValidateRoleID(user.RoleID); err != nil {
		http.Error(w, "Invalid role ID", http.StatusBadRequest)
		logAction("Register in auth controller", "error", "Invalid role ID: "+err.Error(), user)
		return
	}

	// Check if the user already exists (email must be unique)
	existingUser, err := services.GetUserByEmail(user.Email, user.System, user.Hospital)
	if err != nil {
		http.Error(w, "Error checking user existence", http.StatusInternalServerError)
		logAction("Register in auth controller", "error", "Failed to check user existence: "+err.Error(), user)
		return
	}
	if existingUser != nil {
		http.Error(w, "User already exists", http.StatusConflict)
		logAction("Register in auth controller", "error", "User already exists", user)
		return
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		logAction("Register in auth controller", "error", "Failed to hash password: "+err.Error(), user)
		return
	}
	user.Password = string(hashedPassword)

	// Assign default permissions based on role
	if err := services.AssignDefaultPermissions(&user); err != nil {
		http.Error(w, "Failed to assign default permissions", http.StatusInternalServerError)
		logAction("Register in auth controller", "error", "Failed to assign default permissions: "+err.Error(), user)
		return
	}

	// Create user in the database
	if err := services.CreateUser(&user); err != nil {
		http.Error(w, "Error creating user", http.StatusInternalServerError)
		logAction("Register in auth controller", "error", "Failed to create user: "+err.Error(), user)
		return
	}

	// Log successful registration with the correct user ID
	logAction("Register in auth controller", "info", "User created successfully", user)

	// Respond with success message
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "User created successfully, pending approval"})
}

// Handles user login
func Login(w http.ResponseWriter, r *http.Request) {
	var credentials struct {
		Email    string `json:"email"`
		System   string `json:"system"`
		Hospital string `json:"hospital"`
		Password string `json:"password"`
	}

	// Decode request body
	if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil {
		http.Error(w, "Invalid request data", http.StatusBadRequest)
		logAction("Login in auth controller", "error", "Failed to decode login request data", models.User{
			Email:    credentials.Email,
			System:   credentials.System,
			Hospital: credentials.Hospital,
		})
		return
	}

	// Validate required fields
	if credentials.Email == "" || credentials.Password == "" || credentials.System == "" || credentials.Hospital == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		logAction("Login", "error", "Missing required fields for login", models.User{
			Email:    credentials.Email,
			System:   credentials.System,
			Hospital: credentials.Hospital,
		})
		return
	}

	// Retrieve the user from the database
	user, err := services.GetUserByEmail(credentials.Email, credentials.System, credentials.Hospital)
	if err != nil || user.Status != "approved" {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		logAction("Login", "error", "Invalid username or password", models.User{
			Email:    credentials.Email,
			System:   credentials.System,
			Hospital: credentials.Hospital})
		return
	}

	// Compare the password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(credentials.Password)); err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		logAction("Login", "error", "Invalid password attempt", *user)
		return
	}

	// Get User Permissions
	permissions, err := services.GetUserPermissions(user.ID, user.System)
	if err != nil {
		http.Error(w, "Failed to get user permissions", http.StatusInternalServerError)
		logAction("Login", "error", "Failed to retrieve user permissions: "+err.Error(), *user)
		return
	}

	// Get User Role
	role, err := services.GetUserRole(user.RoleID)
	if err != nil {
		http.Error(w, "Failed to get user role", http.StatusInternalServerError)
		logAction("Login", "error", "Failed to retrieve user role: "+err.Error(), *user)
		return
	}

	// Generate JWT token
	token, err := services.GenerateJWT(user)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		logAction("Login", "error", "Failed to generate JWT token: "+err.Error(), *user)
		return
	}

	// Prepare response
	response := models.AuthResponse{
		ID:          user.ID,
		FirstName:   user.FirstName,
		LastName:    user.LastName,
		Email:       user.Email,
		System:      user.System,
		Role:        role.RoleName,
		Hospital:    user.Hospital,
		Status:      user.Status,
		Permissions: permissions,
		JWT:         token,
	}

	// Log login event
	logAction("Login in auth controller", "info", "User logged in successfully", *user)

	// Respond with success message
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// Validates the JWT token
func ValidateToken(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	if token == "" {
		http.Error(w, "Authorization required", http.StatusUnauthorized)
		logAction("ValidateToken in auth controller", "error", "Token missing", models.User{})
		return
	}

	// Handle Bearer token format if necessary
	if len(token) > 7 && token[:7] == "Bearer " {
		token = token[7:] // Extract the actual token part
	}

	// Validate the JWT token
	valid, err := services.ValidateJWT(token)
	if err != nil || !valid {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		logAction("ValidateToken in auth controller", "error", "Invalid token: "+err.Error(), models.User{})
		return
	}

	// Log token validation success
	logAction("ValidateToken in auth controller", "info", "Token validated successfully", models.User{})

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Token is valid"})
}

// Retrieves user information based on JWT token
func GetUserInfo(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	if token == "" {
		http.Error(w, "Authorization required", http.StatusUnauthorized)
		logAction("GetUserInfo in auth controller", "error", "Token missing", models.User{})
		return
	}

	// Handle Bearer token format if necessary
	if len(token) > 7 && token[:7] == "Bearer " {
		token = token[7:] // Extract the actual token part
	}

	// Parse the JWT and get user info
	user, err := services.GetUserFromToken(token)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		logAction("GetUserInfo in auth controller", "error", "Invalid token: "+err.Error(), models.User{})
		return
	}

	// Log successful retrieval of user info
	logAction("GetUserInfo in auth controller", "info", "User info retrieved successfully", models.User{
		ID:        user.ID,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Email:     user.Email,
		System:    user.System,
		Hospital:  user.Hospital,
	})

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(user)
}

// Admin function to approve a user’s registration
func ApproveUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID, err := strconv.Atoi(vars["userID"])
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		logAction("ApproveUser in auth controller", "error", "Invalid user ID", models.User{
			ID: userID,
		})
		return
	}

	// Attempt to approve the user
	if err := services.ApproveUser(userID); err != nil {
		http.Error(w, "Error approving user", http.StatusInternalServerError)
		logAction("ApproveUser in auth controller", "error", "Failed to approve user: "+err.Error(), models.User{
			ID: userID,
		})
		return
	}

	// Log successful user approval
	logAction("ApproveUser in auth controller", "info", "User approved successfully", models.User{
		ID: userID,
	})

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "User approved successfully"})
}

// Admin function to decline a user’s registration
func DeclineUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID, err := strconv.Atoi(vars["userID"])
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		logAction("DeclineUser in auth controller", "error", "Invalid user ID format", models.User{
			ID: userID,
		})
		return
	}

	// Attempt to decline the user
	if err := services.DeclineUser(userID); err != nil {
		logAction("DeclineUser in auth controller", "error", "Failed to decline user: "+err.Error(), models.User{
			ID: userID,
		})
		return
	}

	// Log successful user decline
	logAction("DeclineUser in auth controller", "info", "User declined successfully", models.User{ID: userID})

	// Return JSON response
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "User declined successfully"})
}

// Admin function to edit user details
func EditUser(w http.ResponseWriter, r *http.Request) {
	var updatedUser models.User

	// Decode request data
	if err := json.NewDecoder(r.Body).Decode(&updatedUser); err != nil {
		http.Error(w, "Invalid request data", http.StatusBadRequest)
		logAction("EditUser in auth controller", "error", "Failed to decode request data", models.User{})
		return
	}

	// Update user details in the database
	if err := services.EditUser(&updatedUser); err != nil {
		http.Error(w, "Failed to update user", http.StatusInternalServerError)
		logAction("EditUser in auth controller", "error", "Failed to update user: "+err.Error(), updatedUser)
		return
	}

	// Log successful update
	logAction("EditUser in auth controller", "info", "User updated successfully", updatedUser)

	// Return JSON response
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "User updated successfully"})
}

// Admin function to edit a user’s role
func EditUserRole(w http.ResponseWriter, r *http.Request) {
	var data struct {
		UserID int `json:"user_id"`
		RoleID int `json:"role_id"`
	}

	// Decode request data
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, "Invalid request data", http.StatusBadRequest)
		logAction("EditUserRole in auth controller", "error", "Failed to decode request data", models.User{
			ID: data.UserID,
		})
		return
	}

	// Validate role ID
	if err := services.ValidateRoleID(data.RoleID); err != nil {
		http.Error(w, "Invalid role ID", http.StatusBadRequest)
		logAction("EditUserRole in auth controller", "error", "Invalid role ID: "+err.Error(), models.User{
			ID: data.UserID,
		})
		return
	}

	// Update user role in the database
	if err := services.EditUserRole(data.UserID, data.RoleID); err != nil {
		http.Error(w, "Failed to update user role", http.StatusInternalServerError)
		logAction("EditUserRole in auth controller", "error", "Failed to update user role: "+err.Error(), models.User{
			ID: data.UserID,
		})
		return
	}

	// Log successful role update
	logAction("EditUserRole in auth controller", "info", "User role updated successfully", models.User{
		ID: data.UserID,
	})

	// Return JSON response
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "User role updated successfully"})
}

// Admin function to edit user permissions
func EditUserPermissions(w http.ResponseWriter, r *http.Request) {
	var data struct {
		UserID      int      `json:"user_id"`
		Permissions []string `json:"permissions"`
	}

	// Decode request data
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, "Invalid request data", http.StatusBadRequest)
		logAction("EditUserPermissions in auth controller", "error", "Failed to decode request data", models.User{
			ID: data.UserID,
		})
		return
	}

	// Update user permissions in the database
	if err := services.EditUserPermissions(data.UserID, data.Permissions); err != nil {
		http.Error(w, "Failed to update user permissions", http.StatusInternalServerError)
		logAction("EditUserPermissions in auth controller", "error", "Failed to update user permissions: "+err.Error(), models.User{
			ID: data.UserID,
		})
		return
	}

	// Log successful permissions update
	logAction("EditUserPermissions in auth controller", "info", "User permissions updated successfully", models.User{
		ID: data.UserID,
	})

	// Return JSON response
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "User permissions updated successfully"})
}

// Admin function to edit user ward-specific permissions
func EditUserWardPermissions(w http.ResponseWriter, r *http.Request) {
	var data struct {
		UserID      int      `json:"user_id"`
		Permissions []string `json:"permissions"`
		Wards       []int    `json:"wards"`
	}

	// Decode request data
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, "Invalid request data", http.StatusBadRequest)
		logAction("EditUserWardPermissions in auth controller", "error", "Failed to decode request data", models.User{
			ID: data.UserID,
		})
		return
	}

	// Update user ward-specific permissions in the database
	if err := services.EditUserWardPermissions(data.UserID, data.Permissions, data.Wards); err != nil {
		http.Error(w, "Failed to update user ward permissions", http.StatusInternalServerError)
		logAction("EditUserWardPermissions in auth controller", "error", "Failed to update user ward permissions: "+err.Error(), models.User{
			ID: data.UserID,
		})
		return
	}

	// Log successful permissions update
	logAction("EditUserWardPermissions in auth controller", "info", "User ward permissions updated successfully", models.User{
		ID: data.UserID,
	})

	// Return JSON response
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "User ward permissions updated successfully"})
}

// Admin function to fetch a list of all users for a specific system and hospital
func GetUsersList(w http.ResponseWriter, r *http.Request) {
	system := r.Header.Get("X-System-Name")
	hospital := r.Header.Get("X-Hospital-Name")

	// Check if headers are present
	if system == "" || hospital == "" {
		http.Error(w, "Missing system or hospital in headers", http.StatusBadRequest)
		logAction("GetUsersList in auth controller", "error", "Missing system or hospital in headers", models.User{})
		return
	}

	// Retrieve users list from the service
	users, err := services.GetUsersList(system, hospital)
	if err != nil {
		http.Error(w, "Failed to retrieve users", http.StatusInternalServerError)
		logAction("GetUsersList in auth controller", "error", "Failed to retrieve users: "+err.Error(), models.User{})
		return
	}

	// Log successful user list retrieval
	logAction("GetUsersList in auth controller", "info", "User list retrieved successfully: "+strconv.Itoa(len(users))+" users found", models.User{})

	// Return JSON response
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(users)
}

// Admin function to delete a user by ID
func DeleteUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userIDStr := vars["id"]

	// Convert the userID from string to integer
	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		logAction("DeleteUser in auth controller", "error", "Invalid user ID format", models.User{
			ID: userID,
		})
		return
	}

	// Call the service to delete the user
	if err := services.DeleteUser(userID); err != nil {
		http.Error(w, "Failed to delete user", http.StatusInternalServerError)
		logAction("DeleteUser in auth controller", "error", "Failed to delete user: "+err.Error(), models.User{
			ID: userID,
		})
		return
	}

	// Log successful user deletion
	logAction("DeleteUser in auth controller", "info", "User deleted successfully", models.User{
		ID: userID,
	})

	// Return JSON response
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "User deleted successfully"})
}
