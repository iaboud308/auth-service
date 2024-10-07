package controllers

import (
	"auth-service/models"
	"auth-service/services"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

// Handles user registration
func Register(w http.ResponseWriter, r *http.Request) {
	var user models.User

	// Decode the request body into the user struct
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid request data", http.StatusBadRequest)
		services.LogEntry("Register in auth controller", "error", "Failed to decode request body", user, nil)
		return
	}

	// Validate required fields
	if user.FirstName == "" || user.LastName == "" || user.Email == "" || user.Password == "" || user.System == "" || user.Hospital == "" || user.RoleID == 0 {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		services.LogEntry("Register in auth controller", "error", "Missing required fields", user, nil)
		return
	}

	// Validate role ID
	if err := services.ValidateRoleID(user.RoleID); err != nil {
		http.Error(w, "Invalid role ID", http.StatusBadRequest)
		services.LogEntry("Register in auth controller", "error", "Invalid role ID: "+err.Error(), user, nil)
		return
	}

	// Check if the user already exists (email must be unique)
	existingUser, err := services.GetUserByEmail(user.Email, user.System, user.Hospital)
	if err != nil {
		http.Error(w, "Error checking user existence", http.StatusInternalServerError)
		services.LogEntry("Register in auth controller", "error", "Failed to check user existence: "+err.Error(), user, nil)
		return
	}
	if existingUser != nil {
		http.Error(w, "User already exists", http.StatusConflict)
		services.LogEntry("Register in auth controller", "error", "User already exists", user, nil)
		return
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		services.LogEntry("Register in auth controller", "error", "Failed to hash password: "+err.Error(), user, nil)
		return
	}
	user.Password = string(hashedPassword)

	// Assign default permissions based on role
	if err := services.AssignDefaultPermissions(&user); err != nil {
		http.Error(w, "Failed to assign default permissions", http.StatusInternalServerError)
		services.LogEntry("Register in auth controller", "error", "Failed to assign default permissions: "+err.Error(), user, nil)
		return
	}

	// Create user in the database
	if err := services.CreateUser(&user); err != nil {
		http.Error(w, "Error creating user", http.StatusInternalServerError)
		services.LogEntry("Register in auth controller", "error", "Failed to create user: "+err.Error(), user, nil)
		return
	}

	// Log successful registration with the correct user ID
	services.LogEntry("Register in auth controller", "info", "User created successfully", user, nil)

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
		services.LogEntry("Login in auth controller", "error", "Failed to decode login request data", models.User{
			Email:    credentials.Email,
			System:   credentials.System,
			Hospital: credentials.Hospital,
		}, nil)
		return
	}

	// Validate required fields
	if credentials.Email == "" || credentials.Password == "" || credentials.System == "" || credentials.Hospital == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		services.LogEntry("Login", "error", "Missing required fields for login", models.User{
			Email:    credentials.Email,
			System:   credentials.System,
			Hospital: credentials.Hospital,
		}, nil)
		return
	}

	// Retrieve the user from the database
	user, err := services.GetUserByEmail(credentials.Email, credentials.System, credentials.Hospital)
	if err != nil || user.Status != "approved" {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		services.LogEntry("Login", "error", "Invalid username or password", models.User{
			Email:    credentials.Email,
			System:   credentials.System,
			Hospital: credentials.Hospital}, nil)
		return
	}

	// Compare the password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(credentials.Password)); err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		services.LogEntry("Login", "error", "Invalid password attempt", *user, nil)
		return
	}

	// Get User Permissions
	permissions, err := services.GetUserPermissions(user.ID, user.System)
	if err != nil {
		http.Error(w, "Failed to get user permissions", http.StatusInternalServerError)
		services.LogEntry("Login", "error", "Failed to retrieve user permissions: "+err.Error(), *user, nil)
		return
	}

	// Get User Role
	role, err := services.GetUserRole(user.RoleID)
	if err != nil {
		http.Error(w, "Failed to get user role", http.StatusInternalServerError)
		services.LogEntry("Login", "error", "Failed to retrieve user role: "+err.Error(), *user, map[string]interface{}{
			"Permissions": permissions,
		})
		return
	}

	// Generate JWT token
	token, err := services.GenerateJWT(user)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		services.LogEntry("Login", "error", "Failed to generate JWT token: "+err.Error(), *user, map[string]interface{}{
			"Permissions": permissions,
			"Role":        role.RoleName,
		})
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
	services.LogEntry("Login in auth controller", "info", "User logged in successfully", *user, map[string]interface{}{
		"Permissions": permissions,
		"Role":        role.RoleName,
		"JWT":         token,
	})

	// Respond with success message
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// Validates the JWT token
func ValidateToken(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	if token == "" {
		http.Error(w, "Authorization required", http.StatusUnauthorized)
		services.LogEntry("ValidateToken in auth controller", "error", "Token missing", models.User{}, nil)
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
		services.LogEntry("ValidateToken in auth controller", "error", "Invalid token: "+err.Error(), models.User{}, nil)
		return
	}

	// Log token validation success
	services.LogEntry("ValidateToken in auth controller", "info", "Token validated successfully", models.User{}, nil)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Token is valid"})
}

// Retrieves user information based on JWT token
func GetUserInfo(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	if token == "" {
		http.Error(w, "Authorization required", http.StatusUnauthorized)
		services.LogEntry("GetUserInfo in auth controller", "error", "Token missing", models.User{}, nil)
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
		services.LogEntry("GetUserInfo in auth controller", "error", "Invalid token: "+err.Error(), models.User{}, map[string]interface{}{
			"Token": token,
		})
		return
	}

	// Log successful retrieval of user info
	services.LogEntry("GetUserInfo in auth controller", "info", "User info retrieved successfully", models.User{
		ID:        user.ID,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Email:     user.Email,
		System:    user.System,
		Hospital:  user.Hospital,
	}, map[string]interface{}{
		"Role":        user.Role,
		"Permissions": user.Permissions,
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
		services.LogEntry("ApproveUser in auth controller", "error", "Invalid user ID", models.User{
			ID: userID,
		}, nil)
		return
	}

	// Attempt to approve the user
	if err := services.ApproveUser(userID); err != nil {
		http.Error(w, "Error approving user", http.StatusInternalServerError)
		services.LogEntry("ApproveUser in auth controller", "error", "Failed to approve user: "+err.Error(), models.User{
			ID: userID,
		}, nil)
		return
	}

	// Log successful user approval
	services.LogEntry("ApproveUser in auth controller", "info", "User approved successfully", models.User{
		ID: userID,
	}, nil)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "User approved successfully"})
}

// Admin function to decline a user’s registration
func DeclineUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID, err := strconv.Atoi(vars["userID"])
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		services.LogEntry("DeclineUser in auth controller", "error", "Invalid user ID format", models.User{
			ID: userID,
		}, nil)
		return
	}

	// Attempt to decline the user
	if err := services.DeclineUser(userID); err != nil {
		services.LogEntry("DeclineUser in auth controller", "error", "Failed to decline user: "+err.Error(), models.User{
			ID: userID,
		}, nil)
		return
	}

	// Log successful user decline
	services.LogEntry("DeclineUser in auth controller", "info", "User declined successfully", models.User{
		ID: userID,
	}, nil)

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
		services.LogEntry("EditUser in auth controller", "error", "Failed to decode request data", models.User{}, nil)
		return
	}

	// Update user details in the database
	if err := services.EditUser(&updatedUser); err != nil {
		http.Error(w, "Failed to update user", http.StatusInternalServerError)
		services.LogEntry("EditUser in auth controller", "error", "Failed to update user: "+err.Error(), updatedUser, nil)
		return
	}

	// Log successful update
	services.LogEntry("EditUser in auth controller", "info", "User updated successfully", updatedUser, nil)

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
		services.LogEntry("EditUserRole in auth controller", "error", "Failed to decode request data", models.User{
			ID: data.UserID,
		}, nil)
		return
	}

	// Validate role ID
	if err := services.ValidateRoleID(data.RoleID); err != nil {
		http.Error(w, "Invalid role ID", http.StatusBadRequest)
		services.LogEntry("EditUserRole in auth controller", "error", "Invalid role ID: "+err.Error(), models.User{
			ID: data.UserID,
		}, nil)
		return
	}

	// Update user role in the database
	if err := services.EditUserRole(data.UserID, data.RoleID); err != nil {
		http.Error(w, "Failed to update user role", http.StatusInternalServerError)
		services.LogEntry("EditUserRole in auth controller", "error", "Failed to update user role: "+err.Error(), models.User{
			ID: data.UserID,
		}, nil)
		return
	}

	// Log successful role update
	services.LogEntry("EditUserRole in auth controller", "info", "User role updated successfully", models.User{
		ID: data.UserID,
	}, nil)

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
		services.LogEntry("EditUserPermissions in auth controller", "error", "Failed to decode request data", models.User{
			ID: data.UserID,
		}, nil)
		return
	}

	// Update user permissions in the database
	if err := services.EditUserPermissions(data.UserID, data.Permissions); err != nil {
		http.Error(w, "Failed to update user permissions", http.StatusInternalServerError)
		services.LogEntry("EditUserPermissions in auth controller", "error", "Failed to update user permissions: "+err.Error(), models.User{
			ID: data.UserID,
		}, nil)
		return
	}

	// Log successful permissions update
	services.LogEntry("EditUserPermissions in auth controller", "info", "User permissions updated successfully", models.User{
		ID: data.UserID,
	}, nil)

	// Return JSON response
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "User permissions updated successfully"})
}

// AssignWardsToUser assigns wards to a user based on the incoming request
func AssignWardsToUser(w http.ResponseWriter, r *http.Request) {
	// Parse the request body (assumed to be JSON with user_id, ward_ids)
	var request struct {
		UserID   int    `json:"user_id"`
		WardIDs  []int  `json:"ward_ids"`
		System   string `json:"system"`
		Hospital string `json:"hospital"`
	}
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Call the service layer to assign the wards
	err = services.AssignWardsToUser(request.UserID, request.WardIDs, request.System, request.Hospital)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to assign wards: %s", err.Error()), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Wards assigned successfully"})
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
		services.LogEntry("EditUserWardPermissions in auth controller", "error", "Failed to decode request data", models.User{
			ID: data.UserID,
		}, nil)
		return
	}

	// Update user ward-specific permissions in the database
	if err := services.EditUserWardPermissions(data.UserID, data.Permissions, data.Wards); err != nil {
		http.Error(w, "Failed to update user ward permissions", http.StatusInternalServerError)
		services.LogEntry("EditUserWardPermissions in auth controller", "error", "Failed to update user ward permissions: "+err.Error(), models.User{
			ID: data.UserID,
		}, nil)
		return
	}

	// Log successful permissions update
	services.LogEntry("EditUserWardPermissions in auth controller", "info", "User ward permissions updated successfully", models.User{
		ID: data.UserID,
	}, nil)

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
		services.LogEntry("GetUsersList in auth controller", "error", "Missing system or hospital in headers", models.User{}, map[string]interface{}{
			"System":   system,
			"Hospital": hospital,
		})
		return
	}

	// Retrieve users list from the service
	users, err := services.GetUsersList(system, hospital)
	if err != nil {
		http.Error(w, "Failed to retrieve users", http.StatusInternalServerError)
		services.LogEntry("GetUsersList in auth controller", "error", "Failed to retrieve users: "+err.Error(), models.User{}, map[string]interface{}{
			"System":   system,
			"Hospital": hospital,
		})
		return
	}

	// Log successful user list retrieval
	services.LogEntry("GetUsersList in auth controller", "info", "User list retrieved successfully: "+strconv.Itoa(len(users))+" users found", models.User{}, nil)

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
		services.LogEntry("DeleteUser in auth controller", "error", "Invalid user ID format", models.User{
			ID: userID,
		}, nil)
		return
	}

	// Call the service to delete the user
	if err := services.DeleteUser(userID); err != nil {
		http.Error(w, "Failed to delete user", http.StatusInternalServerError)
		services.LogEntry("DeleteUser in auth controller", "error", "Failed to delete user: "+err.Error(), models.User{
			ID: userID,
		}, nil)
		return
	}

	// Log successful user deletion
	services.LogEntry("DeleteUser in auth controller", "info", "User deleted successfully", models.User{
		ID: userID,
	}, nil)

	// Return JSON response
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "User deleted successfully"})
}

// GetRoles retrieves all roles for a specific system and hospital
func GetRoles(w http.ResponseWriter, r *http.Request) {
	system := r.Header.Get("X-System-Name")
	hospital := r.Header.Get("X-Hospital-Name")

	// Validate required headers
	if system == "" || hospital == "" {
		services.LogEntry("GetRoles in rolesController", "error", "Missing system or hospital in headers", models.User{}, nil)
		http.Error(w, "Missing system or hospital in headers", http.StatusBadRequest)
		return
	}

	roles, err := services.GetRolesBySystemAndHospital(system, hospital)
	if err != nil {
		services.LogEntry("GetRoles in rolesController", "error", fmt.Sprintf("Failed to retrieve roles for system %s and hospital %s: %s", system, hospital, err.Error()), models.User{}, nil)
		http.Error(w, "Failed to retrieve roles", http.StatusInternalServerError)
		return
	}

	services.LogEntry("GetRoles in rolesController", "info", fmt.Sprintf("Roles retrieved successfully for system %s and hospital %s", system, hospital), models.User{}, map[string]interface{}{
		"Roles": roles,
	})

	// Return roles as JSON
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(roles)
}

// GetPermissions retrieves all permissions for a specific system and hospital
func GetPermissions(w http.ResponseWriter, r *http.Request) {
	system := r.Header.Get("X-System-Name")
	hospital := r.Header.Get("X-Hospital-Name")

	// Validate required headers
	if system == "" || hospital == "" {
		services.LogEntry("GetPermissions in permissionsController", "error", "Missing system or hospital in headers", models.User{}, nil)
		http.Error(w, "Missing system or hospital in headers", http.StatusBadRequest)
		return
	}

	permissions, err := services.GetPermissionsBySystemAndHospital(system, hospital)
	if err != nil {
		services.LogEntry("GetPermissions in permissionsController", "error", fmt.Sprintf("Failed to retrieve permissions for system %s and hospital %s: %s", system, hospital, err.Error()), models.User{}, nil)
		http.Error(w, "Failed to retrieve permissions", http.StatusInternalServerError)
		return
	}

	services.LogEntry("GetPermissions in permissionsController", "info", fmt.Sprintf("Permissions retrieved successfully for system %s and hospital %s", system, hospital), models.User{}, map[string]interface{}{
		"Permissions": permissions,
	})

	// Return permissions as JSON
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(permissions)
}
