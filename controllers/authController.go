package controllers

import (
	"auth-service/config"
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

	services.LogEntry("Register in auth controller", "info", "User registration initiated", user, map[string]interface{}{
		"system": config.SystemsList[user.SystemId].SystemCode,
		"tenant": config.TenantsList[user.TenantId].TenantCode,
	})

	// Validate required fields
	if user.FirstName == "" || user.LastName == "" || user.Email == "" || user.Password == "" || user.RoleID == 0 || user.SystemId == 0 || user.TenantId == 0 {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		services.LogEntry("Register in auth controller", "error", "Missing required fields", user, nil)
		return
	}

	// Validate role ID
	if err := services.ValidateRoleID(user.RoleID, user.SystemId, user.TenantId); err != nil {
		http.Error(w, "Invalid role ID", http.StatusBadRequest)
		services.LogEntry("Register in auth controller", "error", "Invalid role ID: "+err.Error(), user, nil)
		return
	}

	// Check if the user already exists (email must be unique)
	existingUser, err := services.GetUserByEmail(user.Email, user.SystemId, user.TenantId)
	if err != nil {
		http.Error(w, "Error checking user existence", http.StatusInternalServerError)
		services.LogEntry("Register in auth controller", "error", "Failed to check user existence: "+err.Error(), user, nil)
		return
	}
	if existingUser != nil {
		http.Error(w, "User already exists", http.StatusConflict)
		services.LogEntry("Register in auth controller", "error", "User already exists", user, map[string]interface{}{
			"ExistingUser": existingUser,
		})
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

	// Create user in the database
	if err := services.CreateUser(&user); err != nil {
		http.Error(w, "Error creating user", http.StatusInternalServerError)
		services.LogEntry("Register in auth controller", "error", "Failed to create user: "+err.Error(), user, nil)
		return
	}

	// Assign default permissions based on role
	if err := services.AssignDefaultPermissions(&user); err != nil {
		http.Error(w, "Failed to assign default permissions", http.StatusInternalServerError)
		services.LogEntry("Register in auth controller", "error", "Failed to assign default permissions: "+err.Error(), user, nil)
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
		SystemId int    `json:"system_id"`
		TenantId int    `json:"tenant_id"`
		Password string `json:"password"`
	}

	// Decode request body
	if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil {
		http.Error(w, "Invalid request data", http.StatusBadRequest)
		services.LogEntry("Login in auth controller", "error", "Failed to decode login request data", models.User{
			Email:    credentials.Email,
			SystemId: credentials.SystemId,
			TenantId: credentials.TenantId,
		}, nil)
		return
	}

	// Validate required fields
	if credentials.Email == "" || credentials.Password == "" || credentials.SystemId == 0 || credentials.TenantId == 0 {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		services.LogEntry("Login", "error", "Missing required fields for login", models.User{
			Email:    credentials.Email,
			SystemId: credentials.SystemId,
			TenantId: credentials.TenantId,
		}, nil)
		return
	}

	// Retrieve the user from the database
	user, err := services.GetUserByEmail(credentials.Email, credentials.SystemId, credentials.TenantId)
	if err != nil || user.Status != "approved" {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		services.LogEntry("Login", "error", "Invalid username or password", models.User{
			Email:    credentials.Email,
			SystemId: credentials.SystemId,
			TenantId: credentials.TenantId}, nil)
		return
	}

	// Compare the password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(credentials.Password)); err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		services.LogEntry("Login", "error", "Invalid password attempt", *user, nil)
		return
	}

	// Get User Role
	role, err := services.GetUserRole(user.RoleID, user.SystemId, user.TenantId)
	if err != nil {
		http.Error(w, "Failed to get user role", http.StatusInternalServerError)
		services.LogEntry("Login", "error", "Failed to retrieve user role: "+err.Error(), *user, nil)
		return
	}

	userWards, err := services.GetUserWards(user.ID, user.SystemId, user.TenantId)
	if err != nil {
		http.Error(w, "Failed to get user wards", http.StatusInternalServerError)
		services.LogEntry("Login", "error", "Failed to retrieve user wards: "+err.Error(), *user, map[string]interface{}{
			"Role": role.RoleName,
		})
		return
	}

	// Get User Permissions
	permissions, err := services.GetUserPermissions(user.ID, user.SystemId, user.TenantId)
	if err != nil {
		http.Error(w, "Failed to get user permissions", http.StatusInternalServerError)
		services.LogEntry("Login", "error", "Failed to retrieve user permissions: "+err.Error(), *user, map[string]interface{}{
			"Role":  role.RoleName,
			"Wards": userWards,
		})
		return
	}

	wardPermissions, err := services.GetUserWardPermissions(user.ID, user.SystemId, user.TenantId)
	if err != nil {
		http.Error(w, "Failed to get user ward permissions", http.StatusInternalServerError)
		services.LogEntry("Login", "error", "Failed to retrieve user ward permissions: "+err.Error(), *user, map[string]interface{}{
			"Role":  role.RoleName,
			"Wards": userWards,
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
		ID:                  user.ID,
		FirstName:           user.FirstName,
		LastName:            user.LastName,
		Email:               user.Email,
		System:              config.SystemsList[user.SystemId].SystemCode,
		Role:                role.RoleName,
		Tenant:              config.TenantsList[user.TenantId].TenantCode,
		Status:              user.Status,
		Permissions:         permissions,
		JWT:                 token,
		UserWards:           userWards,
		UserWardPermissions: wardPermissions,
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
	}, map[string]interface{}{
		"Role":        user.Role,
		"Permissions": user.Permissions,
		"System":      user.System,
		"Tenant":      user.Tenant,
	})

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(user)
}

// ActivateUser sets a user's status to 'active'
func ActivateUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userIDStr := vars["userID"]
	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		services.LogEntry("ActivateUser in auth controller", "error", "Invalid user ID: "+err.Error(), models.User{}, nil)
		return
	}

	// Get systemId and tenantId from headers
	systemIdStr := r.Header.Get("X-System-Id")
	tenantIdStr := r.Header.Get("X-Tenant-Id")

	if systemIdStr == "" || tenantIdStr == "" {
		http.Error(w, "Missing system or tenant in headers", http.StatusBadRequest)
		services.LogEntry("ActivateUser in auth controller", "error", "Missing system or tenant in headers", models.User{
			ID: userID,
		}, nil)
		return
	}

	systemId, err := strconv.Atoi(systemIdStr)
	if err != nil {
		http.Error(w, "Invalid system ID", http.StatusBadRequest)
		services.LogEntry("ActivateUser in auth controller", "error", "Invalid system ID: "+err.Error(), models.User{
			ID: userID,
		}, nil)
		return
	}

	tenantId, err := strconv.Atoi(tenantIdStr)
	if err != nil {
		http.Error(w, "Invalid tenant ID", http.StatusBadRequest)
		services.LogEntry("ActivateUser in auth controller", "error", "Invalid tenant ID: "+err.Error(), models.User{
			ID: userID,
		}, nil)
		return
	}

	err = services.UpdateUserStatus(userID, "active", systemId, tenantId)
	if err != nil {
		http.Error(w, "Failed to activate user", http.StatusInternalServerError)
		services.LogEntry("ActivateUser in auth controller", "error", "Failed to activate user: "+err.Error(), models.User{
			ID:       userID,
			SystemId: systemId,
			TenantId: tenantId,
		}, nil)
		return
	}

	services.LogEntry("ActivateUser in auth controller", "info", "User activated successfully", models.User{
		ID:       userID,
		SystemId: systemId,
		TenantId: tenantId,
	}, nil)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "User activated successfully"})
}

// DeactivateUser sets a user's status to 'deactivated'
func DeactivateUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userIDStr := vars["userID"]
	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		services.LogEntry("DeactivateUser in auth controller", "error", "Invalid user ID: "+err.Error(), models.User{}, nil)
		return
	}

	// Get systemId and tenantId from headers
	systemIdStr := r.Header.Get("X-System-Id")
	tenantIdStr := r.Header.Get("X-Tenant-Id")

	if systemIdStr == "" || tenantIdStr == "" {
		http.Error(w, "Missing system or tenant in headers", http.StatusBadRequest)
		services.LogEntry("DeactivateUser in auth controller", "error", "Missing system or tenant in headers", models.User{
			ID: userID,
		}, nil)
		return
	}

	systemId, err := strconv.Atoi(systemIdStr)
	if err != nil {
		http.Error(w, "Invalid system ID", http.StatusBadRequest)
		services.LogEntry("DeactivateUser in auth controller", "error", "Invalid system ID: "+err.Error(), models.User{
			ID: userID,
		}, nil)
		return
	}

	tenantId, err := strconv.Atoi(tenantIdStr)
	if err != nil {
		http.Error(w, "Invalid tenant ID", http.StatusBadRequest)
		services.LogEntry("DeactivateUser in auth controller", "error", "Invalid tenant ID: "+err.Error(), models.User{
			ID: userID,
		}, nil)
		return
	}

	err = services.UpdateUserStatus(userID, "inactive", systemId, tenantId)
	if err != nil {
		http.Error(w, "Failed to deactivate user", http.StatusInternalServerError)
		services.LogEntry("DeactivateUser in auth controller", "error", "Failed to deactivate user: "+err.Error(), models.User{
			ID:       userID,
			SystemId: systemId,
			TenantId: tenantId,
		}, nil)
		return
	}

	services.LogEntry("DeactivateUser in auth controller", "info", "User deactivated successfully", models.User{
		ID:       userID,
		SystemId: systemId,
		TenantId: tenantId,
	}, nil)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "User deactivated successfully"})
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
		UserId   int `json:"user_id"`
		RoleId   int `json:"role_id"`
		SystemId int `json:"system_id"`
		TenantId int `json:"tenant_id"`
	}

	// Decode request data
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, "Invalid request data", http.StatusBadRequest)
		services.LogEntry("EditUserRole in auth controller", "error", "Failed to decode request data", models.User{
			ID:       data.UserId,
			RoleID:   data.RoleId,
			SystemId: data.SystemId,
			TenantId: data.TenantId,
		}, nil)
		return
	}

	// Validate role ID
	if err := services.ValidateRoleID(data.RoleId, data.SystemId, data.TenantId); err != nil {
		http.Error(w, "Invalid role ID", http.StatusBadRequest)
		services.LogEntry("EditUserRole in auth controller", "error", "Invalid role ID: "+err.Error(), models.User{
			ID:       data.UserId,
			RoleID:   data.RoleId,
			SystemId: data.SystemId,
			TenantId: data.TenantId,
		}, nil)
		return
	}

	// Update user role in the database
	if err := services.EditUserRole(data.UserId, data.RoleId, data.SystemId, data.TenantId); err != nil {
		http.Error(w, "Failed to update user role", http.StatusInternalServerError)
		services.LogEntry("EditUserRole in auth controller", "error", "Failed to update user role: "+err.Error(), models.User{
			ID:       data.UserId,
			RoleID:   data.RoleId,
			SystemId: data.SystemId,
			TenantId: data.TenantId,
		}, nil)
		return
	}

	// Log successful role update
	services.LogEntry("EditUserRole in auth controller", "info", "User role updated successfully", models.User{
		ID:       data.UserId,
		RoleID:   data.RoleId,
		SystemId: data.SystemId,
		TenantId: data.TenantId,
	}, nil)

	// Return JSON response
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "User role updated successfully"})
}

// Admin function to edit user permissions
func EditUserPermissions(w http.ResponseWriter, r *http.Request) {
	var data struct {
		UserID      int                 `json:"user_id"`
		Permissions []models.Permission `json:"permissions"`
		SystemId    int                 `json:"system_id"`
		TenantId    int                 `json:"tenant_id"`
	}

	// Decode request data
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, "Invalid request data", http.StatusBadRequest)
		services.LogEntry("EditUserPermissions in auth controller", "error", "Failed to decode request data", models.User{
			ID:       data.UserID,
			SystemId: data.SystemId,
			TenantId: data.TenantId,
		}, nil)
		return
	}

	// Update user permissions in the database
	if err := services.EditUserPermissions(data.UserID, data.Permissions, data.SystemId, data.TenantId); err != nil {
		http.Error(w, "Failed to update user permissions", http.StatusInternalServerError)
		services.LogEntry("EditUserPermissions in auth controller", "error", "Failed to update user permissions: "+err.Error(), models.User{
			ID: data.UserID,
		}, nil)
		return
	}

	// Log successful permissions update
	services.LogEntry("EditUserPermissions in auth controller", "info", "User permissions updated successfully", models.User{
		ID:       data.UserID,
		SystemId: data.SystemId,
		TenantId: data.TenantId,
	}, nil)

	// Return JSON response
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "User permissions updated successfully"})
}

// AssignWardsToUser assigns wards to a user based on the incoming request
func AssignWardsToUser(w http.ResponseWriter, r *http.Request) {
	// Parse the request body (assumed to be JSON with user_id, ward_ids)
	var request struct {
		UserID   int   `json:"user_id"`
		WardIDs  []int `json:"ward_ids"`
		SystemId int   `json:"system_id"`
		TenantId int   `json:"tenant_id"`
	}
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Call the service layer to assign the wards
	err = services.AssignWardsToUser(request.UserID, request.WardIDs, request.SystemId, request.TenantId)
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
		UserID      int                 `json:"user_id"`
		Permissions []models.Permission `json:"permissions"`
		Wards       []int               `json:"wards"`
		SystemId    int                 `json:"system_id"`
		TenantId    int                 `json:"tenant_id"`
	}

	// Decode request data
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, "Invalid request data", http.StatusBadRequest)
		services.LogEntry("EditUserWardPermissions in auth controller", "error", "Failed to decode request data", models.User{
			ID:       data.UserID,
			SystemId: data.SystemId,
			TenantId: data.TenantId,
		}, nil)
		return
	}

	// Update user ward-specific permissions in the database
	if err := services.EditUserWardPermissions(data.UserID, data.Permissions, data.Wards, data.SystemId, data.TenantId); err != nil {
		http.Error(w, "Failed to update user ward permissions", http.StatusInternalServerError)
		services.LogEntry("EditUserWardPermissions in auth controller", "error", "Failed to update user ward permissions: "+err.Error(), models.User{
			ID:       data.UserID,
			SystemId: data.SystemId,
			TenantId: data.TenantId,
		}, nil)
		return
	}

	// Log successful permissions update
	services.LogEntry("EditUserWardPermissions in auth controller", "info", "User ward permissions updated successfully", models.User{
		ID:       data.UserID,
		SystemId: data.SystemId,
		TenantId: data.TenantId,
	}, nil)

	// Return JSON response
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "User ward permissions updated successfully"})
}

// Admin function to fetch a list of all users for a specific system and hospital
func GetUsersList(w http.ResponseWriter, r *http.Request) {
	systemId := r.Header.Get("X-System-Id")
	tenantId := r.Header.Get("X-Tenant-Id")

	if systemId == "" || tenantId == "" {
		http.Error(w, "Missing system or tenant in headers", http.StatusBadRequest)
		services.LogEntry("GetUsersList in auth controller", "error", "Missing system or hospital in headers", models.User{}, nil)
		return

	}

	systemIdInt, err := strconv.Atoi(systemId)
	if err != nil {
		http.Error(w, "Invalid system ID", http.StatusBadRequest)
		services.LogEntry("GetUsersList in auth controller", "error", "Invalid system ID: "+err.Error(), models.User{}, nil)
		return
	}

	tenantIdInt, err := strconv.Atoi(tenantId)
	if err != nil {
		http.Error(w, "Invalid tenant ID", http.StatusBadRequest)
		services.LogEntry("GetUsersList in auth controller", "error", "Invalid tenant ID: "+err.Error(), models.User{}, nil)
		return
	}

	// Retrieve users list from the service
	users, err := services.GetUsersList(systemIdInt, tenantIdInt)
	if err != nil {
		http.Error(w, "Failed to retrieve users", http.StatusInternalServerError)
		services.LogEntry("GetUsersList in auth controller", "error", "Failed to retrieve users: "+err.Error(), models.User{
			SystemId: systemIdInt,
			TenantId: tenantIdInt,
		}, nil)
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
	SystemId := r.Header.Get("X-System-Id")
	TenantId := r.Header.Get("X-Tenant-Id")

	if userIDStr == "" || SystemId == "" || TenantId == "" {
		http.Error(w, "Missing user ID or system or tenant in headers", http.StatusBadRequest)
		services.LogEntry("DeleteUser in auth controller", "error", "Missing user ID or system or hospital in headers", models.User{}, nil)
		return
	}

	// Convert the systemID from string to integer
	systemIdInt, err := strconv.Atoi(SystemId)
	if err != nil {
		http.Error(w, "Invalid system ID", http.StatusBadRequest)
		services.LogEntry("DeleteUser in auth controller", "error", "Invalid system ID format", models.User{}, nil)
		return
	}

	// Convert the tenantID from string to integer
	tenantIdInt, err := strconv.Atoi(TenantId)
	if err != nil {
		http.Error(w, "Invalid tenant ID", http.StatusBadRequest)
		services.LogEntry("DeleteUser in auth controller", "error", "Invalid tenant ID format", models.User{}, nil)
		return
	}

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
	if err := services.DeleteUser(userID, systemIdInt, tenantIdInt); err != nil {
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
	system := r.Header.Get("X-System-Id")
	tenant := r.Header.Get("X-Tenant-Id")

	// Validate required headers
	if system == "" || tenant == "" {
		services.LogEntry("GetRoles in rolesController", "error", "Missing system or hospital in headers", models.User{}, nil)
		http.Error(w, "Missing system or hospital in headers", http.StatusBadRequest)
		return
	}

	systemId, err := strconv.Atoi(system)
	if err != nil {
		services.LogEntry("GetRoles in rolesController", "error", "Invalid system ID: "+err.Error(), models.User{}, nil)
		http.Error(w, "Invalid system ID", http.StatusBadRequest)
		return
	}

	tenantId, err := strconv.Atoi(tenant)
	if err != nil {
		services.LogEntry("GetRoles in rolesController", "error", "Invalid tenant ID: "+err.Error(), models.User{}, nil)
		http.Error(w, "Invalid tenant ID", http.StatusBadRequest)
		return
	}

	roles, err := services.GetRoles(systemId, tenantId)
	if err != nil {
		services.LogEntry("GetRoles in rolesController", "error",
			fmt.Sprintf("Failed to retrieve roles for system %s and hospital %s: %s", config.SystemsList[systemId].SystemCode, config.TenantsList[tenantId].TenantCode, err.Error()),
			models.User{}, nil)
		http.Error(w, "Failed to retrieve roles", http.StatusInternalServerError)
		return
	}

	services.LogEntry("GetRoles in rolesController", "info",
		fmt.Sprintf("Roles retrieved successfully for system %s and hospital %s", config.TenantsList[tenantId].TenantCode, config.TenantsList[tenantId].TenantCode),
		models.User{}, map[string]interface{}{
			"Roles": roles,
		})

	// Return roles as JSON
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(roles)
}

// GetPermissions retrieves all permissions for a specific system and hospital
func GetPermissions(w http.ResponseWriter, r *http.Request) {
	system := r.Header.Get("X-System-Id")
	tenant := r.Header.Get("X-Tenant-Id")

	// Validate required headers
	if system == "" || tenant == "" {
		services.LogEntry("GetPermissions in permissionsController", "error", "Missing system or hospital in headers", models.User{}, nil)
		http.Error(w, "Missing system or hospital in headers", http.StatusBadRequest)
		return
	}

	systemId, err := strconv.Atoi(system)
	if err != nil {
		services.LogEntry("GetPermissions in permissionsController", "error", "Invalid system ID: "+err.Error(), models.User{}, nil)
		http.Error(w, "Invalid system ID", http.StatusBadRequest)
		return
	}

	tenantId, err := strconv.Atoi(tenant)
	if err != nil {
		services.LogEntry("GetPermissions in permissionsController", "error", "Invalid tenant ID: "+err.Error(), models.User{}, nil)
		http.Error(w, "Invalid tenant ID", http.StatusBadRequest)
		return
	}

	permissions, err := services.GetPermissions(systemId, tenantId)
	if err != nil {
		services.LogEntry("GetPermissions in permissionsController", "error",
			fmt.Sprintf("Failed to retrieve permissions for system %s and hospital %s: %s", config.SystemsList[systemId].SystemCode, config.TenantsList[tenantId].TenantCode, err.Error()),
			models.User{}, nil)
		http.Error(w, "Failed to retrieve permissions", http.StatusInternalServerError)
		return
	}

	services.LogEntry("GetPermissions in permissionsController", "info",
		fmt.Sprintf("Permissions retrieved successfully for system %s and hospital %s", config.TenantsList[tenantId].TenantCode, config.TenantsList[tenantId].TenantCode),
		models.User{}, map[string]interface{}{
			"Permissions": permissions,
		})

	// Return permissions as JSON
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(permissions)
}

// CreateRole creates a new role in the system for a specific tenant
func CreateRole(w http.ResponseWriter, r *http.Request) {
	var roleData struct {
		RoleName string `json:"role_name"`
		SystemId int    `json:"system_id"`
		TenantId int    `json:"tenant_id"`
	}

	// Decode request body
	if err := json.NewDecoder(r.Body).Decode(&roleData); err != nil {
		http.Error(w, "Invalid request data", http.StatusBadRequest)
		services.LogEntry("CreateRole in role controller", "error", "Failed to decode request body", models.User{}, nil)
		return
	}

	// Validate required fields
	if roleData.RoleName == "" || roleData.SystemId == 0 || roleData.TenantId == 0 {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		services.LogEntry("CreateRole in role controller", "error", "Missing required fields", models.User{}, nil)
		return
	}

	// Check if role exists
	existingRole, err := services.GetRoleByName(roleData.RoleName, roleData.SystemId, roleData.TenantId)
	if err == nil && existingRole != nil {
		http.Error(w, "Role already exists", http.StatusConflict)
		services.LogEntry("CreateRole in role controller", "error", "Role already exists", models.User{}, nil)
		return
	}

	// Create the new role
	err = services.CreateRole(roleData.RoleName, roleData.SystemId, roleData.TenantId)
	if err != nil {
		http.Error(w, "Failed to create role", http.StatusInternalServerError)
		services.LogEntry("CreateRole in role controller", "error", "Failed to create role: "+err.Error(), models.User{}, nil)
		return
	}

	services.LogEntry("CreateRole in role controller", "info", "Role created successfully", models.User{}, map[string]interface{}{
		"RoleName": roleData.RoleName,
		"SystemId": roleData.SystemId,
		"TenantId": roleData.TenantId,
	})

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "Role created successfully"})
}

// EditRole updates an existing role's details
func EditRole(w http.ResponseWriter, r *http.Request) {
	var roleData struct {
		RoleId   int    `json:"role_id"`
		RoleName string `json:"role_name"`
		SystemId int    `json:"system_id"`
		TenantId int    `json:"tenant_id"`
	}

	// Decode request body
	if err := json.NewDecoder(r.Body).Decode(&roleData); err != nil {
		http.Error(w, "Invalid request data", http.StatusBadRequest)
		services.LogEntry("EditRole in role controller", "error", "Failed to decode request body", models.User{}, nil)
		return
	}

	// Validate required fields
	if roleData.RoleId == 0 || roleData.RoleName == "" || roleData.SystemId == 0 || roleData.TenantId == 0 {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		services.LogEntry("EditRole in role controller", "error", "Missing required fields", models.User{}, nil)
		return
	}

	// Check if role exists
	existingRole, err := services.GetRoleById(roleData.RoleId, roleData.SystemId, roleData.TenantId)
	if err != nil || existingRole == nil {
		http.Error(w, "Role not found", http.StatusNotFound)
		services.LogEntry("EditRole in role controller", "error", "Role not found", models.User{}, nil)
		return
	}

	// Update the role in the service layer
	err = services.EditRole(roleData.RoleId, roleData.RoleName, roleData.SystemId, roleData.TenantId)
	if err != nil {
		http.Error(w, "Failed to update role", http.StatusInternalServerError)
		services.LogEntry("EditRole in role controller", "error", "Failed to update role: "+err.Error(), models.User{}, nil)
		return
	}

	services.LogEntry("EditRole in role controller", "info", "Role updated successfully", models.User{}, map[string]interface{}{
		"RoleId":   roleData.RoleId,
		"RoleName": roleData.RoleName,
		"SystemId": roleData.SystemId,
		"TenantId": roleData.TenantId,
	})

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Role updated successfully"})
}

// DeleteRole removes a role from the system for a specific tenant
func DeleteRole(w http.ResponseWriter, r *http.Request) {
	var roleData struct {
		RoleId   int `json:"role_id"`
		SystemId int `json:"system_id"`
		TenantId int `json:"tenant_id"`
	}

	// Decode request body
	if err := json.NewDecoder(r.Body).Decode(&roleData); err != nil {
		http.Error(w, "Invalid request data", http.StatusBadRequest)
		services.LogEntry("DeleteRole in role controller", "error", "Failed to decode request body", models.User{}, nil)
		return
	}

	// Validate required fields
	if roleData.RoleId == 0 || roleData.SystemId == 0 || roleData.TenantId == 0 {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		services.LogEntry("DeleteRole in role controller", "error", "Missing required fields", models.User{}, nil)
		return
	}

	// Check if role exists
	existingRole, err := services.GetRoleById(roleData.RoleId, roleData.SystemId, roleData.TenantId)
	if err != nil || existingRole == nil {
		http.Error(w, "Role not found", http.StatusNotFound)
		services.LogEntry("DeleteRole in role controller", "error", "Role not found", models.User{}, nil)
		return
	}

	// Delete the role from the service layer
	err = services.DeleteRole(roleData.RoleId, roleData.SystemId, roleData.TenantId)
	if err != nil {
		http.Error(w, "Failed to delete role", http.StatusInternalServerError)
		services.LogEntry("DeleteRole in role controller", "error", "Failed to delete role: "+err.Error(), models.User{}, nil)
		return
	}

	services.LogEntry("DeleteRole in role controller", "info", "Role deleted successfully", models.User{}, map[string]interface{}{
		"RoleId":   roleData.RoleId,
		"SystemId": roleData.SystemId,
		"TenantId": roleData.TenantId,
	})

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Role deleted successfully"})
}

// CreatePermission handles the creation of a new permission
func CreatePermission(w http.ResponseWriter, r *http.Request) {
	var data struct {
		PermissionName string `json:"permission_name"`
		SystemId       int    `json:"system_id"`
		TenantId       int    `json:"tenant_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, "Invalid request data", http.StatusBadRequest)
		services.LogEntry("CreatePermission in permissionsController", "error", "Failed to decode request data", models.User{}, nil)
		return
	}

	// Validate inputs
	if data.PermissionName == "" {
		http.Error(w, "Permission name is required", http.StatusBadRequest)
		services.LogEntry("CreatePermission in permissionsController", "error", "Permission name is missing", models.User{}, nil)
		return
	}

	if err := services.CreatePermission(data.PermissionName, data.SystemId, data.TenantId); err != nil {
		http.Error(w, fmt.Sprintf("Failed to create permission: %s", err.Error()), http.StatusInternalServerError)
		services.LogEntry("CreatePermission in permissionsController", "error", "Failed to create permission: "+err.Error(), models.User{}, nil)
		return
	}

	services.LogEntry("CreatePermission in permissionsController", "info", fmt.Sprintf("Permission '%s' created successfully", data.PermissionName), models.User{}, nil)
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "Permission created successfully"})
}

// EditPermission handles the editing of an existing permission
func EditPermission(w http.ResponseWriter, r *http.Request) {
	var data struct {
		PermissionId      int    `json:"permission_id"`
		NewPermissionName string `json:"new_permission_name"`
		SystemId          int    `json:"system_id"`
		TenantId          int    `json:"tenant_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, "Invalid request data", http.StatusBadRequest)
		services.LogEntry("EditPermission in permissionsController", "error", "Failed to decode request data", models.User{}, nil)
		return
	}

	if data.NewPermissionName == "" {
		http.Error(w, "New permission name is required", http.StatusBadRequest)
		services.LogEntry("EditPermission in permissionsController", "error", "New permission name is missing", models.User{}, nil)
		return
	}

	if err := services.EditPermission(data.PermissionId, data.NewPermissionName, data.SystemId, data.TenantId); err != nil {
		http.Error(w, fmt.Sprintf("Failed to edit permission: %s", err.Error()), http.StatusInternalServerError)
		services.LogEntry("EditPermission in permissionsController", "error", "Failed to edit permission: "+err.Error(), models.User{}, nil)
		return
	}

	services.LogEntry("EditPermission in permissionsController", "info", fmt.Sprintf("Permission ID %d updated to '%s'", data.PermissionId, data.NewPermissionName), models.User{}, nil)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Permission updated successfully"})
}

// DeletePermission handles the deletion of a permission
func DeletePermission(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	permissionIDStr := params["id"]

	permissionID, err := strconv.Atoi(permissionIDStr)
	if err != nil {
		http.Error(w, "Invalid permission ID", http.StatusBadRequest)
		services.LogEntry("DeletePermission in permissionsController", "error", "Invalid permission ID", models.User{}, nil)
		return
	}

	systemId, err := strconv.Atoi(r.Header.Get("X-System-Id"))
	if err != nil {
		http.Error(w, "Invalid system ID", http.StatusBadRequest)
		services.LogEntry("DeletePermission in permissionsController", "error", "Invalid system ID", models.User{}, nil)
		return
	}

	tenantId, err := strconv.Atoi(r.Header.Get("X-Tenant-Id"))
	if err != nil {
		http.Error(w, "Invalid tenant ID", http.StatusBadRequest)
		services.LogEntry("DeletePermission in permissionsController", "error", "Invalid tenant ID", models.User{}, nil)
		return
	}

	if err := services.DeletePermission(permissionID, systemId, tenantId); err != nil {
		http.Error(w, fmt.Sprintf("Failed to delete permission: %s", err.Error()), http.StatusInternalServerError)
		services.LogEntry("DeletePermission in permissionsController", "error", "Failed to delete permission: "+err.Error(), models.User{}, nil)
		return
	}

	services.LogEntry("DeletePermission in permissionsController", "info", fmt.Sprintf("Permission ID %d deleted successfully", permissionID), models.User{}, nil)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Permission deleted successfully"})
}
