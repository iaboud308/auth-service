package services

import (
	"auth-service/config"
	"auth-service/models"
	"database/sql"
	"errors"
	"fmt"
	"log"

	"github.com/lib/pq"
)

var db *sql.DB

// InitDB initializes the database connection
func InitDB() {
	var err error
	db, err = sql.Open("postgres", config.GetDBConnectionString())
	if err != nil {
		log.Fatal("Unable to connect to the database:", err)
	}

	// Ping the database to ensure connection is established
	if err := db.Ping(); err != nil {
		log.Fatal("Unable to reach the database:", err)
	}
}

// CreateUser inserts a new user into the database
func CreateUser(user *models.User) error {
	user.Status = "pending"
	sqlStatement := `INSERT INTO users (first_name, last_name, email, password, system, role_id, hospital, status) 
	                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	result, err := db.Exec(sqlStatement, user.FirstName, user.LastName, user.Email, user.Password, user.System, user.RoleID, user.Hospital, user.Status)

	// Log the result of the user creation process
	if err != nil {
		LogEntry("CreateUser in authService", "error", "Failed to create user: "+err.Error(),
			*user, map[string]interface{}{
				"RowsAffected": result.RowsAffected,
				"Result":       result,
			})
		return err
	}

	// If successful, log the user creation
	LogEntry("CreateUser in authService", "info", "User created successfully", *user, nil)

	return nil
}

// GetUserByEmail retrieves a user by their email, system, and hospital
func GetUserByEmail(email string, system string, hospital string) (*models.User, error) {
	sqlStatement := `SELECT id, first_name, last_name, email, password, system, role_id, hospital, status 
	                 FROM users WHERE email = $1 AND system = $2 AND hospital = $3`
	rows, err := db.Query(sqlStatement, email, system, hospital)
	if err != nil {
		// Log the error if there is an issue with the query
		LogEntry("GetUserByEmail in authService", "error", "Error retrieving user: "+err.Error(), models.User{
			Email:    email,
			System:   system,
			Hospital: hospital,
		}, nil)
		return nil, err
	}
	defer rows.Close()

	// Check how many rows are returned
	rowCount := 0
	var user models.User
	for rows.Next() {
		rowCount++
		err := rows.Scan(&user.ID, &user.FirstName, &user.LastName, &user.Email, &user.Password, &user.System, &user.RoleID, &user.Hospital, &user.Status)
		if err != nil {
			LogEntry("GetUserByEmail in authService", "error", "Error scanning user: "+err.Error(), user, map[string]interface{}{
				"rowCount": rowCount,
			})
			return nil, err
		}
	}

	// If more than one row is returned, log it as an error
	if rowCount > 1 {
		LogEntry("GetUserByEmail in authService", "error", "Multiple users found with the same email, system, and hospital",
			user, map[string]interface{}{
				"rowCount": rowCount,
			})
		return nil, errors.New("multiple users found with the same email, system, and hospital")
	}

	// If no rows are found, log that no user was found
	if rowCount == 0 {
		LogEntry("GetUserByEmail in authService", "info", "No user found with the given email, system, and hospital", models.User{
			Email:    email,
			System:   system,
			Hospital: hospital,
		}, map[string]interface{}{
			"rowCount": rowCount,
		})
		return nil, nil
	}

	// Log the successful retrieval of the user
	LogEntry("GetUserByEmail in authService", "info", "User retrieved successfully", user, map[string]interface{}{
		"rowCount": rowCount,
	})

	return &user, nil
}

// GetUserByID retrieves a user by their ID from the database
func GetUserByID(userID int) (*models.User, error) {
	sqlStatement := `SELECT id, first_name, last_name, email, system, role_id, hospital, status
	                 FROM users WHERE id = $1`
	row := db.QueryRow(sqlStatement, userID)

	var user models.User
	err := row.Scan(&user.ID, &user.FirstName, &user.LastName, &user.Email, &user.System, &user.RoleID, &user.Hospital, &user.Status)

	// Handle error scenarios
	if err != nil {
		if err == sql.ErrNoRows {
			// Log that no user was found for the given ID
			LogEntry("GetUserByID in authService", "info", "No user found with given ID", models.User{
				ID: userID,
			}, nil)
			return nil, nil // No user found is not an error, so return nil, nil
		}
		// Log any other error that occurred during the query
		LogEntry("GetUserByID in authService", "error", "Error retrieving user: "+err.Error(), models.User{
			ID: userID,
		}, nil)
		return nil, err
	}

	// Log successful retrieval of user
	LogEntry("GetUserByID in authService", "info", "User retrieved successfully", user, nil)

	return &user, nil
}

// UpdateUserStatus updates the user's status in the database
func UpdateUserStatus(user *models.User) error {
	sqlStatement := `UPDATE users SET status = $1 WHERE id = $2`
	result, err := db.Exec(sqlStatement, user.Status, user.ID)
	if err != nil {
		LogEntry("UpdateUserStatus in authService", "error", fmt.Sprintf("Error updating user status for ID %d: %s", user.ID, err.Error()),
			*user, nil)
		return fmt.Errorf("failed to update user status for ID %d: %w", user.ID, err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		LogEntry("UpdateUserStatus in authService", "error", fmt.Sprintf("No user found with ID %d", user.ID),
			*user, nil)
		return fmt.Errorf("no user found with ID %d", user.ID)
	}

	LogEntry("UpdateUserStatus in authService", "info", fmt.Sprintf("User status updated successfully for ID %d", user.ID),
		*user, nil)

	return nil
}

// ApproveUser approves a user's registration by updating the status to "approved"
func ApproveUser(userID int) error {
	user, err := GetUserByID(userID)
	if err != nil {
		// Log the error if the user is not found
		LogEntry("ApproveUser in authService", "error", fmt.Sprintf("User with ID %d not found: %s", userID, err.Error()), models.User{
			ID: userID,
		}, map[string]interface{}{
			"RequestedUserID": userID,
		})
		return fmt.Errorf("user with ID %d not found: %w", userID, err)
	}

	// Check if the user is in the "pending" state
	if user.Status != "pending" {
		// Log if the user is not in the pending state
		LogEntry("ApproveUser in authService", "error", fmt.Sprintf("User with ID %d is not in the pending state", userID),
			*user, map[string]interface{}{
				"RequestedUserID": userID,
			})
		return fmt.Errorf("user with ID %d is not in the pending state", userID)
	}

	// Update the user's status to "approved"
	user.Status = "approved"
	err = UpdateUserStatus(user)
	if err != nil {
		// Log if updating the status fails
		LogEntry("ApproveUser in authService", "error", fmt.Sprintf("Error updating status to approved for user ID %d: %s", userID, err.Error()),
			*user, map[string]interface{}{
				"RequestedUserID": userID,
			})
		return fmt.Errorf("failed to approve user with ID %d: %w", userID, err)
	}

	// Log the successful approval of the user
	LogEntry("ApproveUser in authService", "info", fmt.Sprintf("User with ID %d approved successfully", userID),
		*user, nil)

	return nil
}

// DeclineUser declines a user's registration by updating the status to "declined"
func DeclineUser(userID int) error {
	user, err := GetUserByID(userID)
	if err != nil {
		// Log the error if the user is not found
		LogEntry("DeclineUser in authService", "error", fmt.Sprintf("User with ID %d not found: %s", userID, err.Error()),
			*user, map[string]interface{}{
				"RequestedUserID": userID,
			})
		return fmt.Errorf("user with ID %d not found: %w", userID, err)
	}

	// Check if the user is in the "pending" state
	if user.Status != "pending" {
		// Log if the user is not in the pending state
		LogEntry("DeclineUser in authService", "error", fmt.Sprintf("User with ID %d is not in the pending state", userID),
			*user, map[string]interface{}{
				"RequestedUserID": userID,
			})
		return fmt.Errorf("user with ID %d is not in the pending state", userID)
	}

	// Update the user's status to "declined"
	user.Status = "declined"
	err = UpdateUserStatus(user)
	if err != nil {
		// Log if updating the status fails
		LogEntry("DeclineUser in authService", "error",
			fmt.Sprintf("Error updating status to declined for user ID %d: %s", userID, err.Error()),
			*user, map[string]interface{}{
				"RequestedUserID": userID,
			})
		return fmt.Errorf("failed to decline user with ID %d: %w", userID, err)
	}

	// Log the successful decline of the user
	LogEntry("DeclineUser in authService", "info",
		fmt.Sprintf("User with ID %d declined successfully", userID),
		*user, nil)

	return nil
}

// EditUser updates user details like first name, last name, and email
func EditUser(user *models.User) error {
	sqlStatement := `UPDATE users SET first_name = $1, last_name = $2, email = $3 WHERE id = $4`
	result, err := db.Exec(sqlStatement, user.FirstName, user.LastName, user.Email, user.ID)
	if err != nil {
		LogEntry("EditUser in authService", "error",
			fmt.Sprintf("Error updating user details for ID %d: %s", user.ID, err.Error()),
			*user, nil)
		return fmt.Errorf("failed to update user details for ID %d: %w", user.ID, err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		LogEntry("EditUser in authService", "error",
			fmt.Sprintf("No user found with ID %d", user.ID),
			*user, map[string]interface{}{
				"RowsAffected": rowsAffected,
			})
		return fmt.Errorf("no user found with ID %d", user.ID)
	}

	LogEntry("EditUser in authService", "info",
		fmt.Sprintf("User details updated successfully for ID %d", user.ID),
		*user, nil)

	return nil
}

// DeleteUser deletes a user by ID
func DeleteUser(userID int) error {
	sqlStatement := `DELETE FROM users WHERE id = $1`
	result, err := db.Exec(sqlStatement, userID)
	if err != nil {
		// Log the error if the deletion fails
		LogEntry("DeleteUser in authService", "error",
			fmt.Sprintf("Error deleting user with ID %d: %s", userID, err.Error()),
			models.User{
				ID: userID,
			}, nil)
		return fmt.Errorf("failed to delete user with ID %d: %w", userID, err)
	}

	// Check how many rows were affected
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		// Log if no rows were deleted (meaning no user was found)
		LogEntry("DeleteUser in authService", "error", fmt.Sprintf("No user found with ID %d", userID),
			models.User{
				ID: userID,
			}, map[string]interface{}{
				"RowsAffected": rowsAffected,
			})
		return fmt.Errorf("no user found with ID %d", userID)
	}

	// Log the successful deletion
	LogEntry("DeleteUser in authService", "info", fmt.Sprintf("User with ID %d deleted successfully", userID),
		models.User{
			ID: userID,
		}, map[string]interface{}{
			"Result": result,
		})

	return nil
}

// AssignDefaultPermissions assigns default permissions to a user based on their role
func AssignDefaultPermissions(user *models.User) error {
	sqlStatement := `INSERT INTO user_permissions (user_id, permission_id)
	                 SELECT $1, permission_id FROM role_permissions WHERE role_id = $2`
	result, err := db.Exec(sqlStatement, user.ID, user.RoleID)
	if err != nil {
		// Log the error if the permission assignment fails
		LogEntry("AssignDefaultPermissions in authService", "error",
			fmt.Sprintf("Error assigning default permissions to user ID %d with role ID %d: %s", user.ID, user.RoleID, err.Error()),
			*user, nil)
		return fmt.Errorf("failed to assign default permissions for user ID %d with role ID %d: %w", user.ID, user.RoleID, err)
	}

	// Check how many rows were affected (i.e., how many permissions were assigned)
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		// Log if no permissions were assigned (meaning no matching role permissions)
		LogEntry("AssignDefaultPermissions in authService", "error",
			fmt.Sprintf("No default permissions found for role ID %d for user ID %d", user.RoleID, user.ID),
			*user, map[string]interface{}{
				"RowsAffected": rowsAffected,
			})
		return fmt.Errorf("no default permissions found for role ID %d for user ID %d", user.RoleID, user.ID)
	}

	// Log the successful assignment of permissions
	LogEntry("AssignDefaultPermissions in authService", "info",
		fmt.Sprintf("Default permissions assigned successfully for user ID %d with role ID %d", user.ID, user.RoleID),
		*user, nil)

	return nil
}

// GetUsersList retrieves a list of users by system and hospital
func GetUsersList(system, hospital string) ([]models.AuthResponse, error) {
	// Query to fetch users, roles, and permissions in one go
	sqlStatement := `
		SELECT u.id, u.first_name, u.last_name, u.email, u.system, u.hospital, u.status, r.role_name, array_agg(p.permission_name)
		FROM users u
		INNER JOIN roles r ON u.role_id = r.id
		LEFT JOIN user_permissions up ON u.id = up.user_id
		LEFT JOIN permissions p ON up.permission_id = p.id
		WHERE u.system = $1 AND u.hospital = $2
		GROUP BY u.id, r.role_name
	`

	// Execute the query
	rows, err := db.Query(sqlStatement, system, hospital)
	if err != nil {
		LogEntry("GetUsersList in authService", "error", fmt.Sprintf("Error retrieving users: %s", err.Error()),
			models.User{}, map[string]interface{}{
				"System":   system,
				"Hospital": hospital,
			})
		return nil, fmt.Errorf("failed to retrieve users for system %s and hospital %s: %w", system, hospital, err)
	}
	defer rows.Close()

	var users []models.AuthResponse
	for rows.Next() {
		var user models.AuthResponse
		var permissions []string

		// Scan the results, including aggregated permissions
		err := rows.Scan(&user.ID, &user.FirstName, &user.LastName, &user.Email, &user.System, &user.Hospital, &user.Status, &user.Role, pq.Array(&permissions))
		if err != nil {
			LogEntry("GetUsersList in authService", "error",
				fmt.Sprintf("Error scanning user data: %s", err.Error()),
				models.User{
					ID:        user.ID,
					Email:     user.Email,
					FirstName: user.FirstName,
					LastName:  user.LastName,
					System:    user.System,
					Hospital:  user.Hospital,
					Status:    user.Status,
				}, nil)
			return nil, fmt.Errorf("failed to scan user data for system %s and hospital %s: %w", system, hospital, err)
		}

		// Assign the permissions to the user
		user.Permissions = permissions

		// Append to the user list
		users = append(users, user)
	}

	// Check for errors after the iteration
	if err := rows.Err(); err != nil {
		LogEntry("GetUsersList in authService", "error", fmt.Sprintf("Error iterating over rows: %s", err.Error()),
			models.User{}, map[string]interface{}{
				"System":   system,
				"Hospital": hospital,
			})
		return nil, fmt.Errorf("error iterating over rows for system %s and hospital %s: %w", system, hospital, err)
	}

	// Log the successful retrieval
	LogEntry("GetUsersList in authService", "info",
		fmt.Sprintf("Successfully retrieved users for system %s and hospital %s", system, hospital),
		models.User{}, map[string]interface{}{
			"System":   system,
			"Hospital": hospital,
			"Users":    len(users),
		})

	return users, nil
}
