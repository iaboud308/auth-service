package services

import (
	"auth-service/models"
	"fmt"
)

// CreateUser inserts a new user into the database
func CreateUser(user *models.User) error {
	user.Status = "pending"
	sqlStatement := `INSERT INTO users (first_name, last_name, email, password, role_id, status) 
	                 VALUES ($1, $2, $3, $4, $5, $6)`
	db, err := GetDBConnection(user.SystemId, user.TenantId)
	if err != nil {
		LogEntry("CreateUser in authService", "error", "Error getting database connection: "+err.Error(), *user, nil)
		return fmt.Errorf("failed to get database connection: %w", err)
	}

	rowCount, err := InsertRow(db, sqlStatement, []interface{}{
		user.FirstName, user.LastName, user.Email, user.Password, user.RoleID, user.Status,
	}, models.LogInfo{
		Action:  "CreateUser",
		Message: fmt.Sprintf("Creating user with email %s", user.Email),
		User:    *user,
	})

	if err != nil {
		return fmt.Errorf("failed to insert user: %w", err)
	}

	if rowCount == 0 {
		return fmt.Errorf("no rows inserted")
	}

	return nil
}

// GetUserByEmail retrieves a user by their email, system, and tenant
func GetUserByEmail(email string, systemId int, tenantId int) (*models.User, error) {
	sqlStatement := `SELECT id, first_name, last_name, email, password, role_id, status
	                 FROM users WHERE email = $1`
	db, err := GetDBConnection(systemId, tenantId)
	if err != nil {
		LogEntry("GetUserByEmail in authService", "error", "Error getting database connection: "+err.Error(), models.User{
			Email:    email,
			SystemId: systemId,
			TenantId: tenantId,
		}, nil)
		return nil, err
	}

	var user models.User
	rowCount, err := GetSingleRow(db, sqlStatement, []interface{}{email}, []interface{}{
		&user.ID, &user.FirstName, &user.LastName, &user.Email, &user.Password, &user.RoleID, &user.Status,
	}, models.LogInfo{
		Action:  "GetUserByEmail in authService - GetSingleRow",
		Message: fmt.Sprintf("Retrieving user with email %s", email),
		User: models.User{
			Email:    email,
			SystemId: systemId,
			TenantId: tenantId,
		},
	})

	if err != nil {
		return nil, err
	}

	if rowCount == 0 {
		return nil, nil
	}

	return &user, nil
}

// GetUserByID retrieves a user by their ID from the database
func GetUserByID(userID int, systemId int, tenantId int) (*models.User, error) {
	sqlStatement := `SELECT id, first_name, last_name, email, role_id, status
	                 FROM users WHERE id = $1`
	db, err := GetDBConnection(systemId, tenantId)
	if err != nil {
		LogEntry("GetUserByID in authService", "error", "Error getting database connection: "+err.Error(), models.User{
			ID: userID,
		}, nil)
		return nil, err
	}

	var user models.User
	_, err = GetSingleRow(db, sqlStatement, []interface{}{userID}, []interface{}{
		&user.ID, &user.FirstName, &user.LastName, &user.Email, &user.RoleID, &user.Status,
	}, models.LogInfo{
		Action:  "GetUserByID",
		Message: fmt.Sprintf("Retrieving user with ID %d", userID),
		User: models.User{
			ID: userID,
		},
	})

	if err != nil {
		return nil, err
	}

	LogEntry("GetUserByID in authService", "info", "User retrieved successfully", user, nil)

	return &user, nil
}

// UpdateUserStatus updates the user's status in the database
func UpdateUserStatus(userId int, status string, systemId int, tenantId int) error {
	sqlStatement := `UPDATE users SET status = $1 WHERE id = $2`

	db, err := GetDBConnection(systemId, tenantId)
	if err != nil {
		LogEntry("UpdateUserStatus in authService", "error", fmt.Sprintf("Error getting database connection: %s", err.Error()),
			models.User{ID: userId}, nil)
		return fmt.Errorf("failed to get database connection: %w", err)
	}

	rowCount, err := UpdateRow(db, sqlStatement, []interface{}{status, userId}, models.LogInfo{
		Action:  "UpdateUserStatus",
		Message: fmt.Sprintf("Updating user status for ID %d", userId),
		User:    models.User{ID: userId},
	})

	if err != nil {
		return fmt.Errorf("failed to update user status for ID %d: %w", userId, err)
	}

	if rowCount == 0 {
		return fmt.Errorf("no rows updated")
	}

	LogEntry("UpdateUserStatus in authService", "info", fmt.Sprintf("User status updated successfully for ID %d", userId),
		models.User{ID: userId}, nil)

	return nil
}

// EditUser updates user details like first name, last name, and email
func EditUser(user *models.User) error {
	sqlStatement := `UPDATE users SET first_name = $1, last_name = $2, email = $3 WHERE id = $4`
	db, err := GetDBConnection(user.SystemId, user.TenantId)
	if err != nil {
		LogEntry("EditUser in authService", "error",
			fmt.Sprintf("Error getting database connection: %s", err.Error()),
			*user, nil)
		return fmt.Errorf("failed to get database connection: %w", err)
	}

	rowCount, err := UpdateRow(db, sqlStatement, []interface{}{user.FirstName, user.LastName, user.Email, user.ID}, models.LogInfo{
		Action:  "EditUser",
		Message: fmt.Sprintf("Editing user details for ID %d", user.ID),
		User:    *user,
	})

	if err != nil {
		return fmt.Errorf("failed to update user details for ID %d: %w", user.ID, err)
	}

	if rowCount == 0 {
		return fmt.Errorf("no rows updated")
	}

	LogEntry("EditUser in authService", "info",
		fmt.Sprintf("User details updated successfully for ID %d", user.ID),
		*user, nil)

	return nil
}

// DeleteUser deletes a user by ID
func DeleteUser(userID int, systemId int, tenantId int) error {
	sqlStatement := `DELETE FROM users WHERE id = $1`
	db, err := GetDBConnection(systemId, tenantId)
	if err != nil {
		LogEntry("DeleteUser in authService", "error",
			fmt.Sprintf("Error getting database connection: %s", err.Error()),
			models.User{
				ID: userID,
			}, nil)
		return fmt.Errorf("failed to get database connection: %w", err)
	}

	result, err := DeleteRow(db, sqlStatement, []interface{}{userID}, models.LogInfo{
		Action:  "DeleteUser",
		Message: fmt.Sprintf("Deleting user with ID %d", userID),
		User: models.User{
			ID: userID,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to delete user with ID %d: %w", userID, err)
	}

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
	db, err := GetDBConnection(user.SystemId, user.TenantId)
	if err != nil {
		LogEntry("AssignDefaultPermissions in authService", "error", fmt.Sprintf("Error getting database connection: %s", err.Error()),
			*user, nil)
		return fmt.Errorf("failed to get database connection: %w", err)
	}

	rowCount, err := InsertRow(db, sqlStatement, []interface{}{user.ID, user.RoleID}, models.LogInfo{
		Action:  "AssignDefaultPermissions",
		Message: fmt.Sprintf("Assigning default permissions for user ID %d with role ID %d", user.ID, user.RoleID),
		User:    *user,
	})

	if err != nil {
		return fmt.Errorf("failed to assign default permissions for user ID %d with role ID %d: %w", user.ID, user.RoleID, err)
	}

	if rowCount == 0 {
		return fmt.Errorf("no rows inserted")
	}

	LogEntry("AssignDefaultPermissions in authService", "info",
		fmt.Sprintf("Default permissions assigned successfully for user ID %d with role ID %d", user.ID, user.RoleID),
		*user, nil)

	return nil
}

// GetUsersList retrieves a list of users by system and tenant
func GetUsersList(systemId int, tenantId int) ([]models.AuthResponse, error) {
	// sqlStatement := `
	// 	SELECT u.id, u.first_name, u.last_name, u.email, u.status, r.role_name,
	// 	       array_agg(DISTINCT p.permission_name) AS permissions,
	// 	       array_agg(DISTINCT w.ward_name) AS wards,
	// 	       array_agg(DISTINCT wp.permission_name) AS ward_permissions
	// 	FROM users u
	// 	INNER JOIN roles r ON u.role_id = r.id
	// 	LEFT JOIN user_permissions up ON u.id = up.user_id
	// 	LEFT JOIN permissions p ON up.permission_id = p.id
	// 	LEFT JOIN user_wards uw ON u.id = uw.user_id
	// 	LEFT JOIN wards w ON uw.ward_id = w.id
	// 	LEFT JOIN user_ward_permissions uwp ON uw.id = uwp.user_ward_id
	// 	LEFT JOIN permissions wp ON uwp.permission_id = wp.id
	// 	GROUP BY u.id, r.role_name
	// `

	sqlStatement := `
    SELECT u.id, u.first_name, u.last_name, u.email, u.status, r.role_name
    FROM users u
    INNER JOIN roles r ON u.role_id = r.id
`

	db, err := GetDBConnection(systemId, tenantId)
	if err != nil {
		return nil, fmt.Errorf("failed to get database connection: %w", err)
	}

	var users []models.AuthResponse
	var user models.AuthResponse

	rows, err := db.Query(sqlStatement)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rowCount int

	for rows.Next() {
		if err := rows.Scan(&user.ID, &user.FirstName, &user.LastName, &user.Email, &user.Status, &user.Role); err != nil {
			return nil, err
		}

		rowCount++
		users = append(users, user)
	}

	if rowCount == 0 {
		return nil, fmt.Errorf("no users found")
	}

	LogEntry("GetUsersList in authService", "info",
		fmt.Sprintf("Retrieved %d users for system %d and tenant %d", rowCount, systemId, tenantId), models.User{}, map[string]interface{}{
			"Result": users,
		})

	return users, nil
}
