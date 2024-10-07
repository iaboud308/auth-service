package services

import (
	"auth-service/models"
	"fmt"
)

// GetUserPermissions retrieves the general permissions associated with a user
func GetUserPermissions(userID int, system string) ([]string, error) {
	sqlStatement := `
        SELECT p.permission_name
        FROM user_permissions up
        JOIN permissions p ON up.permission_id = p.id
        WHERE up.user_id = $1 AND p.system = $2
    `
	rows, err := db.Query(sqlStatement, userID, system)
	if err != nil {
		// Log the error and return
		LogEntry("GetUserPermissions in permissionService", "error",
			fmt.Sprintf("Error querying permissions for user ID %d and system %s: %s", userID, system, err.Error()), models.User{
				ID:     userID,
				System: system,
			}, nil)
		return nil, fmt.Errorf("failed to query permissions for user ID %d: %w", userID, err)
	}
	defer rows.Close()

	var permissions []string
	for rows.Next() {
		var permission string
		if err := rows.Scan(&permission); err != nil {
			LogEntry("GetUserPermissions in permissionService", "error",
				fmt.Sprintf("Error scanning permission for user ID %d: %s", userID, err.Error()), models.User{
					ID:     userID,
					System: system,
				}, nil)
			return nil, fmt.Errorf("failed to scan permission for user ID %d: %w", userID, err)
		}
		permissions = append(permissions, permission)
	}

	// Check for any errors encountered during the iteration
	if err := rows.Err(); err != nil {
		LogEntry("GetUserPermissions in permissionService", "error", fmt.Sprintf("Error during rows iteration for user ID %d: %s", userID, err.Error()), models.User{
			ID:     userID,
			System: system,
		}, nil)
		return nil, fmt.Errorf("error during rows iteration for user ID %d: %w", userID, err)
	}

	LogEntry("GetUserPermissions in permissionService", "info", fmt.Sprintf("Permissions retrieved successfully for user ID %d", userID), models.User{
		ID:     userID,
		System: system,
	}, map[string]interface{}{
		"Permissions": permissions,
	})

	return permissions, nil
}

// EditUserPermissions updates the general permissions of a user
func EditUserPermissions(userID int, permissions []string) error {
	// Start a transaction
	tx, err := db.Begin()
	if err != nil {
		LogEntry("EditUserPermissions in permissionService", "error", fmt.Sprintf("Failed to start transaction for user ID %d: %s", userID, err.Error()), models.User{
			ID: userID,
		}, nil)
		return fmt.Errorf("failed to start transaction for user ID %d: %w", userID, err)
	}

	// Ensure rollback if anything goes wrong
	defer func() {
		if err != nil {
			tx.Rollback()
			LogEntry("EditUserPermissions in permissionService", "error", fmt.Sprintf("Transaction rolled back for user ID %d: %s", userID, err.Error()), models.User{
				ID: userID,
			}, nil)
		}
	}()

	// Delete existing permissions for the user
	sqlDelete := `DELETE FROM user_permissions WHERE user_id = $1`
	_, err = tx.Exec(sqlDelete, userID)
	if err != nil {
		LogEntry("EditUserPermissions in permissionService", "error", fmt.Sprintf("Failed to delete permissions for user ID %d: %s", userID, err.Error()), models.User{
			ID: userID,
		}, nil)
		return fmt.Errorf("failed to delete permissions for user ID %d: %w", userID, err)
	}

	// Batch insert new permissions
	sqlInsert := `
        INSERT INTO user_permissions (user_id, permission_id)
        SELECT $1, p.id FROM permissions p WHERE p.permission_name = $2
    `
	for _, permission := range permissions {
		_, err := tx.Exec(sqlInsert, userID, permission)
		if err != nil {
			LogEntry("EditUserPermissions in permissionService", "error", fmt.Sprintf("Failed to insert permission '%s' for user ID %d: %s", permission, userID, err.Error()), models.User{
				ID: userID,
			}, map[string]interface{}{
				"Permission": permission,
			})
			return fmt.Errorf("failed to insert permission '%s' for user ID %d: %w", permission, userID, err)
		}
	}

	// Commit the transaction
	err = tx.Commit()
	if err != nil {
		LogEntry("EditUserPermissions in permissionService", "error", fmt.Sprintf("Failed to commit transaction for user ID %d: %s", userID, err.Error()), models.User{
			ID: userID,
		}, nil)
		return fmt.Errorf("failed to commit transaction for user ID %d: %w", userID, err)
	}

	// Log the successful update of permissions
	LogEntry("EditUserPermissions in permissionService", "info", fmt.Sprintf("Permissions updated successfully for user ID %d", userID), models.User{
		ID: userID,
	}, map[string]interface{}{
		"Permissions": permissions,
	})

	return nil
}

// EditUserWardPermissions updates ward-specific permissions for a user
func EditUserWardPermissions(userID int, permissions []string, wards []int) error {
	// Start a transaction
	tx, err := db.Begin()
	if err != nil {
		LogEntry("EditUserWardPermissions in permissionService", "error", fmt.Sprintf("Failed to start transaction for user ID %d: %s", userID, err.Error()), models.User{
			ID: userID,
		}, nil)
		return fmt.Errorf("failed to start transaction for user ID %d: %w", userID, err)
	}

	// Ensure rollback if something goes wrong
	defer func() {
		if err != nil {
			tx.Rollback()
			LogEntry("EditUserWardPermissions in permissionService", "error", fmt.Sprintf("Transaction rolled back for user ID %d: %s", userID, err.Error()), models.User{
				ID: userID,
			}, nil)
		}
	}()

	// Delete existing ward permissions for the user
	sqlDelete := `DELETE FROM user_ward_permissions WHERE user_id = $1`
	_, err = tx.Exec(sqlDelete, userID)
	if err != nil {
		LogEntry("EditUserWardPermissions in permissionService", "error", fmt.Sprintf("Failed to delete ward permissions for user ID %d: %s", userID, err.Error()), models.User{
			ID: userID,
		}, nil)
		return fmt.Errorf("failed to delete ward permissions for user ID %d: %w", userID, err)
	}

	// Batch insert new ward-specific permissions
	sqlInsert := `
        INSERT INTO user_ward_permissions (user_id, ward_id, permission_id)
        SELECT $1, $2, p.id FROM permissions p WHERE p.permission_name = $3
    `
	for _, wardID := range wards {
		for _, permission := range permissions {
			_, err := tx.Exec(sqlInsert, userID, wardID, permission)
			if err != nil {
				LogEntry("EditUserWardPermissions in permissionService", "error",
					fmt.Sprintf("Failed to insert ward permission '%s' for ward ID %d and user ID %d: %s", permission, wardID, userID, err.Error()), models.User{
						ID: userID,
					}, map[string]interface{}{
						"WardID":     wardID,
						"Permission": permission,
					})
				return fmt.Errorf("failed to insert ward permission '%s' for ward ID %d and user ID %d: %w", permission, wardID, userID, err)
			}
		}
	}

	// Commit the transaction
	err = tx.Commit()
	if err != nil {
		LogEntry("EditUserWardPermissions in permissionService", "error", fmt.Sprintf("Failed to commit transaction for user ID %d: %s", userID, err.Error()), models.User{
			ID: userID,
		}, nil)
		return fmt.Errorf("failed to commit transaction for user ID %d: %w", userID, err)
	}

	// Log the successful update of ward permissions
	LogEntry("EditUserWardPermissions in permissionService", "info", fmt.Sprintf("Ward permissions updated successfully for user ID %d", userID), models.User{
		ID: userID,
	}, map[string]interface{}{
		"Permissions": permissions,
		"Wards":       wards,
	})

	return nil
}

// AssignWardsToUser assigns wards to a specific user
func AssignWardsToUser(userID int, wardIDs []int, system, hospital string) error {
	// Start a transaction
	tx, err := db.Begin()
	if err != nil {
		LogEntry("AssignWardsToUser in authService", "error", fmt.Sprintf("Failed to start transaction for user ID %d: %s", userID, err.Error()), models.User{
			ID: userID,
		}, nil)
		return fmt.Errorf("failed to start transaction for user ID %d: %w", userID, err)
	}

	defer func() {
		if err != nil {
			tx.Rollback()
			LogEntry("AssignWardsToUser in authService", "error", fmt.Sprintf("Transaction rolled back for user ID %d: %s", userID, err.Error()), models.User{
				ID: userID,
			}, nil)
		}
	}()

	// Insert each ward ID for the user
	sqlInsert := `
        INSERT INTO user_wards (user_id, ward_id, system, hospital)
        VALUES ($1, $2, $3, $4)
    `
	for _, wardID := range wardIDs {
		_, err = tx.Exec(sqlInsert, userID, wardID, system, hospital)
		if err != nil {
			LogEntry("AssignWardsToUser in authService", "error", fmt.Sprintf("Failed to assign ward ID %d to user ID %d: %s", wardID, userID, err.Error()), models.User{
				ID: userID,
			}, map[string]interface{}{
				"WardID": wardID,
			})
			return fmt.Errorf("failed to assign ward ID %d to user ID %d: %w", wardID, userID, err)
		}
	}

	// Commit the transaction
	err = tx.Commit()
	if err != nil {
		LogEntry("AssignWardsToUser in authService", "error", fmt.Sprintf("Failed to commit transaction for user ID %d: %s", userID, err.Error()), models.User{
			ID: userID,
		}, nil)
		return fmt.Errorf("failed to commit transaction for user ID %d: %w", userID, err)
	}

	// Log the successful assignment of wards
	LogEntry("AssignWardsToUser in authService", "info", fmt.Sprintf("Wards assigned successfully to user ID %d", userID), models.User{
		ID: userID,
	}, map[string]interface{}{
		"WardIDs": wardIDs,
	})

	return nil
}

// AssignPermissionsToUser assigns general permissions to a user
func AssignPermissionsToUser(userID int, permissions []string) error {
	// Start a transaction
	tx, err := db.Begin()
	if err != nil {
		LogEntry("AssignPermissionsToUser in permissionService", "error", fmt.Sprintf("Failed to start transaction for user ID %d: %s", userID, err.Error()), models.User{
			ID: userID,
		}, nil)
		return fmt.Errorf("failed to start transaction for user ID %d: %w", userID, err)
	}

	// Ensure rollback if something goes wrong
	defer func() {
		if err != nil {
			tx.Rollback()
			LogEntry("AssignPermissionsToUser in permissionService", "error", fmt.Sprintf("Transaction rolled back for user ID %d: %s", userID, err.Error()), models.User{
				ID: userID,
			}, nil)
		}
	}()

	// Insert permissions in batch
	sqlInsert := `
        INSERT INTO user_permissions (user_id, permission_id)
        SELECT $1, p.id FROM permissions p WHERE p.permission_name = $2
    `
	for _, permission := range permissions {
		_, err := tx.Exec(sqlInsert, userID, permission)
		if err != nil {
			LogEntry("AssignPermissionsToUser in permissionService", "error", fmt.Sprintf("Failed to insert permission '%s' for user ID %d: %s", permission, userID, err.Error()), models.User{
				ID: userID,
			}, map[string]interface{}{
				"Permission": permission,
			})
			return fmt.Errorf("failed to insert permission '%s' for user ID %d: %w", permission, userID, err)
		}
	}

	// Commit the transaction
	err = tx.Commit()
	if err != nil {
		LogEntry("AssignPermissionsToUser in permissionService", "error", fmt.Sprintf("Failed to commit transaction for user ID %d: %s", userID, err.Error()), models.User{
			ID: userID,
		}, nil)
		return fmt.Errorf("failed to commit transaction for user ID %d: %w", userID, err)
	}

	// Log the successful assignment of permissions
	LogEntry("AssignPermissionsToUser in permissionService", "info", fmt.Sprintf("Permissions assigned successfully to user ID %d", userID), models.User{
		ID: userID,
	}, map[string]interface{}{
		"Permissions": permissions,
	})

	return nil
}

// GetRolePermissions retrieves the permissions associated with a specific role
func GetRolePermissions(roleID int) ([]string, error) {
	// SQL query to retrieve role permissions
	sqlStatement := `
        SELECT p.permission_name
        FROM role_permissions rp
        JOIN permissions p ON rp.permission_id = p.id
        WHERE rp.role_id = $1
    `
	rows, err := db.Query(sqlStatement, roleID)
	if err != nil {
		LogEntry("GetRolePermissions in permissionService", "error", fmt.Sprintf("Error querying permissions for role ID %d: %s", roleID, err.Error()), models.User{
			RoleID: roleID,
		}, nil)
		return nil, fmt.Errorf("failed to query permissions for role ID %d: %w", roleID, err)
	}
	defer rows.Close()

	var permissions []string
	for rows.Next() {
		var permission string
		if err := rows.Scan(&permission); err != nil {
			LogEntry("GetRolePermissions in permissionService", "error", fmt.Sprintf("Error scanning permission for role ID %d: %s", roleID, err.Error()), models.User{
				RoleID: roleID,
			}, nil)
			return nil, fmt.Errorf("failed to scan permission for role ID %d: %w", roleID, err)
		}
		permissions = append(permissions, permission)
	}

	// Check if there were any errors while iterating over rows
	if err := rows.Err(); err != nil {
		LogEntry("GetRolePermissions in permissionService", "error", fmt.Sprintf("Error during rows iteration for role ID %d: %s", roleID, err.Error()), models.User{
			RoleID: roleID,
		}, nil)
		return nil, fmt.Errorf("error during rows iteration for role ID %d: %w", roleID, err)
	}

	// Log success
	LogEntry("GetRolePermissions in permissionService", "info", fmt.Sprintf("Permissions retrieved successfully for role ID %d", roleID), models.User{
		RoleID: roleID,
	}, map[string]interface{}{
		"Permissions": permissions,
	})

	return permissions, nil
}

// GetPermissionsBySystemAndHospital retrieves permissions for a specific system and hospital
func GetPermissionsBySystemAndHospital(system string, hospital string) ([]models.Permission, error) {
	sqlStatement := `
        SELECT id, permission_name, system, hospital
        FROM permissions
        WHERE system = $1 AND hospital = $2;
    `

	rows, err := db.Query(sqlStatement, system, hospital)
	if err != nil {
		LogEntry("GetPermissionsBySystemAndHospital in permissionsService", "error", fmt.Sprintf("Error querying permissions for system %s and hospital %s: %s", system, hospital, err.Error()), models.User{}, nil)
		return nil, fmt.Errorf("failed to query permissions for system %s and hospital %s: %w", system, hospital, err)
	}
	defer rows.Close()

	var permissions []models.Permission
	for rows.Next() {
		var permission models.Permission
		err := rows.Scan(&permission.ID, &permission.PermissionName, &permission.System, &permission.Hospital)
		if err != nil {
			LogEntry("GetPermissionsBySystemAndHospital in permissionsService", "error", fmt.Sprintf("Error scanning permission for system %s and hospital %s: %s", system, hospital, err.Error()), models.User{}, nil)
			return nil, fmt.Errorf("failed to scan permission for system %s and hospital %s: %w", system, hospital, err)
		}
		permissions = append(permissions, permission)
	}

	LogEntry("GetPermissionsBySystemAndHospital in permissionsService", "info", fmt.Sprintf("Permissions retrieved for system %s and hospital %s", system, hospital), models.User{}, map[string]interface{}{
		"Permissions": permissions,
	})

	return permissions, nil
}
