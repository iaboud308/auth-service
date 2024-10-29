package services

import (
	"auth-service/config"
	"auth-service/models"
	"fmt"
)

// GetUserPermissions retrieves the general permissions associated with a user
func GetUserPermissions(userID int, systemId int, tenantId int) ([]models.Permission, error) {
	// SQL query to fetch permissions for the user
	sqlStatement := `
        SELECT p.permission_name
        FROM user_permissions up
        JOIN permissions p ON up.permission_id = p.id
        WHERE up.user_id = $1
    `

	// Log the initial state
	LogEntry("GetUserPermissions", "info", "Fetching permissions for user", models.User{
		ID: userID,
	}, map[string]interface{}{
		"systemId": systemId,
		"tenantId": tenantId,
	})

	// Get database connection
	db, err := GetDBConnection(systemId, tenantId)
	if err != nil {
		LogEntry("GetUserPermissions", "error", fmt.Sprintf("Error getting database connection: %s", err.Error()), models.User{
			ID: userID,
		}, map[string]interface{}{
			"systemId": systemId,
			"tenantId": tenantId,
		})
		return nil, fmt.Errorf("failed to get database connection: %w", err)
	}

	var permissions []models.Permission
	var permission models.Permission

	// Use helper function to retrieve multiple rows
	rowCount, err := GetMultipleRows(db, sqlStatement, []interface{}{userID}, []interface{}{&permissions}, []interface{}{
		&permission.ID,
		&permission.PermissionName,
	}, models.LogInfo{
		Action:  "GetUserPermissions - Fetch",
		Message: fmt.Sprintf("Attempting to fetch permissions for user ID %d", userID),
		User: models.User{
			ID: userID,
		},
		AdditionalData: map[string]interface{}{
			"systemId": systemId,
			"tenantId": tenantId,
		},
	})

	// Error handling for the query
	if err != nil {
		LogEntry("GetUserPermissions", "error",
			fmt.Sprintf("Error querying permissions for user ID %d: %s", userID, err.Error()), models.User{
				ID: userID,
			}, map[string]interface{}{
				"systemId": systemId,
				"tenantId": tenantId,
			})
		return nil, fmt.Errorf("failed to query permissions for user ID %d: %w", userID, err)
	}

	// Handle case when no permissions are found
	if rowCount == 0 {
		LogEntry("GetUserPermissions", "warning", fmt.Sprintf("No permissions found for user ID %d", userID), models.User{
			ID: userID,
		}, map[string]interface{}{
			"systemId": systemId,
			"tenantId": tenantId,
		})
		return nil, fmt.Errorf("no permissions found for user ID %d", userID)
	}

	// Log the success case
	LogEntry("GetUserPermissions", "info", fmt.Sprintf("Permissions successfully retrieved for user ID %d", userID), models.User{
		ID: userID,
	}, map[string]interface{}{
		"permissions": permissions,
		"systemId":    systemId,
		"tenantId":    tenantId,
	})

	return permissions, nil
}

// CreatePermission adds a new permission to the system
func CreatePermission(permissionName string, systemId int, tenantId int) error {
	sqlStatement := `INSERT INTO permissions (permission_name) VALUES ($1)`

	db, err := GetDBConnection(systemId, tenantId) // Connect to the correct DB
	if err != nil {
		LogEntry("CreatePermission in permissionService", "error",
			fmt.Sprintf("Error getting database connection: %s", err.Error()), models.User{}, nil)
		return fmt.Errorf("failed to get database connection: %w", err)
	}

	rowCount, err := InsertRow(db, sqlStatement, []interface{}{permissionName}, models.LogInfo{
		Action:  "CreatePermission",
		Message: fmt.Sprintf("Creating permission '%s'", permissionName),
		User:    models.User{},
	})
	if err != nil {
		return fmt.Errorf("failed to create permission: %w", err)
	}

	if rowCount == 0 {
		return fmt.Errorf("failed to insert permission '%s'", permissionName)
	}

	LogEntry("CreatePermission in permissionService", "info",
		fmt.Sprintf("Permission '%s' created successfully", permissionName), models.User{}, nil)

	return nil
}

// EditPermission updates the name of an existing permission
func EditPermission(permissionID int, newPermissionName string, systemId int, tenantId int) error {
	sqlStatement := `UPDATE permissions SET permission_name = $1 WHERE id = $2`

	db, err := GetDBConnection(systemId, tenantId) // Correct DB for system/tenant
	if err != nil {
		LogEntry("EditPermission in permissionService", "error",
			fmt.Sprintf("Error getting database connection: %s", err.Error()), models.User{}, nil)
		return fmt.Errorf("failed to get database connection: %w", err)
	}

	rowCount, err := UpdateRow(db, sqlStatement, []interface{}{newPermissionName, permissionID}, models.LogInfo{
		Action:  "EditPermission",
		Message: fmt.Sprintf("Editing permission ID %d to '%s'", permissionID, newPermissionName),
		User:    models.User{},
	})
	if err != nil {
		return fmt.Errorf("failed to update permission: %w", err)
	}

	if rowCount == 0 {
		return fmt.Errorf("permission ID %d not found or no change detected", permissionID)
	}

	LogEntry("EditPermission in permissionService", "info",
		fmt.Sprintf("Permission ID %d updated to '%s'", permissionID, newPermissionName), models.User{}, nil)

	return nil
}

// GetPermissionById retrieves a permission by its ID
func GetPermissionById(permissionID int, systemId int, tenantId int) (*models.Permission, error) {
	sqlStatement := `SELECT id, permission_name FROM permissions WHERE id = $1`

	db, err := GetDBConnection(systemId, tenantId) // Use correct DB for system/tenant
	if err != nil {
		LogEntry("GetPermissionById in permissionService", "error",
			fmt.Sprintf("Error getting database connection: %s", err.Error()), models.User{}, nil)
		return nil, fmt.Errorf("failed to get database connection: %w", err)
	}

	var permission models.Permission
	rowCount, err := GetSingleRow(db, sqlStatement, []interface{}{permissionID}, []interface{}{&permission.ID, &permission.PermissionName}, models.LogInfo{
		Action:  "GetPermissionById",
		Message: fmt.Sprintf("Permission retrieved for ID %d", permissionID),
		User:    models.User{},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get permission: %w", err)
	}
	if rowCount == 0 {
		return nil, fmt.Errorf("permission ID %d not found", permissionID)
	}

	LogEntry("GetPermissionById in permissionService", "info",
		fmt.Sprintf("Permission ID %d retrieved successfully", permissionID), models.User{}, map[string]interface{}{
			"PermissionId": permissionID,
		})

	return &permission, nil
}

// GetPermissionByName retrieves a permission by its name
func GetPermissionByName(permissionName string, systemId int, tenantId int) (*models.Permission, error) {
	sqlStatement := `SELECT id, permission_name FROM permissions WHERE permission_name = $1`

	db, err := GetDBConnection(systemId, tenantId) // Correct DB for system/tenant
	if err != nil {
		LogEntry("GetPermissionByName in permissionService", "error",
			fmt.Sprintf("Error getting database connection: %s", err.Error()), models.User{}, nil)
		return nil, fmt.Errorf("failed to get database connection: %w", err)
	}

	var permission models.Permission
	rowCount, err := GetSingleRow(db, sqlStatement, []interface{}{permissionName}, []interface{}{&permission.ID, &permission.PermissionName}, models.LogInfo{
		Action:  "GetPermissionByName",
		Message: fmt.Sprintf("Permission retrieved for name '%s'", permissionName),
		User:    models.User{},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve permission: %w", err)
	}
	if rowCount == 0 {
		return nil, fmt.Errorf("permission '%s' not found", permissionName)
	}

	LogEntry("GetPermissionByName in permissionService", "info",
		fmt.Sprintf("Permission '%s' retrieved successfully", permissionName), models.User{}, map[string]interface{}{
			"PermissionName": permissionName,
		})

	return &permission, nil
}

// DeletePermission removes a permission by its ID
func DeletePermission(permissionID int, systemId int, tenantId int) error {
	sqlStatement := `DELETE FROM permissions WHERE id = $1`

	db, err := GetDBConnection(systemId, tenantId) // Connect to correct DB for system/tenant
	if err != nil {
		LogEntry("DeletePermission in permissionService", "error",
			fmt.Sprintf("Error getting database connection: %s", err.Error()), models.User{}, nil)
		return fmt.Errorf("failed to get database connection: %w", err)
	}

	rowCount, err := DeleteRow(db, sqlStatement, []interface{}{permissionID}, models.LogInfo{
		Action:  "DeletePermission",
		Message: fmt.Sprintf("Deleting permission ID %d", permissionID),
		User:    models.User{},
	})
	if err != nil {
		return fmt.Errorf("failed to delete permission: %w", err)
	}

	if rowCount == 0 {
		return fmt.Errorf("permission ID %d not found", permissionID)
	}

	LogEntry("DeletePermission in permissionService", "info",
		fmt.Sprintf("Permission ID %d deleted successfully", permissionID), models.User{}, nil)

	return nil
}

// EditUserPermissions updates the general permissions of a user
func EditUserPermissions(userID int, permissions []models.Permission, systemId int, tenantId int) error {
	// Log the initiation of permission update
	LogEntry("EditUserPermissions", "info", "Starting permission update for user", models.User{
		ID: userID,
	}, map[string]interface{}{
		"systemId":    systemId,
		"tenantId":    tenantId,
		"permissions": permissions,
	})

	// Get the database connection
	db, err := GetDBConnection(systemId, tenantId)
	if err != nil {
		LogEntry("EditUserPermissions", "error", fmt.Sprintf("Error getting database connection: %s", err.Error()), models.User{
			ID: userID,
		}, map[string]interface{}{
			"systemId": systemId,
			"tenantId": tenantId,
		})
		return fmt.Errorf("failed to get database connection: %w", err)
	}

	// Start a transaction
	tx, err := db.Begin()
	if err != nil {
		LogEntry("EditUserPermissions", "error", fmt.Sprintf("Failed to start transaction for user ID %d: %s", userID, err.Error()), models.User{
			ID: userID,
		}, map[string]interface{}{
			"systemId": systemId,
			"tenantId": tenantId,
		})
		return fmt.Errorf("failed to start transaction for user ID %d: %w", userID, err)
	}

	// Ensure rollback if something goes wrong
	defer func() {
		if p := recover(); p != nil || err != nil {
			tx.Rollback()
			LogEntry("EditUserPermissions", "error", fmt.Sprintf("Transaction rolled back for user ID %d", userID), models.User{
				ID: userID,
			}, map[string]interface{}{
				"systemId":    systemId,
				"tenantId":    tenantId,
				"permissions": permissions,
			})
		}
	}()

	// Delete existing permissions for the user
	sqlDelete := `DELETE FROM user_permissions WHERE user_id = $1`
	rowCount, err := DeleteRow(tx, sqlDelete, []interface{}{userID}, models.LogInfo{
		Action:  "EditUserPermissions - Delete",
		Message: fmt.Sprintf("Deleting old permissions for user ID %d", userID),
		User: models.User{
			ID: userID,
		},
		AdditionalData: map[string]interface{}{
			"systemId": systemId,
			"tenantId": tenantId,
		},
	})

	if err != nil {
		return fmt.Errorf("failed to delete permissions for user ID %d: %w", userID, err)
	}

	if rowCount == 0 {
		LogEntry("EditUserPermissions", "warning", fmt.Sprintf("No existing permissions found for user ID %d", userID), models.User{
			ID: userID,
		}, map[string]interface{}{
			"systemId": systemId,
			"tenantId": tenantId,
		})
	}

	// Insert new permissions for the user
	sqlInsert := `INSERT INTO user_permissions (user_id, permission_id) SELECT $1, p.id FROM permissions p WHERE p.permission_name = $2`
	for _, permission := range permissions {
		_, err = InsertRow(tx, sqlInsert, []interface{}{userID, permission.PermissionName}, models.LogInfo{
			Action:  "EditUserPermissions - Insert",
			Message: fmt.Sprintf("Inserting permission '%s' for user ID %d", permission.PermissionName, userID),
			User: models.User{
				ID: userID,
			},
			AdditionalData: map[string]interface{}{
				"permission": permission.PermissionName,
				"systemId":   systemId,
				"tenantId":   tenantId,
			},
		})

		if err != nil {
			return fmt.Errorf("failed to insert permission '%s' for user ID %d: %w", permission.PermissionName, userID, err)
		}
	}

	// Commit the transaction
	err = tx.Commit()
	if err != nil {
		LogEntry("EditUserPermissions", "error", fmt.Sprintf("Failed to commit transaction for user ID %d: %s", userID, err.Error()), models.User{
			ID: userID,
		}, map[string]interface{}{
			"systemId":    systemId,
			"tenantId":    tenantId,
			"permissions": permissions,
		})
		return fmt.Errorf("failed to commit transaction for user ID %d: %w", userID, err)
	}

	// Log the successful update of permissions
	LogEntry("EditUserPermissions", "info", fmt.Sprintf("Permissions updated successfully for user ID %d", userID), models.User{
		ID: userID,
	}, map[string]interface{}{
		"permissions": permissions,
		"systemId":    systemId,
		"tenantId":    tenantId,
	})

	return nil
}

// EditUserWardPermissions updates ward-specific permissions for a user
func EditUserWardPermissions(userID int, permissions []models.Permission, wards []int, systemId int, tenantId int) error {
	// Log the initiation of ward-specific permission update
	LogEntry("EditUserWardPermissions", "info", "Starting ward-specific permission update for user", models.User{
		ID: userID,
	}, map[string]interface{}{
		"systemId":    systemId,
		"tenantId":    tenantId,
		"permissions": permissions,
		"wards":       wards,
	})

	// Get the database connection
	db, err := GetDBConnection(systemId, tenantId)
	if err != nil {
		LogEntry("EditUserWardPermissions", "error", fmt.Sprintf("Error getting database connection: %s", err.Error()), models.User{
			ID: userID,
		}, map[string]interface{}{
			"systemId": systemId,
			"tenantId": tenantId,
			"wards":    wards,
		})
		return fmt.Errorf("failed to get database connection: %w", err)
	}

	// Start a transaction
	tx, err := db.Begin()
	if err != nil {
		LogEntry("EditUserWardPermissions", "error", fmt.Sprintf("Failed to start transaction for user ID %d: %s", userID, err.Error()), models.User{
			ID: userID,
		}, map[string]interface{}{
			"systemId": systemId,
			"tenantId": tenantId,
			"wards":    wards,
		})
		return fmt.Errorf("failed to start transaction for user ID %d: %w", userID, err)
	}

	// Ensure rollback if something goes wrong
	defer func() {
		if p := recover(); p != nil || err != nil {
			tx.Rollback()
			LogEntry("EditUserWardPermissions", "error", fmt.Sprintf("Transaction rolled back for user ID %d", userID), models.User{
				ID: userID,
			}, map[string]interface{}{
				"systemId":    systemId,
				"tenantId":    tenantId,
				"permissions": permissions,
				"wards":       wards,
			})
		}
	}()

	// Delete existing ward permissions for the user
	sqlDelete := `DELETE FROM user_ward_permissions WHERE user_id = $1`
	rowCount, err := DeleteRow(tx, sqlDelete, []interface{}{userID}, models.LogInfo{
		Action:  "EditUserWardPermissions - Delete",
		Message: fmt.Sprintf("Deleted old ward-specific permissions for user ID %d", userID),
		User: models.User{
			ID: userID,
		},
		AdditionalData: map[string]interface{}{
			"systemId": systemId,
			"tenantId": tenantId,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to delete ward-specific permissions for user ID %d: %w", userID, err)
	}

	// Insert new ward-specific permissions
	sqlInsert := `
        INSERT INTO user_ward_permissions (user_id, ward_id, permission_id)
        SELECT $1, $2, p.id FROM permissions p WHERE p.permission_name = $3
    `
	for _, wardID := range wards {
		for _, permission := range permissions {
			_, err = InsertRow(tx, sqlInsert, []interface{}{userID, wardID, permission.PermissionName}, models.LogInfo{
				Action:  "EditUserWardPermissions - Insert",
				Message: fmt.Sprintf("Inserting ward-specific permission '%s' for ward ID %d and user ID %d", permission.PermissionName, wardID, userID),
				User: models.User{
					ID: userID,
				},
				AdditionalData: map[string]interface{}{
					"wardID":     wardID,
					"permission": permission.PermissionName,
					"systemId":   systemId,
					"tenantId":   tenantId,
				},
			})
			if err != nil {
				return fmt.Errorf("failed to insert ward-specific permission '%s' for ward ID %d and user ID %d: %w", permission.PermissionName, wardID, userID, err)
			}
		}
	}

	// Commit the transaction
	err = tx.Commit()
	if err != nil {
		LogEntry("EditUserWardPermissions", "error", fmt.Sprintf("Failed to commit transaction for user ID %d: %s", userID, err.Error()), models.User{
			ID: userID,
		}, map[string]interface{}{
			"systemId":    systemId,
			"tenantId":    tenantId,
			"permissions": permissions,
			"wards":       wards,
		})
		return fmt.Errorf("failed to commit transaction for user ID %d: %w", userID, err)
	}

	if rowCount == 0 {
		LogEntry("EditUserWardPermissions", "warning", fmt.Sprintf("No ward-specific permissions found for user ID %d", userID), models.User{
			ID: userID,
		}, map[string]interface{}{
			"systemId":    systemId,
			"tenantId":    tenantId,
			"permissions": permissions,
			"wards":       wards,
		})
	}

	// Log the successful update of ward-specific permissions
	LogEntry("EditUserWardPermissions", "info", fmt.Sprintf("Ward-specific permissions updated successfully for user ID %d", userID), models.User{
		ID: userID,
	}, map[string]interface{}{
		"permissions": permissions,
		"wards":       wards,
		"systemId":    systemId,
		"tenantId":    tenantId,
	})

	return nil
}

// AssignWardsToUser assigns wards to a specific user
func AssignWardsToUser(userID int, wardIDs []int, systemId int, tenantId int) error {
	// Log the initiation of ward assignment
	LogEntry("AssignWardsToUser", "info", "Starting ward assignment for user", models.User{
		ID: userID,
	}, map[string]interface{}{
		"systemId": systemId,
		"tenantId": tenantId,
		"wardIDs":  wardIDs,
	})

	// Get the database connection
	db, err := GetDBConnection(systemId, tenantId)
	if err != nil {
		LogEntry("AssignWardsToUser", "error", fmt.Sprintf("Error getting database connection: %s", err.Error()), models.User{
			ID: userID,
		}, map[string]interface{}{
			"systemId": systemId,
			"tenantId": tenantId,
			"wardIDs":  wardIDs,
		})
		return fmt.Errorf("failed to get database connection: %w", err)
	}

	// Start a transaction
	tx, err := db.Begin()
	if err != nil {
		LogEntry("AssignWardsToUser", "error", fmt.Sprintf("Failed to start transaction for user ID %d: %s", userID, err.Error()), models.User{
			ID: userID,
		}, map[string]interface{}{
			"systemId": systemId,
			"tenantId": tenantId,
			"wardIDs":  wardIDs,
		})
		return fmt.Errorf("failed to start transaction for user ID %d: %w", userID, err)
	}

	// Ensure rollback if something goes wrong
	defer func() {
		if p := recover(); p != nil || err != nil {
			tx.Rollback()
			LogEntry("AssignWardsToUser", "error", fmt.Sprintf("Transaction rolled back for user ID %d", userID), models.User{
				ID: userID,
			}, map[string]interface{}{
				"systemId": systemId,
				"tenantId": tenantId,
				"wardIDs":  wardIDs,
			})
		}
	}()

	// Insert each ward ID for the user
	sqlInsert := `
        INSERT INTO user_wards (user_id, ward_id)
        VALUES ($1, $2)
    `
	for _, wardID := range wardIDs {
		_, err = InsertRow(tx, sqlInsert, []interface{}{userID, wardID}, models.LogInfo{
			Action:  "AssignWardsToUser - Insert",
			Message: fmt.Sprintf("Assigning ward ID %d to user ID %d", wardID, userID),
			User: models.User{
				ID: userID,
			},
			AdditionalData: map[string]interface{}{
				"wardID":   wardID,
				"systemId": systemId,
				"tenantId": tenantId,
			},
		})
		if err != nil {
			LogEntry("AssignWardsToUser", "error", fmt.Sprintf("Failed to assign ward ID %d to user ID %d: %s", wardID, userID, err.Error()), models.User{
				ID: userID,
			}, map[string]interface{}{
				"wardID":   wardID,
				"systemId": systemId,
				"tenantId": tenantId,
			})
			return fmt.Errorf("failed to assign ward ID %d to user ID %d: %w", wardID, userID, err)
		}
	}

	// Commit the transaction
	err = tx.Commit()
	if err != nil {
		LogEntry("AssignWardsToUser", "error", fmt.Sprintf("Failed to commit transaction for user ID %d: %s", userID, err.Error()), models.User{
			ID: userID,
		}, map[string]interface{}{
			"systemId": systemId,
			"tenantId": tenantId,
			"wardIDs":  wardIDs,
		})
		return fmt.Errorf("failed to commit transaction for user ID %d: %w", userID, err)
	}

	// Log the successful assignment of wards
	LogEntry("AssignWardsToUser", "info", fmt.Sprintf("Wards assigned successfully to user ID %d", userID), models.User{
		ID: userID,
	}, map[string]interface{}{
		"wardIDs":  wardIDs,
		"systemId": systemId,
		"tenantId": tenantId,
	})

	return nil
}

// AssignPermissionsToUser assigns general permissions to a user
func AssignPermissionsToUser(userID int, permissions []models.Permission, systemId int, tenantId int) error {
	// Log the initiation of permission assignment
	LogEntry("AssignPermissionsToUser", "info", "Starting permission assignment for user", models.User{
		ID: userID,
	}, map[string]interface{}{
		"systemId":    systemId,
		"tenantId":    tenantId,
		"permissions": permissions,
	})

	// Get the database connection
	db, err := GetDBConnection(systemId, tenantId)
	if err != nil {
		LogEntry("AssignPermissionsToUser", "error", fmt.Sprintf("Failed to get database connection: %s", err.Error()), models.User{
			ID: userID,
		}, map[string]interface{}{
			"systemId":    systemId,
			"tenantId":    tenantId,
			"permissions": permissions,
		})
		return fmt.Errorf("failed to get database connection: %w", err)
	}

	// Start a transaction
	tx, err := db.Begin()
	if err != nil {
		LogEntry("AssignPermissionsToUser", "error", fmt.Sprintf("Failed to start transaction for user ID %d: %s", userID, err.Error()), models.User{
			ID: userID,
		}, map[string]interface{}{
			"systemId":    systemId,
			"tenantId":    tenantId,
			"permissions": permissions,
		})
		return fmt.Errorf("failed to start transaction for user ID %d: %w", userID, err)
	}

	// Ensure rollback if something goes wrong
	defer func() {
		if p := recover(); p != nil || err != nil {
			tx.Rollback()
			LogEntry("AssignPermissionsToUser", "error", fmt.Sprintf("Transaction rolled back for user ID %d", userID), models.User{
				ID: userID,
			}, map[string]interface{}{
				"systemId":    systemId,
				"tenantId":    tenantId,
				"permissions": permissions,
			})
		}
	}()

	// Insert permissions in batch
	sqlInsert := `
        INSERT INTO user_permissions (user_id, permission_id)
        SELECT $1, p.id FROM permissions p WHERE p.permission_name = $2
    `
	for _, permission := range permissions {
		_, err = InsertRow(tx, sqlInsert, []interface{}{userID, permission.PermissionName}, models.LogInfo{
			Action:  "AssignPermissionsToUser - Insert",
			Message: fmt.Sprintf("Assigning permission '%s' to user ID %d", permission.PermissionName, userID),
			User: models.User{
				ID: userID,
			},
			AdditionalData: map[string]interface{}{
				"permission": permission,
				"systemId":   systemId,
				"tenantId":   tenantId,
			},
		})
		if err != nil {
			LogEntry("AssignPermissionsToUser", "error", fmt.Sprintf("Failed to insert permission '%s' for user ID %d: %s", permission.PermissionName, userID, err.Error()), models.User{
				ID: userID,
			}, map[string]interface{}{
				"permission": permission,
				"systemId":   systemId,
				"tenantId":   tenantId,
			})
			return fmt.Errorf("failed to insert permission '%s' for user ID %d: %w", permission.PermissionName, userID, err)
		}
	}

	// Commit the transaction
	err = tx.Commit()
	if err != nil {
		LogEntry("AssignPermissionsToUser", "error", fmt.Sprintf("Failed to commit transaction for user ID %d: %s", userID, err.Error()), models.User{
			ID: userID,
		}, map[string]interface{}{
			"systemId":    systemId,
			"tenantId":    tenantId,
			"permissions": permissions,
		})
		return fmt.Errorf("failed to commit transaction for user ID %d: %w", userID, err)
	}

	// Log the successful assignment of permissions
	LogEntry("AssignPermissionsToUser", "info", fmt.Sprintf("Permissions assigned successfully to user ID %d", userID), models.User{
		ID: userID,
	}, map[string]interface{}{
		"permissions": permissions,
		"systemId":    systemId,
		"tenantId":    tenantId,
	})

	return nil
}

// GetRolePermissions retrieves the permissions associated with a specific role
func GetRolePermissions(roleID int, systemId int, tenantId int) ([]models.Permission, error) {
	// Log the start of the operation
	LogEntry("GetRolePermissions", "info", fmt.Sprintf("Retrieving permissions for role ID %d", roleID), models.User{}, map[string]interface{}{
		"systemId": systemId,
		"tenantId": tenantId,
		"roleID":   roleID,
	})

	// SQL query to retrieve role permissions
	sqlStatement := `
        SELECT p.id, p.permission_name
        FROM role_permissions rp
        JOIN permissions p ON rp.permission_id = p.id
        WHERE rp.role_id = $1
    `

	// Get the database connection
	db, err := GetDBConnection(systemId, tenantId)
	if err != nil {
		LogEntry("GetRolePermissions", "error", fmt.Sprintf("Error getting database connection: %s", err.Error()), models.User{}, map[string]interface{}{
			"systemId": systemId,
			"tenantId": tenantId,
			"roleID":   roleID,
		})
		return nil, fmt.Errorf("failed to get database connection: %w", err)
	}

	// Execute the query and fetch the permissions
	var permissions []models.Permission
	var permission models.Permission

	rowCount, err := GetMultipleRows(db, sqlStatement, []interface{}{roleID}, []interface{}{&permissions}, []interface{}{
		&permission.ID,
		&permission.PermissionName,
	}, models.LogInfo{
		Action:  "GetRolePermissions",
		Message: fmt.Sprintf("Permissions retrieved for role ID %d", roleID),
		AdditionalData: map[string]interface{}{
			"systemId": systemId,
			"tenantId": tenantId,
			"roleID":   roleID,
		},
	})

	if err != nil {
		LogEntry("GetRolePermissions", "error", fmt.Sprintf("Error querying permissions for role ID %d: %s", roleID, err.Error()), models.User{}, map[string]interface{}{
			"systemId": systemId,
			"tenantId": tenantId,
			"roleID":   roleID,
		})
		return nil, fmt.Errorf("failed to query permissions for role ID %d: %w", roleID, err)
	}

	// Handle case where no permissions are found
	if rowCount == 0 {
		LogEntry("GetRolePermissions", "info", fmt.Sprintf("No permissions found for role ID %d", roleID), models.User{}, map[string]interface{}{
			"systemId": systemId,
			"tenantId": tenantId,
			"roleID":   roleID,
		})
		return nil, fmt.Errorf("no permissions found for role ID %d", roleID)
	}

	// Log the successful retrieval
	LogEntry("GetRolePermissions", "info", fmt.Sprintf("Permissions successfully retrieved for role ID %d", roleID), models.User{}, map[string]interface{}{
		"systemId":    systemId,
		"tenantId":    tenantId,
		"roleID":      roleID,
		"permissions": permissions,
	})

	return permissions, nil
}

// GetPermissions retrieves permissions for a specific system and tenant
func GetPermissions(systemId int, tenantId int) ([]models.Permission, error) {
	sqlStatement := `
        SELECT id, permission_name
        FROM permissions;
    `

	// Get the database connection
	db, err := GetDBConnection(systemId, tenantId)
	if err != nil {
		LogEntry("GetPermissions in permissionsService", "error",
			fmt.Sprintf("Error getting database connection: %s", err.Error()),
			models.User{}, map[string]interface{}{
				"System": config.SystemsList[systemId].SystemCode,
				"Tenant": config.TenantsList[tenantId].TenantCode,
			})
		return nil, fmt.Errorf("failed to get database connection: %w", err)
	}

	// Use helper function to get multiple rows
	var permissions []models.Permission
	var permission models.Permission
	rowCount, err := GetMultipleRows(db, sqlStatement, nil, []interface{}{&permissions}, []interface{}{
		&permission.ID,
		&permission.PermissionName,
	}, models.LogInfo{
		Action:  "GetPermissions",
		Message: fmt.Sprintf("Retrieved permissions for system %s and tenant %s", config.SystemsList[systemId].SystemCode, config.TenantsList[tenantId].TenantCode),
		User:    models.User{},
	})

	if err != nil {
		LogEntry("GetPermissions in permissionsService", "error",
			fmt.Sprintf("Error querying permissions for system %s and tenant %s: %s", config.SystemsList[systemId].SystemCode, config.TenantsList[tenantId].TenantCode, err.Error()), models.User{},
			map[string]interface{}{
				"System": config.SystemsList[systemId].SystemCode,
				"Tenant": config.TenantsList[tenantId].TenantCode,
			})
		return nil, fmt.Errorf("failed to query permissions for system %s and tenant %s: %w", config.SystemsList[systemId].SystemCode, config.TenantsList[tenantId].TenantCode, err)
	}

	// Handle case when no rows are found
	if rowCount == 0 {
		LogEntry("GetPermissions in permissionsService", "info",
			fmt.Sprintf("No permissions found for system %s and tenant %s", config.SystemsList[systemId].SystemCode, config.TenantsList[tenantId].TenantCode),
			models.User{}, map[string]interface{}{
				"System": config.SystemsList[systemId].SystemCode,
				"Tenant": config.TenantsList[tenantId].TenantCode,
			})
		return nil, fmt.Errorf("no permissions found for system %s and tenant %s", config.SystemsList[systemId].SystemCode, config.TenantsList[tenantId].TenantCode)
	}

	// Log success
	LogEntry("GetPermissions in permissionsService", "info",
		fmt.Sprintf("Permissions retrieved successfully for system %s and tenant %s", config.SystemsList[systemId].SystemCode, config.TenantsList[tenantId].TenantCode),
		models.User{}, map[string]interface{}{
			"Permissions": permissions,
			"System":      config.SystemsList[systemId].SystemCode,
			"Tenant":      config.TenantsList[tenantId].TenantCode,
		})

	return permissions, nil
}

// GetUserWards retrieves the wards assigned to a specific user
func GetUserWards(userID int, systemId int, tenantId int) ([]models.UserWard, error) {
	// SQL query to retrieve wards assigned to the user
	sqlStatement := `
		SELECT ward_id
		FROM user_wards
		WHERE user_id = $1
	`

	// Get the database connection
	db, err := GetDBConnection(systemId, tenantId)
	if err != nil {
		LogEntry("GetWardsForUser", "error", fmt.Sprintf("Failed to get database connection: %s", err.Error()), models.User{
			ID: userID,
		}, map[string]interface{}{
			"SystemId": systemId,
			"TenantId": tenantId,
			"UserId":   userID,
		})
		return nil, fmt.Errorf("failed to get database connection: %w", err)
	}

	// Execute the SQL query
	var wards []models.UserWard
	var ward models.UserWard
	rowCount, err := GetMultipleRows(db, sqlStatement, []interface{}{userID}, []interface{}{&wards}, []interface{}{
		&ward.ID,
	}, models.LogInfo{
		Action:  "GetWardsForUser",
		Message: fmt.Sprintf("Wards retrieved successfully for user ID %d", userID),
		User: models.User{
			ID: userID,
		},
	})
	if err != nil {
		LogEntry("GetWardsForUser", "error", fmt.Sprintf("Failed to retrieve wards for user ID %d: %s", userID, err.Error()), models.User{
			ID: userID,
		}, map[string]interface{}{
			"SystemId": systemId,
			"TenantId": tenantId,
			"UserId":   userID,
		})
		return nil, fmt.Errorf("failed to retrieve wards for user ID %d: %w", userID, err)
	}

	// Handle case where no rows are found
	if rowCount == 0 {
		LogEntry("GetWardsForUser", "info", fmt.Sprintf("No wards found for user ID %d", userID), models.User{
			ID: userID,
		}, map[string]interface{}{
			"SystemId": systemId,
			"TenantId": tenantId,
			"UserId":   userID,
		})
		return nil, fmt.Errorf("no wards found for user ID %d", userID)
	}

	// Log success
	LogEntry("GetWardsForUser", "info", fmt.Sprintf("Wards retrieved successfully for user ID %d", userID), models.User{
		ID: userID,
	}, map[string]interface{}{
		"Wards":    wards,
		"SystemId": systemId,
		"TenantId": tenantId,
		"UserId":   userID,
	})

	return wards, nil
}

// EditUserWards updates the wards assigned to a user
func EditUserWards(userID int, wards []int, systemId int, tenantId int) error {
	// Get the database connection
	db, err := GetDBConnection(systemId, tenantId)
	if err != nil {
		LogEntry("EditUserWards", "error", fmt.Sprintf("Failed to get database connection: %s", err.Error()), models.User{
			ID: userID,
		}, map[string]interface{}{
			"SystemId": systemId,
			"TenantId": tenantId,
			"UserId":   userID,
			"Wards":    wards,
		})
		return fmt.Errorf("failed to get database connection: %w", err)
	}

	// Start a transaction
	tx, err := db.Begin()
	if err != nil {
		LogEntry("EditUserWards", "error", fmt.Sprintf("Failed to start transaction for user ID %d: %s", userID, err.Error()), models.User{
			ID: userID,
		}, map[string]interface{}{
			"SystemId": systemId,
			"TenantId": tenantId,
			"UserId":   userID,
			"Wards":    wards,
		})
		return fmt.Errorf("failed to start transaction for user ID %d: %w", userID, err)
	}

	// Ensure rollback if something goes wrong
	defer func() {
		if p := recover(); p != nil || err != nil {
			tx.Rollback()
			LogEntry("EditUserWards", "error", fmt.Sprintf("Transaction rolled back for user ID %d", userID), models.User{
				ID: userID,
			}, map[string]interface{}{
				"SystemId": systemId,
				"TenantId": tenantId,
				"UserId":   userID,
				"Wards":    wards,
			})
		}
	}()

	// Delete existing wards for the user
	sqlDelete := `DELETE FROM user_wards WHERE user_id = $1`
	rowCount, err := DeleteRow(tx, sqlDelete, []interface{}{userID}, models.LogInfo{
		Action:  "EditUserWards - Delete",
		Message: fmt.Sprintf("Deleted existing wards for user ID %d", userID),
		User: models.User{
			ID: userID,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to delete existing wards for user ID %d: %w", userID, err)
	}

	// Handle case when no rows are found to delete
	if rowCount == 0 {
		LogEntry("EditUserWards", "info", fmt.Sprintf("No existing wards found to delete for user ID %d", userID), models.User{
			ID: userID,
		}, map[string]interface{}{
			"SystemId": systemId,
			"TenantId": tenantId,
			"UserId":   userID,
			"Wards":    wards,
		})
	}

	// Insert new wards for the user
	sqlInsert := `INSERT INTO user_wards (user_id, ward_id) VALUES ($1, $2)`
	for _, wardID := range wards {
		_, err = InsertRow(tx, sqlInsert, []interface{}{userID, wardID}, models.LogInfo{
			Action:  "EditUserWards - Insert",
			Message: fmt.Sprintf("Assigned ward ID %d to user ID %d", wardID, userID),
			User: models.User{
				ID: userID,
			},
		})
		if err != nil {
			return fmt.Errorf("failed to assign ward ID %d to user ID %d: %w", wardID, userID, err)
		}
	}

	// Commit the transaction
	err = tx.Commit()
	if err != nil {
		LogEntry("EditUserWards", "error", fmt.Sprintf("Failed to commit transaction for user ID %d: %s", userID, err.Error()), models.User{
			ID: userID,
		}, map[string]interface{}{
			"SystemId": systemId,
			"TenantId": tenantId,
			"UserId":   userID,
			"Wards":    wards,
		})
		return fmt.Errorf("failed to commit transaction for user ID %d: %w", userID, err)
	}

	// Log successful update of wards
	LogEntry("EditUserWards", "info", fmt.Sprintf("Wards updated successfully for user ID %d", userID), models.User{
		ID: userID,
	}, map[string]interface{}{
		"SystemId": systemId,
		"TenantId": tenantId,
		"UserId":   userID,
		"Wards":    wards,
	})

	return nil
}

// func GetUserWardPermissions(userID int, systemId int, tenantId int) ([]models.UserWardPermissions, error) {

// 	var sqlStatement = `
// 		SELECT user_id, ward_id, permission_id
// 		FROM user_wards_permissions
// 		WHERE user_id = $1
// 	`

// 	db, err := GetDBConnection(systemId, tenantId)
// 	if err != nil {
// 		LogEntry("GetUserWardPermissions", "error", fmt.Sprintf("Failed to get database connection: %s", err.Error()), models.User{
// 			ID: userID,
// 		}, map[string]interface{}{
// 			"SystemId": systemId,
// 			"TenantId": tenantId,
// 			"UserId":   userID,
// 		})
// 		return nil, fmt.Errorf("failed to get database connection: %w", err)
// 	}

// 	var userWardPermissions []models.UserWardPermissions
// 	rowCount, err := GetMultipleRows(db, sqlStatement, []interface{}{userID}, []interface{}{&userWardPermissions}, models.LogInfo{
// 		Action:  "GetUserWardPermissions",
// 		Message: fmt.Sprintf("Retrieved permissions for user ID %d", userID),
// 		User: models.User{
// 			ID: userID,
// 		},
// 	})
// 	if err != nil {
// 		LogEntry("GetUserWardPermissions", "error", fmt.Sprintf("Failed to get permissions for user ID %d: %s", userID, err.Error()), models.User{
// 			ID: userID,
// 		}, map[string]interface{}{
// 			"SystemId": systemId,
// 			"TenantId": tenantId,
// 			"UserId":   userID,
// 		})
// 		return nil, fmt.Errorf("failed to get permissions for user ID %d: %w", userID, err)
// 	}

// 	if rowCount == 0 {
// 		LogEntry("GetUserWardPermissions", "info", fmt.Sprintf("No permissions found for user ID %d", userID), models.User{
// 			ID: userID,
// 		}, map[string]interface{}{
// 			"SystemId": systemId,
// 			"TenantId": tenantId,
// 			"UserId":   userID,
// 		})
// 		return nil, nil
// 	}

// 	LogEntry("GetUserWardPermissions", "info",
// 		fmt.Sprintf("UserWardPermissions retrieved successfully for user ID %d", userID), models.User{
// 			ID: userID,
// 		}, map[string]interface{}{
// 			"SystemId": systemId,
// 			"TenantId": tenantId,
// 			"UserId":   userID,
// 		})

// 	// Get user ward permissions
// 	return userWardPermissions, nil
// }
