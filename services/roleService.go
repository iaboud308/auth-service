package services

import (
	"auth-service/config"
	"auth-service/models"
	"fmt"
)

// GetUserRole retrieves the role associated with the user’s role ID
func GetUserRole(roleID int, systemId int, tenantId int) (*models.Role, error) {
	sqlStatement := `SELECT id, role_name FROM roles WHERE id = $1`
	db, err := GetDBConnection(systemId, tenantId)
	if err != nil {
		LogEntry("GetUserRole in roleService", "error",
			fmt.Sprintf("Error getting database connection: %s", err.Error()),
			models.User{
				RoleID: roleID,
			}, map[string]interface{}{
				"System": config.SystemsList[systemId].SystemCode,
				"Tenant": config.TenantsList[tenantId].TenantCode,
			})
		return nil, fmt.Errorf("failed to get database connection: %w", err)
	}

	var role models.Role
	rowCount, err := GetSingleRow(db, sqlStatement, []interface{}{roleID}, []interface{}{&role.ID, &role.RoleName}, models.LogInfo{
		Action:  "GetUserRole",
		Message: fmt.Sprintf("Retrieving role for role ID %d", roleID),
		User: models.User{
			RoleID: roleID,
		},
		AdditionalData: map[string]interface{}{
			"System": config.SystemsList[systemId].SystemCode,
			"Tenant": config.TenantsList[tenantId].TenantCode,
		},
	})

	if err != nil {
		LogEntry("GetUserRole in roleService", "error",
			fmt.Sprintf("Error querying role for role ID %d: %s", roleID, err.Error()),
			models.User{
				RoleID: roleID,
			}, map[string]interface{}{
				"System": config.SystemsList[systemId].SystemCode,
				"Tenant": config.TenantsList[tenantId].TenantCode,
			})
		return nil, fmt.Errorf("failed to query role for role ID %d: %w", roleID, err)
	}

	if rowCount == 0 {
		LogEntry("GetUserRole in roleService", "error",
			fmt.Sprintf("No role found for role ID %d", roleID),
			models.User{
				RoleID: roleID,
			}, map[string]interface{}{
				"System": config.SystemsList[systemId].SystemCode,
				"Tenant": config.TenantsList[tenantId].TenantCode,
			})
		return nil, fmt.Errorf("no role found for role ID %d", roleID)
	}

	LogEntry("GetUserRole in roleService", "info",
		fmt.Sprintf("Role retrieved successfully for role ID %d", roleID),
		models.User{
			RoleID: roleID,
		}, map[string]interface{}{
			"Role":   role,
			"System": config.SystemsList[systemId].SystemCode,
			"Tenant": config.TenantsList[tenantId].TenantCode,
		})

	return &role, nil
}

// GetRoleById retrieves a role by its ID for a specific system and tenant
func GetRoleById(roleID int, systemId int, tenantId int) (*models.Role, error) {
	sqlStatement := `SELECT id, role_name FROM roles WHERE id = $1`

	db, err := GetDBConnection(systemId, tenantId)
	if err != nil {
		LogEntry("GetRoleById in roleService", "error",
			fmt.Sprintf("Error getting database connection: %s", err.Error()), models.User{}, nil)
		return nil, fmt.Errorf("failed to get database connection: %w", err)
	}

	var role models.Role
	rowCount, err := GetSingleRow(db, sqlStatement, []interface{}{roleID}, []interface{}{&role.ID, &role.RoleName}, models.LogInfo{
		Action:  "GetRoleById",
		Message: fmt.Sprintf("Role retrieved for ID %d", roleID),
		User:    models.User{},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get role: %w", err)
	}
	if rowCount == 0 {
		return nil, fmt.Errorf("role ID %d not found", roleID)
	}

	LogEntry("GetRoleById in roleService", "info",
		fmt.Sprintf("Role ID %d retrieved successfully", roleID), models.User{}, map[string]interface{}{
			"RoleId": roleID,
		})

	return &role, nil
}

// CreateRole adds a new role for a specific system and tenant
func CreateRole(roleName string, systemId int, tenantId int) error {
	sqlStatement := `INSERT INTO roles (role_name) VALUES ($1)`

	db, err := GetDBConnection(systemId, tenantId)
	if err != nil {
		LogEntry("CreateRole in roleService", "error",
			fmt.Sprintf("Error getting database connection: %s", err.Error()), models.User{}, nil)
		return fmt.Errorf("failed to get database connection: %w", err)
	}

	rowCount, err := InsertRow(db, sqlStatement, []interface{}{roleName}, models.LogInfo{
		Action:  "CreateRole",
		Message: fmt.Sprintf("Creating role '%s' for system %d and tenant %d", roleName, systemId, tenantId),
		User:    models.User{},
	})
	if err != nil {
		return fmt.Errorf("failed to create role: %w", err)
	}

	if rowCount == 0 {
		return fmt.Errorf("failed to insert role '%s'", roleName)
	}

	LogEntry("CreateRole in roleService", "info",
		fmt.Sprintf("Role '%s' created successfully for system %d and tenant %d", roleName, systemId, tenantId), models.User{}, nil)

	return nil
}

// EditRole updates an existing role's name for a specific system and tenant
func EditRole(roleID int, newRoleName string, systemId int, tenantId int) error {
	sqlStatement := `UPDATE roles SET role_name = $1 WHERE id = $2`

	db, err := GetDBConnection(systemId, tenantId)
	if err != nil {
		LogEntry("EditRole in roleService", "error",
			fmt.Sprintf("Error getting database connection: %s", err.Error()), models.User{}, nil)
		return fmt.Errorf("failed to get database connection: %w", err)
	}

	rowCount, err := UpdateRow(db, sqlStatement, []interface{}{newRoleName, roleID}, models.LogInfo{
		Action:  "EditRole",
		Message: fmt.Sprintf("Editing role ID %d to '%s' for system %d and tenant %d", roleID, newRoleName, systemId, tenantId),
		User:    models.User{},
	})
	if err != nil {
		return fmt.Errorf("failed to update role: %w", err)
	}

	if rowCount == 0 {
		return fmt.Errorf("role ID %d not found or no change detected", roleID)
	}

	LogEntry("EditRole in roleService", "info",
		fmt.Sprintf("Role ID %d updated to '%s' for system %d and tenant %d", roleID, newRoleName, systemId, tenantId), models.User{}, nil)

	return nil
}

// GetRoleByName retrieves a role by its name for a specific system and tenant
func GetRoleByName(roleName string, systemId int, tenantId int) (*models.Role, error) {
	sqlStatement := `SELECT id, role_name FROM roles WHERE role_name = $1`

	db, err := GetDBConnection(systemId, tenantId)
	if err != nil {
		LogEntry("GetRoleByName in roleService", "error",
			fmt.Sprintf("Error getting database connection: %s", err.Error()), models.User{}, nil)
		return nil, fmt.Errorf("failed to get database connection: %w", err)
	}

	var role models.Role
	rowCount, err := GetSingleRow(db, sqlStatement, []interface{}{roleName}, []interface{}{&role.ID, &role.RoleName}, models.LogInfo{
		Action:  "GetRoleByName",
		Message: fmt.Sprintf("Role retrieved for name '%s'", roleName),
		User:    models.User{},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve role: %w", err)
	}
	if rowCount == 0 {
		return nil, fmt.Errorf("role '%s' not found", roleName)
	}

	LogEntry("GetRoleByName in roleService", "info",
		fmt.Sprintf("Role '%s' retrieved successfully", roleName), models.User{}, map[string]interface{}{
			"RoleName": roleName,
		})

	return &role, nil
}

// EditUserRole updates a user's role by assigning a new role ID
func EditUserRole(userID int, roleID int, systemId int, tenantId int) error {
	sqlStatement := `UPDATE users SET role_id = $1 WHERE id = $2`
	db, err := GetDBConnection(systemId, tenantId)
	if err != nil {
		LogEntry("EditUserRole in roleService", "error",
			fmt.Sprintf("Error getting database connection: %s", err.Error()),
			models.User{
				ID: userID,
			}, map[string]interface{}{
				"RoleID": roleID,
				"System": config.SystemsList[systemId].SystemCode,
				"Tenant": config.TenantsList[tenantId].TenantCode,
			})
		return fmt.Errorf("failed to get database connection: %w", err)
	}

	// Use the UpdateRow helper function to execute the update
	rowCount, err := UpdateRow(db, sqlStatement, []interface{}{roleID, userID}, models.LogInfo{
		Action:  "EditUserRole",
		Message: fmt.Sprintf("Updating role for user ID %d to role ID %d", userID, roleID),
		User: models.User{
			ID: userID,
		},
		AdditionalData: map[string]interface{}{
			"RoleID": roleID,
			"System": config.SystemsList[systemId].SystemCode,
			"Tenant": config.TenantsList[tenantId].TenantCode,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to update role for user ID %d: %w", userID, err)
	}

	if rowCount == 0 {
		LogEntry("EditUserRole in roleService", "error",
			fmt.Sprintf("No rows were updated for user ID %d and role ID %d", userID, roleID),
			models.User{
				ID: userID,
			}, map[string]interface{}{
				"RoleID": roleID,
				"System": config.SystemsList[systemId].SystemCode,
				"Tenant": config.TenantsList[tenantId].TenantCode,
			})
		return fmt.Errorf("no rows were updated for user ID %d", userID)
	}

	// Optionally, assign default permissions based on the new role
	err = AssignDefaultPermissionsToRole(userID, roleID, systemId, tenantId)
	if err != nil {
		LogEntry("EditUserRole in roleService", "error",
			fmt.Sprintf("Failed to assign default permissions to role ID %d for user ID %d: %s", roleID, userID, err.Error()),
			models.User{
				ID: userID,
			}, map[string]interface{}{
				"RoleID": roleID,
				"System": config.SystemsList[systemId].SystemCode,
				"Tenant": config.TenantsList[tenantId].TenantCode,
			})
		return fmt.Errorf("failed to assign default permissions for user ID %d: %w", userID, err)
	}

	LogEntry("EditUserRole in roleService", "info",
		fmt.Sprintf("Successfully updated role for user ID %d to role ID %d", userID, roleID),
		models.User{
			ID: userID,
		}, map[string]interface{}{
			"RoleID": roleID,
			"System": config.SystemsList[systemId].SystemCode,
			"Tenant": config.TenantsList[tenantId].TenantCode,
		})

	return nil
}

// AssignDefaultPermissionsToRole assigns the default permissions associated with a role to a user
func AssignDefaultPermissionsToRole(userID int, roleID int, systemId int, tenantId int) error {
	// SQL query to insert default permissions based on role
	sqlInsert := `
        INSERT INTO user_permissions (user_id, permission_id)
        SELECT $1, permission_id FROM role_permissions WHERE role_id = $2
    `

	// Get the database connection
	db, err := GetDBConnection(systemId, tenantId)
	if err != nil {
		LogEntry("AssignDefaultPermissionsToRole in roleService", "error",
			fmt.Sprintf("Error getting database connection: %s", err.Error()),
			models.User{
				ID: userID,
			}, map[string]interface{}{
				"RoleID":   roleID,
				"SystemID": systemId,
				"TenantID": tenantId,
			})
		return fmt.Errorf("failed to get database connection: %w", err)
	}

	// Insert the default permissions for the role
	rowCount, err := InsertRow(db, sqlInsert, []interface{}{userID, roleID}, models.LogInfo{
		Action:  "AssignDefaultPermissionsToRole - Insert",
		Message: fmt.Sprintf("Assigning default permissions for role %d to user ID %d", roleID, userID),
		User: models.User{
			ID: userID,
		},
		AdditionalData: map[string]interface{}{
			"RoleID":   roleID,
			"SystemID": systemId,
			"TenantID": tenantId,
		},
	})

	// Error handling for the SQL insert
	if err != nil {
		LogEntry("AssignDefaultPermissionsToRole in roleService", "error",
			fmt.Sprintf("Error inserting default permissions for role %d to user ID %d: %s", roleID, userID, err.Error()),
			models.User{
				ID: userID,
			}, map[string]interface{}{
				"RoleID":   roleID,
				"SystemID": systemId,
				"TenantID": tenantId,
			})
		return fmt.Errorf("failed to insert default permissions for role %d to user ID %d: %w", roleID, userID, err)
	}

	// If no rows are affected, log a message indicating no permissions were assigned
	if rowCount == 0 {
		LogEntry("AssignDefaultPermissionsToRole in roleService", "info",
			fmt.Sprintf("No default permissions found for role %d and user ID %d", roleID, userID),
			models.User{
				ID: userID,
			}, map[string]interface{}{
				"RoleID":   roleID,
				"SystemID": systemId,
				"TenantID": tenantId,
			})
		return fmt.Errorf("no default permissions found for role %d and user ID %d", roleID, userID)
	}

	// Log the successful assignment of permissions
	LogEntry("AssignDefaultPermissionsToRole in roleService", "info",
		fmt.Sprintf("Default permissions assigned successfully for role %d to user ID %d", roleID, userID),
		models.User{
			ID: userID,
		}, map[string]interface{}{
			"RoleID":   roleID,
			"SystemID": systemId,
			"TenantID": tenantId,
		})

	return nil
}

// ValidateRoleID checks if a given role ID exists in the database
func ValidateRoleID(roleID int, systemId int, tenantId int) error {
	// SQL query to check if the role ID exists
	sqlStatement := `SELECT id FROM roles WHERE id = $1`

	// Get the database connection
	db, err := GetDBConnection(systemId, tenantId)
	if err != nil {
		LogEntry("ValidateRoleID in roleService", "error",
			fmt.Sprintf("Error getting database connection: %s", err.Error()),
			models.User{}, map[string]interface{}{
				"RoleID":   roleID,
				"SystemID": systemId,
				"TenantID": tenantId,
			})
		return fmt.Errorf("failed to get database connection: %w", err)
	}

	// Execute the query to validate the role ID
	var id int
	rowCount, err := GetSingleRow(db, sqlStatement, []interface{}{roleID}, []interface{}{&id}, models.LogInfo{
		Action:  "ValidateRoleID - Select",
		Message: fmt.Sprintf("Validating role ID %d", roleID),
		User:    models.User{},
		AdditionalData: map[string]interface{}{
			"RoleID":   roleID,
			"SystemID": systemId,
			"TenantID": tenantId,
		},
	})

	// Error handling for SQL execution
	if err != nil {
		LogEntry("ValidateRoleID in roleService", "error",
			fmt.Sprintf("Error validating role ID %d: %s", roleID, err.Error()),
			models.User{}, map[string]interface{}{
				"RoleID":   roleID,
				"SystemID": systemId,
				"TenantID": tenantId,
			})
		return fmt.Errorf("error validating role ID %d: %w", roleID, err)
	}

	// If no rows are returned, log the error and return an appropriate message
	if rowCount == 0 {
		LogEntry("ValidateRoleID in roleService", "info",
			fmt.Sprintf("Role ID %d does not exist", roleID),
			models.User{}, map[string]interface{}{
				"RoleID":   roleID,
				"SystemID": systemId,
				"TenantID": tenantId,
			})
		return fmt.Errorf("role ID %d does not exist", roleID)
	}

	// Log success and return nil for a valid role ID
	LogEntry("ValidateRoleID in roleService", "info",
		fmt.Sprintf("Role ID %d is valid", roleID),
		models.User{}, map[string]interface{}{
			"RoleID":   roleID,
			"SystemID": systemId,
			"TenantID": tenantId,
		})

	return nil
}

// GetRoles retrieves all roles for a specific system and tenant
func GetRoles(systemId int, tenantId int) ([]models.Role, error) {
	sqlStatement := `
		SELECT id, role_name
		FROM roles;
	`

	// Get the database connection
	db, err := GetDBConnection(systemId, tenantId)
	if err != nil {
		LogEntry("GetRoles in roleService", "error",
			fmt.Sprintf("Error getting database connection: %s", err.Error()),
			models.User{}, map[string]interface{}{
				"SystemId": config.SystemsList[systemId].SystemCode,
				"Tenant":   config.TenantsList[tenantId].TenantCode,
			})
		return nil, fmt.Errorf("failed to get database connection: %w", err)
	}

	var roles []models.Role
	var role models.Role

	rows, err := db.Query(sqlStatement)
	if err != nil {
		LogEntry("GetRoles in roleService", "error",
			fmt.Sprintf("Error querying roles for system %s and tenant %s: %s", config.SystemsList[systemId].SystemCode, config.TenantsList[tenantId].TenantCode, err.Error()), models.User{},
			map[string]interface{}{
				"System": config.SystemsList[systemId].SystemCode,
				"Tenant": config.TenantsList[tenantId].TenantCode,
			})
		return nil, fmt.Errorf("failed to query roles for system %s and tenant %s: %w", config.SystemsList[systemId].SystemCode, config.TenantsList[tenantId].TenantCode, err)
	}

	defer rows.Close()

	rowCount := 0
	for rows.Next() {
		rowCount++
		if err := rows.Scan(&role.ID, &role.RoleName); err != nil {
			LogEntry("GetRoles in roleService", "error",
				fmt.Sprintf("Error scanning roles for system %s and tenant %s: %s", config.SystemsList[systemId].SystemCode, config.TenantsList[tenantId].TenantCode, err.Error()), models.User{},
				map[string]interface{}{
					"System": config.SystemsList[systemId].SystemCode,
					"Tenant": config.TenantsList[tenantId].TenantCode,
				})
			return nil, fmt.Errorf("failed to scan roles for system %s and tenant %s: %w", config.SystemsList[systemId].SystemCode, config.TenantsList[tenantId].TenantCode, err)
		}
		roles = append(roles, role)
	}

	// Handle case when no rows are found
	if rowCount == 0 {
		LogEntry("GetRoles in roleService", "info",
			fmt.Sprintf("No roles found for system %s and tenant %s", config.SystemsList[systemId].SystemCode, config.TenantsList[tenantId].TenantCode),
			models.User{}, map[string]interface{}{
				"System": config.SystemsList[systemId].SystemCode,
				"Tenant": config.TenantsList[tenantId].TenantCode,
			})
		return nil, fmt.Errorf("no roles found for system %s and tenant %s", config.SystemsList[systemId].SystemCode, config.TenantsList[tenantId].TenantCode)
	}

	// Log success
	LogEntry("GetRoles in roleService", "info",
		fmt.Sprintf("Roles retrieved successfully for system %s and tenant %s", config.SystemsList[systemId].SystemCode, config.TenantsList[tenantId].TenantCode),
		models.User{}, map[string]interface{}{
			"Roles":  roles,
			"System": config.SystemsList[systemId].SystemCode,
			"Tenant": config.TenantsList[tenantId].TenantCode,
		})

	return roles, nil
}

// DeleteRole deletes a role from the database
func DeleteRole(roleID int, systemId int, tenantId int) error {
	sqlStatement := `DELETE FROM roles WHERE id = $1`

	db, err := GetDBConnection(systemId, tenantId)
	if err != nil {
		LogEntry("DeleteRole in roleService", "error",
			fmt.Sprintf("Error getting database connection: %s", err.Error()), models.User{}, nil)
		return fmt.Errorf("failed to get database connection: %w", err)
	}

	rowCount, err := DeleteRow(db, sqlStatement, []interface{}{roleID}, models.LogInfo{
		Action:  "DeleteRole in roleService",
		Message: fmt.Sprintf("Deleted role ID %d", roleID),
		User:    models.User{},
	})

	if err != nil {
		LogEntry("DeleteRole in roleService", "error",
			fmt.Sprintf("Error deleting role ID %d: %s", roleID, err.Error()), models.User{}, nil)
		return fmt.Errorf("failed to delete role: %w", err)
	}

	if rowCount == 0 {
		return fmt.Errorf("role ID %d not found", roleID)
	}

	LogEntry("DeleteRole in roleService", "info",
		fmt.Sprintf("Role ID %d deleted successfully", roleID), models.User{}, nil)

	return nil
}
