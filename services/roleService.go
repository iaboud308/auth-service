package services

import (
	"auth-service/models"
	"database/sql"
	"errors"
	"fmt"
)

// GetUserRole retrieves the role associated with the user’s role ID
func GetUserRole(roleID int) (*models.Role, error) {
	sqlStatement := `SELECT id, role_name, system, hospital FROM roles WHERE id = $1`
	row := db.QueryRow(sqlStatement, roleID)

	var role models.Role
	err := row.Scan(&role.ID, &role.RoleName, &role.System, &role.Hospital)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("role not found")
		}
		return nil, err
	}

	return &role, nil
}

// EditUserRole updates a user's role by assigning a new role ID
func EditUserRole(userID int, roleID int) error {
	sqlStatement := `UPDATE users SET role_id = $1 WHERE id = $2`
	_, err := db.Exec(sqlStatement, roleID, userID)
	if err != nil {
		return err
	}

	// Optionally, assign default permissions based on the new role
	err = AssignDefaultPermissionsToRole(userID, roleID)
	if err != nil {
		return err
	}

	return nil
}

// AssignDefaultPermissionsToRole assigns the default permissions associated with a role to a user
func AssignDefaultPermissionsToRole(userID int, roleID int) error {
	sqlStatement := `INSERT INTO user_permissions (user_id, permission_id)
	                 SELECT $1, permission_id FROM role_permissions WHERE role_id = $2`
	_, err := db.Exec(sqlStatement, userID, roleID)
	if err != nil {
		return err
	}
	return nil
}

// ValidateRoleID checks if a given role ID exists in the database
func ValidateRoleID(roleID int) error {
	sqlStatement := `SELECT id FROM roles WHERE id = $1`
	row := db.QueryRow(sqlStatement, roleID)

	var id int
	err := row.Scan(&id)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("role ID %d does not exist", roleID)
		}
		return fmt.Errorf("error checking role ID %d: %w", roleID, err)
	}

	return nil
}
