package services

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
		return nil, err
	}
	defer rows.Close()

	var permissions []string
	for rows.Next() {
		var permission string
		err := rows.Scan(&permission)
		if err != nil {
			return nil, err
		}
		permissions = append(permissions, permission)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return permissions, nil
}

// EditUserPermissions updates the general permissions of a user
func EditUserPermissions(userID int, permissions []string) error {
	// Delete existing permissions for the user
	sqlDelete := `DELETE FROM user_permissions WHERE user_id = $1`
	_, err := db.Exec(sqlDelete, userID)
	if err != nil {
		return err
	}

	// Insert new permissions
	for _, permission := range permissions {
		sqlInsert := `
            INSERT INTO user_permissions (user_id, permission_id)
            SELECT $1, p.id FROM permissions p WHERE p.permission_name = $2
        `
		_, err := db.Exec(sqlInsert, userID, permission)
		if err != nil {
			return err
		}
	}
	return nil
}

// EditUserWardPermissions updates ward-specific permissions for a user
func EditUserWardPermissions(userID int, permissions []string, wards []int) error {
	// Delete existing ward permissions for the user
	sqlDelete := `DELETE FROM user_ward_permissions WHERE user_id = $1`
	_, err := db.Exec(sqlDelete, userID)
	if err != nil {
		return err
	}

	// Insert new ward-specific permissions
	for _, wardID := range wards {
		for _, permission := range permissions {
			sqlInsert := `
                INSERT INTO user_ward_permissions (user_id, ward_id, permission_id)
                SELECT $1, $2, p.id FROM permissions p WHERE p.permission_name = $3
            `
			_, err := db.Exec(sqlInsert, userID, wardID, permission)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// AssignPermissionsToUser assigns general permissions to a user
func AssignPermissionsToUser(userID int, permissions []string) error { // Need to enter system and hospital
	for _, permission := range permissions {
		sqlInsert := `
            INSERT INTO user_permissions (user_id, permission_id)
            SELECT $1, p.id FROM permissions p WHERE p.permission_name = $2
        `
		_, err := db.Exec(sqlInsert, userID, permission)
		if err != nil {
			return err
		}
	}
	return nil
}

// GetRolePermissions retrieves the permissions associated with a specific role
func GetRolePermissions(roleID int) ([]string, error) {
	sqlStatement := `
        SELECT p.permission_name
        FROM role_permissions rp
        JOIN permissions p ON rp.permission_id = p.id
        WHERE rp.role_id = $1
    `
	rows, err := db.Query(sqlStatement, roleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var permissions []string
	for rows.Next() {
		var permission string
		err := rows.Scan(&permission)
		if err != nil {
			return nil, err
		}
		permissions = append(permissions, permission)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return permissions, nil
}
