// services/authService.go
package services

import (
	"auth-service/config" // Correctly importing the appconfig package
	"auth-service/models"
	"database/sql"
	"errors"
	"log"

	_ "github.com/lib/pq"
)

var db *sql.DB

func InitDB() {
	var err error
	db, err = sql.Open("postgres", config.GetDBConnectionString()) // Access the connection string from appconfig
	if err != nil {
		log.Fatal("Unable to connect to the database:", err)
	}

	// Ping to ensure the connection is established
	if err := db.Ping(); err != nil {
		log.Fatal("Unable to reach the database:", err)
	}
}

func CreateUser(user *models.User) error {

	var checkUser *models.User
	if checkUser, _ = GetUserByEmail(user.Email, user.Hospital); checkUser != nil {
		return errors.New("user already exists")
	}

	user.Status = "pending"
	sql := `INSERT INTO users (first_name, last_name, email, password, system, role, hospital, status) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	_, err := db.Exec(sql, user.FirstName, user.LastName, user.Email, user.Password, user.System, user.Role, user.Hospital, user.Status)
	log.Println("CreateUser", err, user)
	return err
}

func GetUserByEmail(email string, hospital string) (*models.User, error) {
	sql := `SELECT first_name, last_name, email, password, system, role, hospital, status FROM users WHERE email = $1 AND hospital = $2 AND status = $3`
	row := db.QueryRow(sql, email, hospital, "approved")

	var user models.User
	err := row.Scan(&user.FirstName, &user.LastName, &user.Email, &user.Password, &user.System, &user.Role, &user.Hospital, &user.Status)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

// Retrieve a user by ID from the database
func GetUserByID(userID uint) (*models.User, error) {
	sql := `SELECT id, email, system, role, hospital, status FROM users WHERE id = $1`
	row := db.QueryRow(sql, userID)

	var user models.User
	err := row.Scan(&user.ID, &user.Email, &user.System, &user.Role, &user.Hospital, &user.Status)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

// Save user status changes in the database
func SaveUser(user *models.User) error {
	sql := `UPDATE users SET status = $1 WHERE id = $2`
	_, err := db.Exec(sql, user.Status, user.ID)
	return err
}

// Approve a user's registration (set status to "approved")
func ApproveUser(userID uint) error {
	user, err := GetUserByID(userID)
	if err != nil {
		return errors.New("user not found")
	}

	if user.Status != "pending" {
		return errors.New("user is not in pending state")
	}

	user.Status = "approved"
	return SaveUser(user)
}

// Decline a user's registration (set status to "declined")
func DeclineUser(userID uint) error {
	user, err := GetUserByID(userID)
	if err != nil {
		return errors.New("user not found")
	}

	if user.Status != "pending" {
		return errors.New("user is not in pending state")
	}

	user.Status = "declined"
	return SaveUser(user)
}

func GetUserRoles(userID int, system string) ([]string, error) {
	sql := `
        SELECT r.role_name
        FROM user_roles ur
        JOIN roles r ON ur.role_id = r.id
        WHERE ur.user_id = $1 AND r.system = $2
    `
	rows, err := db.Query(sql, userID, system)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var roles []string
	for rows.Next() {
		var role string
		err := rows.Scan(&role)
		if err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}

	return roles, nil
}

func GetUserPermissions(userID int, system string) ([]string, error) {
	sql := `
        SELECT p.permission_name
        FROM user_roles ur
        JOIN roles r ON ur.role_id = r.id
        JOIN role_permissions rp ON r.id = rp.role_id
        JOIN permissions p ON rp.permission_id = p.id
        WHERE ur.user_id = $1 AND r.system = $2
    `
	rows, err := db.Query(sql, userID, system)
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

	return permissions, nil
}

// GetUsersList retrieves users from the database for a specific system and hospital
func GetUsersList(system string, hospital string) ([]models.LoginResponse, error) {
	log.Println("GetUsersList Service", system, hospital)
	// Query the database to get users by system and hospital
	sqlStatement := `SELECT id, first_name, last_name, email, role, hospital, status FROM users WHERE system = $1 AND hospital = $2`
	rows, err := db.Query(sqlStatement, system, hospital)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// Initialize slice to store users
	var users []models.LoginResponse

	// Loop through the result set
	for rows.Next() {
		var user models.LoginResponse
		err := rows.Scan(&user.ID, &user.FirstName, &user.LastName, &user.Email, &user.Role, &user.Hospital, &user.Status)
		if err != nil {
			return nil, err
		}
		user.Permsions, _ = GetUserPermissions(user.ID, system)
		users = append(users, user)
	}

	// Check for errors during row iteration
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return users, nil
}

// DeleteUser removes a user from the database by their ID
func DeleteUser(userID int) error {
	sqlStatement := `DELETE FROM users WHERE id = $1`

	_, err := db.Exec(sqlStatement, userID)
	if err != nil {
		return err
	}

	return nil
}

func GetRolePermissions(role string) ([]string, error) {
	// Query to get the permissions for the role
	query := `SELECT permission FROM role_permissions WHERE role = $1`
	rows, err := db.Query(query, role)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var permissions []string
	for rows.Next() {
		var permission string
		if err := rows.Scan(&permission); err != nil {
			return nil, err
		}
		permissions = append(permissions, permission)
	}
	return permissions, nil
}

func AssignPermissionsToUser(userID int, permissions []string) error {
	for _, permission := range permissions {
		query := `INSERT INTO user_permissions (user_id, permission) VALUES ($1, $2)`
		_, err := db.Exec(query, userID, permission)
		if err != nil {
			return err
		}
	}
	return nil
}
