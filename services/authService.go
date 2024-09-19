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
	user.Status = "approved"
	user.Role = "Admin"
	sql := `INSERT INTO users (first_name, last_name, email, password, system, role, hospital, status) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	_, err := db.Exec(sql, user.FirstName, user.LastName, user.Email, user.Password, user.System, user.Role, user.Hospital, user.Status)
	log.Println("CreateUser", err)
	return err
}

func GetUserByEmail(email string) (*models.User, error) {
	sql := `SELECT first_name, last_name, email, password, system, role, hospital, status FROM users WHERE email = $1`
	row := db.QueryRow(sql, email)

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
