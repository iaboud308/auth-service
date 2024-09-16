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
	sql := `INSERT INTO users (username, password, system, role, hospital) VALUES ($1, $2, $3, $4, $5)`
	_, err := db.Exec(sql, user.Email, user.Password, user.System, user.Role, user.Hospital, user.Status)
	return err
}

func GetUserByUsername(username string) (*models.User, error) {
	sql := `SELECT username, password, system, role, hospital FROM users WHERE username = $1`
	row := db.QueryRow(sql, username)

	var user models.User
	err := row.Scan(&user.Email, &user.Password, &user.System, &user.Role, &user.Hospital)
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
