// services/authService.go
package services

import (
	"auth-service/config" // Correctly importing the appconfig package
	"auth-service/models"
	"database/sql"
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
	_, err := db.Exec(sql, user.Username, user.Password, user.System, user.Role, user.Hospital)
	return err
}

func GetUserByUsername(username string) (*models.User, error) {
	sql := `SELECT username, password, system, role, hospital FROM users WHERE username = $1`
	row := db.QueryRow(sql, username)

	var user models.User
	err := row.Scan(&user.Username, &user.Password, &user.System, &user.Role, &user.Hospital)
	if err != nil {
		return nil, err
	}

	return &user, nil
}
