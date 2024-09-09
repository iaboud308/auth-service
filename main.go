package main

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

func main() {
	connStr := "postgres://authuser:authpassword@db-auth-service:5432/authdb?sslmode=disable"

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal("Failed to open database connection:", err)
	}

	err = db.Ping()
	if err != nil {
		log.Fatal("Failed to connect to the auth database:", err)
	}

	fmt.Println("Successfully connected to the auth database!")
}
