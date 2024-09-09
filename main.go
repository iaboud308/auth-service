package main

import (
	"fmt"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Auth service running!")
}

func main() {
	http.HandleFunc("/", handler)
	fmt.Println("Starting auth service on port 8081")
	if err := http.ListenAndServe("0.0.0.0:8081", nil); err != nil {
		fmt.Println("Failed to start server:", err)
	}
}

// connStr := "postgres://authuser:authpassword@db-auth-service:5432/authdb?sslmode=disable"
