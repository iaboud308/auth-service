package models

// User struct representing the user entity
type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"-"`
	System   string `json:"system"`
	Role     string `json:"role"`
	Hospital string `json:"hospital"`
}
