package models

// Role struct representing a role entity
type Role struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Permissions string `json:"permissions"` // Store permissions as a JSON string or in a more structured way
}
