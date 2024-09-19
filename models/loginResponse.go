package models

// User struct representing the user entity
type LoginResponse struct {
	ID        int    `json:"id"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Email     string `json:"email"`
	System    string `json:"system"`
	Role      string `json:"role"`
	Hospital  string `json:"hospital"`
	Status    string `json:"status"` // 'pending', 'approved', or 'declined'
	JWT       string `json:"jwt"`
}
