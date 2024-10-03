package models

// AuthResponse struct for login response
type AuthResponse struct {
	ID          int      `json:"id"`
	FirstName   string   `json:"first_name"`
	LastName    string   `json:"last_name"`
	Email       string   `json:"email"`
	System      string   `json:"system"`
	Role        string   `json:"role"`
	Hospital    string   `json:"hospital"`
	Status      string   `json:"status"` // 'pending', 'approved', or 'declined'
	Permissions []string `json:"permissions"`
	JWT         string   `json:"jwt"`
}
