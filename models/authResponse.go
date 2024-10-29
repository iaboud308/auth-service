package models

// AuthResponse struct for login response
type AuthResponse struct {
	ID                  int                   `json:"id"`
	FirstName           string                `json:"first_name"`
	LastName            string                `json:"last_name"`
	Email               string                `json:"email"`
	System              string                `json:"system"`
	Role                string                `json:"role"`
	Tenant              string                `json:"tenant"`
	TenantID            int                   `json:"tenant_id"`
	Status              string                `json:"status"` // 'pending', 'approved', or 'declined'
	Permissions         []Permission          `json:"permissions"`
	JWT                 string                `json:"jwt"`
	UserWards           []UserWard            `json:"user_wards"`
	UserWardPermissions []UserWardPermissions `json:"user_ward_permissions"`
}
