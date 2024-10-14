package models

// User struct representing the user entity
type User struct {
	ID                  int                   `json:"id"`
	FirstName           string                `json:"first_name"`
	LastName            string                `json:"last_name"`
	Email               string                `json:"email"`
	Password            string                `json:"password"`
	SystemId            int                   `json:"system_id"` // System the user belongs to
	RoleID              int                   `json:"role_id"`   // Foreign Key for the Role
	TenantId            int                   `json:"tenant_id"` // Hospital user is associated with
	Status              string                `json:"status"`    // 'pending', 'active', or 'inactive'
	UserWards           []UserWard            `json:"wards"`
	UserWardPermissions []UserWardPermissions `json:"user_ward_permissions"`
}

type Role struct {
	ID       int    `json:"id"`
	RoleName string `json:"role_name"`
}

type Permission struct {
	ID             int    `json:"id"`
	PermissionName string `json:"permission_name"`
}

type RolePermission struct {
	ID           int `json:"id"`
	RoleID       int `json:"role_id"`
	PermissionID int `json:"permission_id"`
}

type UserPermission struct {
	ID           int `json:"id"`
	UserID       int `json:"user_id"`
	PermissionID int `json:"permission_id"`
}

type UserWard struct {
	ID           int  `json:"id"`
	UserID       int  `json:"user_id"`
	WardID       int  `json:"ward_id"`
	GlobalAccess bool `json:"global_access"`
}

type UserWardPermissions struct {
	ID           int `json:"id"`
	UserID       int `json:"user_id"`
	WardID       int `json:"ward_id"`
	PermissionID int `json:"permission_id"`
}
