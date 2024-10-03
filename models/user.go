package models

// User struct representing the user entity
type User struct {
	ID        int    `json:"id"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Email     string `json:"email"`
	Password  string `json:"password"`
	System    string `json:"system"`   // System the user belongs to
	RoleID    int    `json:"role_id"`  // Foreign Key for the Role
	Hospital  string `json:"hospital"` // Hospital user is associated with
	Status    string `json:"status"`   // 'pending', 'approved', or 'declined'
}

type Role struct {
	ID       int    `json:"id"`
	RoleName string `json:"role_name"`
	System   string `json:"system"`   // Role tied to a system
	Hospital string `json:"hospital"` // Role tied to a hospital
}

type Permission struct {
	ID             int    `json:"id"`
	PermissionName string `json:"permission_name"`
	System         string `json:"system"`   // Permission tied to a system
	Hospital       string `json:"hospital"` // Permission tied to a hospital
}

type RolePermission struct {
	ID           int    `json:"id"`
	RoleID       int    `json:"role_id"`
	PermissionID int    `json:"permission_id"`
	System       string `json:"system"`
	Hospital     string `json:"hospital"`
}

type UserPermission struct {
	ID           int    `json:"id"`
	UserID       int    `json:"user_id"`
	PermissionID int    `json:"permission_id"`
	System       string `json:"system"`
	Hospital     string `json:"hospital"`
}

type UserWardPermissions struct {
	ID           int    `json:"id"`
	UserID       int    `json:"user_id"`
	WardID       int    `json:"ward_id"`
	PermissionID int    `json:"permission_id"`
	System       string `json:"system"`
	Hospital     string `json:"hospital"`
}
