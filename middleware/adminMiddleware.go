package middleware

import (
	"auth-service/services"
	"net/http"
	"strings"
)

// RequireAdmin checks if the user has an admin role
func RequireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract the token from the Authorization header
		tokenStr := r.Header.Get("Authorization")
		tokenStr = strings.TrimPrefix(tokenStr, "Bearer ")

		// Parse the user from the token
		user, err := services.GetUserFromToken(tokenStr)
		if err != nil {
			http.Error(w, "Unauthorized access: Invalid token", http.StatusUnauthorized)
			return
		}

		// Check if the user's role is "Admin"
		if user.Role != "Admin" {
			http.Error(w, "Forbidden: Admin access only", http.StatusForbidden)
			return
		}

		// Call the next handler if the user is an admin
		next.ServeHTTP(w, r)
	}
}
