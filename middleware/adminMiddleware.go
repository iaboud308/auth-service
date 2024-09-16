package middleware

import (
	"auth-service/services"
	"net/http"
)

// RequireAdmin checks if the user has admin role
func RequireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenStr := r.Header.Get("Authorization")
		user, err := services.GetUserFromToken(tokenStr)
		if err != nil || user.Role != "admin" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	}
}
