package middleware

import (
	"auth-service/services"
	"log"
	"net/http"
)

// RequireAdmin checks if the user has admin role
func RequireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenStr := r.Header.Get("Authorization")
		user, err := services.GetUserFromToken(tokenStr)

		log.Println("RequireAdmin Controller User", user, "Error", err)

		if err != nil || user.Role != "Admin" {
			log.Println("RequireAdmin Controller User: Will not pass")
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	}
}
