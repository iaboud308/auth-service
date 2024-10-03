package middleware

import (
	"auth-service/services"
	"net/http"
	"strings"
)

// ValidateJWT middleware validates JWT tokens
func ValidateJWT(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		tokenString = strings.TrimPrefix(tokenString, "Bearer ")

		token, err := services.ValidateJWT(tokenString)
		if err != nil || !token {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}
