package services

import (
	"auth-service/config"
	"auth-service/models"
	"errors"
	"time"

	"github.com/dgrijalva/jwt-go"
)

// JWT claims structure
type CustomClaims struct {
	Username string `json:"username"`
	System   string `json:"system"`
	Role     string `json:"role"`
	Hospital string `json:"hospital"`
	jwt.StandardClaims
}

// GenerateJWT creates a new token for a user
func GenerateJWT(user *models.User) (string, error) {
	claims := CustomClaims{
		Username: user.Username,
		System:   user.System,
		Role:     user.Role,
		Hospital: user.Hospital,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 24).Unix(), // Token valid for 24 hours
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(config.JWTSecret))
}

// ValidateJWT checks if a token is valid
func ValidateJWT(tokenStr string) (bool, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(config.JWTSecret), nil
	})

	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		return claims.ExpiresAt > time.Now().Unix(), nil
	}
	return false, err
}

// RevokeToken (optional): Add your revocation logic here (e.g., store in a blacklist)
func RevokeToken(tokenStr string) error {
	// Implement token revocation (e.g., add the token to a blacklist)
	return nil
}

// GetUserFromToken parses the JWT token and returns the associated user info
func GetUserFromToken(tokenStr string) (*models.User, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(config.JWTSecret), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		return &models.User{
			Username: claims.Username,
			System:   claims.System,
			Role:     claims.Role,
			Hospital: claims.Hospital,
		}, nil
	}
	return nil, errors.New("invalid token")
}
