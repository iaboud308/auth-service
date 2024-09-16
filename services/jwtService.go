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
	Email    string `json:"email"`
	System   int    `json:"system"`
	Role     string `json:"role"`
	Hospital int    `json:"hospital"`
	jwt.StandardClaims
}

// GenerateJWT creates a new token for a user
func GenerateJWT(user *models.User) (string, error) {
	claims := CustomClaims{
		Email:    user.Email,
		System:   user.System,
		Role:     user.Role,
		Hospital: user.Hospital,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 24).Unix(), // Token valid for 24 hours
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(config.JWTSecrets[user.System]))
}

// ValidateJWT checks if a token is valid
func ValidateJWT(tokenStr string) (bool, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		if claims, ok := token.Claims.(*CustomClaims); ok {
			// Get the appropriate secret based on the system
			return []byte(config.JWTSecrets[claims.System]), nil
		}
		return nil, errors.New("unable to parse token claims")
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
		if claims, ok := token.Claims.(*CustomClaims); ok {
			// Get the appropriate secret based on the system
			return []byte(config.JWTSecrets[claims.System]), nil
		}
		return nil, errors.New("unable to parse token claims")
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		return &models.User{
			Email:    claims.Email,
			System:   claims.System,
			Role:     claims.Role,
			Hospital: claims.Hospital,
		}, nil
	}
	return nil, errors.New("invalid token")
}
