package services

import (
	"auth-service/config"
	"auth-service/models"
	"errors"
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type CustomClaims struct {
	ID        int    `json:"id"`
	FirstName string `json:"first_name,omitempty"`
	LastName  string `json:"last_name,omitempty"`
	Email     string `json:"email,omitempty"`
	System    string `json:"system,omitempty"`
	RoleID    int    `json:"role_id"`
	Role      string `json:"role,omitempty"` // Use pointer for optional value
	Hospital  string `json:"hospital,omitempty"`
	jwt.StandardClaims
}

func GenerateJWT(user *models.User) (string, error) {
	// Fetch the role name based on RoleID
	role, err := GetUserRole(user.RoleID)
	if err != nil {
		return "", fmt.Errorf("failed to fetch role for user ID %d: %w", user.ID, err)
	}

	claims := CustomClaims{
		ID:        user.ID,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Email:     user.Email,
		System:    user.System,
		RoleID:    user.RoleID,
		Role:      role.RoleName, // Include role name in the JWT
		Hospital:  user.Hospital,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 24).Unix(), // Token valid for 24 hours
			Issuer:    "auth-service",                        // Adding issuer for better traceability
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Fetch the JWT secret for the system and hospital
	jwtSecret, err := config.GetJWTSecret(user.System, user.Hospital)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve JWT secret: %w", err)
	}

	signedToken, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		return "", fmt.Errorf("failed to sign the JWT token: %w", err)
	}

	return signedToken, nil
}

// ValidateJWT checks if a JWT token is valid and not expired
func ValidateJWT(tokenStr string) (bool, error) {
	// Parse the token with claims
	token, err := jwt.ParseWithClaims(tokenStr, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Retrieve claims to extract system and hospital
		if claims, ok := token.Claims.(*CustomClaims); ok {
			// Get the secret key for the system and hospital
			jwtSecret, err := config.GetJWTSecret(claims.System, claims.Hospital)
			if err != nil {
				return nil, err
			}
			return []byte(jwtSecret), nil
		}
		return nil, errors.New("unable to parse token claims")
	})

	// If token parsing failed, return false and the error
	if err != nil {
		return false, err
	}

	// Validate token and check expiration time
	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		if claims.ExpiresAt > time.Now().Unix() {
			return true, nil // Token is valid and not expired
		}
		return false, errors.New("token has expired") // Token expired
	}

	return false, errors.New("invalid token")
}

// GetUserFromToken parses the JWT token and returns the associated user info
func GetUserFromToken(tokenStr string) (*models.AuthResponse, error) {
	// Parse the token with custom claims
	token, err := jwt.ParseWithClaims(tokenStr, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Retrieve the claims to extract system and hospital
		if claims, ok := token.Claims.(*CustomClaims); ok {
			// Get the secret key for the system and hospital
			jwtSecret, err := config.GetJWTSecret(claims.System, claims.Hospital)
			if err != nil {
				// Log the error when retrieving JWT secret
				LogEntry("GetUserFromToken in jwtService", claims.System, claims.Hospital, "error", "Failed to retrieve JWT secret: "+err.Error(), 0, nil)
				return nil, err
			}
			return []byte(jwtSecret), nil
		}
		return nil, errors.New("unable to parse token claims")
	})

	// Handle token parsing errors
	if err != nil {
		LogEntry("GetUserFromToken in jwtService", "Nil", "Nil", "error", "Failed to parse token: "+err.Error(), 0, nil)
		return nil, err
	}

	// Validate the token and extract user details
	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		// Construct the AuthResponse based on claims
		authResponse := &models.AuthResponse{
			ID:          claims.ID,
			FirstName:   claims.FirstName,
			LastName:    claims.LastName,
			Email:       claims.Email,
			System:      claims.System,
			Role:        claims.Role, // Role is already stored in the token
			Hospital:    claims.Hospital,
			Permissions: []string{}, // Optionally fetch from DB if needed
		}

		// Log successful token parsing and user extraction
		LogEntry("GetUserFromToken in jwtService", claims.System, claims.Hospital, "info", "Token parsed and user info retrieved successfully", claims.ID, nil)

		return authResponse, nil
	}

	// Log invalid token
	LogEntry("GetUserFromToken in jwtService", "Nil", "Nil", "error", "Invalid token", 0, nil)
	return nil, errors.New("invalid token")
}
