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
	Role      string `json:"role,omitempty"` // Use pointer for optional value
	Hospital  string `json:"hospital,omitempty"`
	jwt.StandardClaims
}

func GenerateJWT(user *models.User) (string, error) {
	// Fetch the role name based on RoleID
	role, err := GetUserRole(user.RoleID)
	if err != nil {
		LogEntry("GenerateJWT in jwtService", "error", fmt.Sprintf("Failed to fetch role for user ID %d: %s", user.ID, err.Error()), *user, nil)
		return "", fmt.Errorf("failed to fetch role for user ID %d: %w", user.ID, err)
	}

	// Set token expiration time (24 hours)
	expirationTime := time.Now().Add(24 * time.Hour).Unix()

	claims := CustomClaims{
		ID:        user.ID,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Email:     user.Email,
		System:    user.System,
		Role:      role.RoleName, // Include role name in the JWT
		Hospital:  user.Hospital,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime, // Token valid for 24 hours
			Issuer:    "auth-service", // Adding issuer for traceability
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Fetch the JWT secret for the system and hospital
	jwtSecret, err := config.GetJWTSecret(user.System, user.Hospital)
	if err != nil {
		LogEntry("GenerateJWT in jwtService", "error", fmt.Sprintf("Failed to retrieve JWT secret for user ID %d: %s", user.ID, err.Error()), *user, nil)
		return "", fmt.Errorf("failed to retrieve JWT secret for user ID %d: %w", user.ID, err)
	}

	signedToken, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		LogEntry("GenerateJWT in jwtService", "error", fmt.Sprintf("Failed to sign JWT token for user ID %d: %s", user.ID, err.Error()), *user, nil)
		return "", fmt.Errorf("failed to sign the JWT token for user ID %d: %w", user.ID, err)
	}

	LogEntry("GenerateJWT in jwtService", "info", fmt.Sprintf("JWT token generated successfully for user ID %d", user.ID), *user, map[string]interface{}{
		"ExpiresAt": expirationTime,
	})

	return signedToken, nil
}

// ValidateJWT checks if a JWT token is valid and not expired
func ValidateJWT(tokenStr string) (bool, error) {
	// Parse the token with claims
	token, err := jwt.ParseWithClaims(tokenStr, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		claims, ok := token.Claims.(*CustomClaims)
		if !ok {
			LogEntry("ValidateJWT in jwtService", "error", "Unable to parse token claims", models.User{}, nil)
			return nil, errors.New("unable to parse token claims")
		}

		// Get the secret key for the system and hospital
		jwtSecret, err := config.GetJWTSecret(claims.System, claims.Hospital)
		if err != nil {
			LogEntry("ValidateJWT in jwtService", "error", "Failed to retrieve JWT secret: "+err.Error(), models.User{}, map[string]interface{}{
				"System":   claims.System,
				"Hospital": claims.Hospital,
			})
			return nil, fmt.Errorf("failed to retrieve JWT secret: %w", err)
		}

		return []byte(jwtSecret), nil
	})

	if err != nil {
		LogEntry("ValidateJWT in jwtService", "error", "Token parsing failed: "+err.Error(), models.User{}, map[string]interface{}{
			"TokenStr": tokenStr,
		})
		return false, fmt.Errorf("token parsing failed: %w", err)
	}

	// Validate token and check expiration time
	claims, ok := token.Claims.(*CustomClaims)
	if !ok || !token.Valid {
		LogEntry("ValidateJWT in jwtService", "error", "Invalid token", models.User{}, map[string]interface{}{
			"Claims": token.Claims,
		})
		return false, errors.New("invalid token")
	}

	// Check if token has expired
	expirationTime := time.Unix(claims.ExpiresAt, 0)
	if time.Now().After(expirationTime) {
		LogEntry("ValidateJWT in jwtService", "error", "Token has expired", models.User{}, map[string]interface{}{
			"ExpiresAt": expirationTime,
		})
		return false, errors.New("token has expired")
	}

	LogEntry("ValidateJWT in jwtService", "info", "Token is valid", models.User{}, map[string]interface{}{
		"UserID":   claims.ID,
		"Email":    claims.Email,
		"Role":     claims.Role,
		"System":   claims.System,
		"Hospital": claims.Hospital,
	})

	return true, nil // Token is valid and not expired
}

// GetUserFromToken parses the JWT token and returns the associated user info
func GetUserFromToken(tokenStr string) (*models.AuthResponse, error) {
	// Validate the token and check if it's expired or invalid
	isValid, err := ValidateJWT(tokenStr)
	if err != nil {
		LogEntry("GetUserFromToken in jwtService", "error", "Failed to validate JWT: "+err.Error(), models.User{}, map[string]interface{}{
			"TokenStr": tokenStr,
		})
		return nil, err
	}

	if !isValid {
		LogEntry("GetUserFromToken in jwtService", "error", "Invalid JWT token", models.User{}, map[string]interface{}{
			"TokenStr": tokenStr,
		})
		return nil, errors.New("invalid JWT token")
	}

	// Parse the token with custom claims
	token, err := jwt.ParseWithClaims(tokenStr, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Retrieve the claims to extract system and hospital
		if claims, ok := token.Claims.(*CustomClaims); ok {
			// Get the secret key for the system and hospital
			jwtSecret, err := config.GetJWTSecret(claims.System, claims.Hospital)
			if err != nil {
				// Log the error when retrieving JWT secret
				LogEntry("GetUserFromToken in jwtService", "error", "Failed to retrieve JWT secret: "+err.Error(),
					models.User{}, map[string]interface{}{
						"Claims": claims,
					})
				return nil, err
			}
			return []byte(jwtSecret), nil
		}
		return nil, errors.New("unable to parse token claims")
	})

	// Handle token parsing errors
	if err != nil {
		LogEntry("GetUserFromToken in jwtService", "error", "Failed to parse token: "+err.Error(), models.User{}, map[string]interface{}{
			"Claims": token.Claims,
		})
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
		LogEntry("GetUserFromToken in jwtService", "info", "Token parsed and user info retrieved successfully", models.User{},
			map[string]interface{}{
				"User": authResponse,
			})

		return authResponse, nil
	}

	// Log invalid token
	LogEntry("GetUserFromToken in jwtService", "error", "Invalid token", models.User{}, map[string]interface{}{
		"Claims": token.Claims,
	})
	return nil, errors.New("invalid token")
}
