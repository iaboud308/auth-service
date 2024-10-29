package services

import (
	"auth-service/config"
	"auth-service/models"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5" // Updated JWT library
)

type CustomClaims struct {
	ID        int    `json:"id"`
	FirstName string `json:"first_name,omitempty"`
	LastName  string `json:"last_name,omitempty"`
	Email     string `json:"email,omitempty"`
	System    string `json:"system,omitempty"`
	Role      string `json:"role,omitempty"`
	Tenant    string `json:"tenant,omitempty"`
	jwt.RegisteredClaims
}

func GenerateJWT(user *models.User) (string, error) {

	// Set token expiration time (24 hours)
	expirationTime := time.Now().Add(24 * time.Hour).Unix()

	claims := CustomClaims{
		ID:        user.ID,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Email:     user.Email,
		System:    config.SystemsList[user.SystemId].SystemCode,
		// Role:      role.RoleName, // Include role name in the JWT
		Tenant: config.TenantsList[user.TenantId].TenantCode,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			Issuer:    "auth-service",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Fetch the JWT secret for the system and hospital
	jwtSecret, err := config.GetJWTSecret(user.SystemId, user.TenantId)
	if err != nil {
		LogEntry("GenerateJWT in jwtService", "error",
			fmt.Sprintf("Failed to retrieve JWT secret for user ID %d: %s", user.ID, err.Error()), *user, nil)
		return "", fmt.Errorf("failed to retrieve JWT secret for user ID %d: %w", user.ID, err)
	}

	signedToken, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		LogEntry("GenerateJWT in jwtService", "error",
			fmt.Sprintf("Failed to sign JWT token for user ID %d: %s", user.ID, err.Error()), *user, nil)
		return "", fmt.Errorf("failed to sign the JWT token for user ID %d: %w", user.ID, err)
	}

	LogEntry("GenerateJWT in jwtService", "info",
		fmt.Sprintf("JWT token generated successfully for user ID %d", user.ID), *user,
		map[string]interface{}{
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
		var systemId, _ = config.GetSystemId(claims.System)
		var tenantId, _ = config.GetTenantId(claims.Tenant)
		jwtSecret, err := config.GetJWTSecret(systemId, tenantId)
		if err != nil {
			LogEntry("ValidateJWT in jwtService", "error", "Failed to retrieve JWT secret: "+err.Error(), models.User{}, map[string]interface{}{
				"System": claims.System,
				"Tenant": claims.Tenant,
			})
			return nil, fmt.Errorf("failed to retrieve JWT secret: %w", err)
		}

		return []byte(jwtSecret), nil
	})

	if err != nil {
		LogEntry("ValidateJWT in jwtService", "error", "Token parsing failed: "+err.Error(),
			models.User{},
			map[string]interface{}{
				"TokenStr": tokenStr,
			})
		return false, fmt.Errorf("token parsing failed: %w", err)
	}

	// Validate token and check expiration time
	claims, ok := token.Claims.(*CustomClaims)
	if !ok || !token.Valid {
		LogEntry("ValidateJWT in jwtService", "error", "Invalid token", models.User{},
			map[string]interface{}{
				"Claims": token.Claims,
			})
		return false, errors.New("invalid token")
	}

	// Check if token has expired
	expirationTime := time.Unix(claims.ExpiresAt.Unix(), 0)
	if time.Now().After(expirationTime) {
		LogEntry("ValidateJWT in jwtService", "error", "Token has expired", models.User{},
			map[string]interface{}{
				"ExpiresAt": expirationTime,
			})
		return false, errors.New("token has expired")
	}

	LogEntry("ValidateJWT in jwtService", "info", "Token is valid", models.User{}, map[string]interface{}{
		"UserID":   claims.ID,
		"Email":    claims.Email,
		"Role":     claims.Role,
		"System":   claims.System,
		"Hospital": claims.Tenant,
	})

	return true, nil
}

// GetUserFromToken parses the JWT token and returns the associated user info
func GetUserFromToken(tokenStr string) (*models.AuthResponse, error) {
	// Validate and parse the token with custom claims
	token, err := jwt.ParseWithClaims(tokenStr, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		claims, ok := token.Claims.(*CustomClaims)
		if !ok {
			LogEntry("GetUserFromToken in jwtService", "error", "Unable to parse token claims", models.User{}, nil)
			return nil, errors.New("unable to parse token claims")
		}

		// Retrieve JWT secret using system and tenant from claims
		var systemId, _ = config.GetSystemId(claims.System)
		var tenantId, _ = config.GetTenantId(claims.Tenant)
		jwtSecret, err := config.GetJWTSecret(systemId, tenantId)
		if err != nil {
			LogEntry("GetUserFromToken in jwtService", "error", "Failed to retrieve JWT secret: "+err.Error(), models.User{}, map[string]interface{}{
				"System": claims.System,
				"Tenant": claims.Tenant,
			})
			return nil, fmt.Errorf("failed to retrieve JWT secret: %w", err)
		}

		return []byte(jwtSecret), nil
	})

	// Handle token parsing errors
	if err != nil {
		LogEntry("GetUserFromToken in jwtService", "error", "Failed to parse token: "+err.Error(), models.User{}, map[string]interface{}{
			"TokenStr": tokenStr,
		})
		return nil, err
	}

	// Check if token is valid and extract claims
	claims, ok := token.Claims.(*CustomClaims)
	if !ok || !token.Valid {
		LogEntry("GetUserFromToken in jwtService", "error", "Invalid token", models.User{}, map[string]interface{}{
			"Claims": token.Claims,
		})
		return nil, errors.New("invalid token")
	}

	// Retrieve system and tenant IDs based on claims
	systemId, err := config.GetSystemId(claims.System)
	if err != nil {
		LogEntry("GetUserFromToken in jwtService", "error", "Failed to retrieve system ID: "+err.Error(),
			models.User{}, map[string]interface{}{
				"System": claims.System,
			})
		return nil, fmt.Errorf("failed to retrieve system ID: %w", err)
	}

	tenantId, err := config.GetTenantId(claims.Tenant)
	if err != nil {
		LogEntry("GetUserFromToken in jwtService", "error", "Failed to retrieve tenant ID: "+err.Error(),
			models.User{}, map[string]interface{}{
				"Tenant": claims.Tenant,
			})
		return nil, fmt.Errorf("failed to retrieve tenant ID: %w", err)
	}

	// Fetch user permissions
	permissions, err := GetUserPermissions(claims.ID, systemId, tenantId)
	if err != nil {
		LogEntry("GetUserFromToken in jwtService", "error", "Failed to retrieve permissions: "+err.Error(),
			models.User{}, map[string]interface{}{
				"UserID": claims.ID,
			})
		return nil, fmt.Errorf("failed to retrieve permissions: %w", err)
	}

	// Construct the AuthResponse based on claims
	authResponse := &models.AuthResponse{
		ID:          claims.ID,
		FirstName:   claims.FirstName,
		LastName:    claims.LastName,
		Email:       claims.Email,
		System:      claims.System,
		Role:        claims.Role,
		Tenant:      claims.Tenant,
		Permissions: permissions,
	}

	// Log successful token parsing and user extraction
	LogEntry("GetUserFromToken in jwtService", "info", "Token parsed and user info retrieved successfully", models.User{},
		map[string]interface{}{
			"User": authResponse,
		})

	return authResponse, nil
}
