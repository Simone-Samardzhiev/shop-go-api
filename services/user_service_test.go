package services

import (
	"api/auth"
	"api/config"
	"api/models"
	"api/repositories"
	"context"
	"github.com/golang-jwt/jwt/v5"
	"testing"
)

// Setup returns DefaultUserService
//
// The service is configured with repositories.MemoryUserRepository,
// repositories.MemoryTokenRepository and auth.JWTAuthenticator.
func Setup() *DefaultUserService {
	userRepository := repositories.NewMemoryUserRepository()
	tokenRepository := repositories.NewMemoryTokenRepository()
	authenticator := auth.NewJWTAuthenticator(config.AuthConfig{
		JWTSecret: "secret",
		Issuer:    "issuer",
	})
	return NewDefaultUserService(userRepository, tokenRepository, authenticator)
}

// ValidRegisterUserPayloadUser returns valid models.User.
func ValidRegisterUserPayloadUser() *models.RegisterClientPayload {
	return models.NewRegisterClientPayload("exmaple@gmai.com", "Username", "Password_123")
}

// TestDefaultUserServiceAddValidUser verifies that adding a valid user succeeds, and
// an attempt to add the same user result in an error.
func TestDefaultUserServiceAddValidUser(t *testing.T) {
	service := Setup()

	// The First attempt should succeed.
	err := service.AddClient(context.Background(), ValidRegisterUserPayloadUser())
	if err != nil {
		t.Errorf("AddClient returned error: %v", err)
	}

	// The second attempt should fail.
	err = service.AddClient(context.Background(), ValidRegisterUserPayloadUser())
	if err == nil {
		t.Errorf("AddClient returned no error when adding the same user.")
	}
}

// TestDefaultUserServiceAddInvalidUser verifies that adding an invalid user result in an error.
func TestDefaultUserServiceAddInvalidUser(t *testing.T) {
	service := Setup()
	user := models.NewRegisterClientPayload("valid.com", "ValidUsername", "ValidPassword_2")

	// Adding the invalid user should result in an error.
	err := service.AddClient(context.Background(), user)
	if err == nil {
		t.Errorf("AddClient returned no error when adding invalid user.")
	}
}

// TestDefaultUserServiceAddLogin verifies that after successful
// registration, the user can log in.
func TestDefaultUserServiceAddLogin(t *testing.T) {
	service := Setup()

	// Registering the user.
	err := service.AddClient(context.Background(), ValidRegisterUserPayloadUser())
	if err != nil {
		t.Errorf("AddClient returned error: %v", err)
	}

	// Logging as the same user.
	loginUser := models.LoginUserPayload{
		Username: "Username",
		Password: "Password_123",
	}
	_, err = service.Login(context.Background(), &loginUser)
	if err != nil {
		t.Errorf("Error logging in: %v", err)
	}
}

func TestDefaultUserServiceRefreshSession(t *testing.T) {
	service := Setup()

	// Register the client
	apiErr := service.AddClient(context.Background(), ValidRegisterUserPayloadUser())
	if apiErr != nil {
		t.Fatalf("Failed to register client: %v", apiErr)
	}

	// Login to get refresh token
	loginPayload := &models.LoginUserPayload{
		Username: "Username",
		Password: "Password_123",
	}
	tokenGroup, apiErr := service.Login(context.Background(), loginPayload)
	if apiErr != nil {
		t.Fatalf("Login failed: %v", apiErr.Message)
	}

	// Decode refresh token manually to get claims
	parsedToken, err := jwt.ParseWithClaims(tokenGroup.RefreshToken, &auth.Claims{}, func(token *jwt.Token) (any, error) {
		return []byte("secret"), nil
	})
	if err != nil {
		t.Fatalf("Failed to parse token: %v", err)
	}

	claims, ok := parsedToken.Claims.(*auth.Claims)
	if !ok || !parsedToken.Valid {
		t.Fatalf("Invalid claims")
	}

	// Call RefreshSession with parsed claims
	newTokenGroup, apiErr := service.RefreshSession(context.Background(), *claims)
	if apiErr != nil {
		t.Fatalf("RefreshSession failed: %v", apiErr)
	}

	if newTokenGroup.AccessToken == "" || newTokenGroup.RefreshToken == "" {
		t.Errorf("Expected non-empty tokens")
	}
}
