package services

import (
	"api/auth"
	"api/config"
	"api/models"
	"api/repositories"
	"context"
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

// TestDefaultUserServiceAddValidUser verifies that adding a valid user succeeds, and
// an attempt to add the same user result in an error.
func TestDefaultUserServiceAddValidUser(t *testing.T) {
	service := Setup()

	user := models.NewRegisterClientPayload("validEmail@gmail.com", "ValidUsername", "ValidPassword_2")

	// The First attempt should succeed.
	err := service.AddClient(context.Background(), user)
	if err != nil {
		t.Errorf("AddClient returned error: %v", err)
	}

	// The second attempt should fail.
	err = service.AddClient(context.Background(), user)
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
	user := models.NewRegisterClientPayload("validEmail@gmail.com", "ValidUsername", "ValidPassword_2")
	err := service.AddClient(context.Background(), user)
	if err != nil {
		t.Errorf("AddClient returned error: %v", err)
	}

	// Logging as the same user.
	loginUser := models.LoginUserPayload{
		Username: "ValidUsername",
		Password: "ValidPassword_2",
	}
	_, err = service.Login(context.Background(), &loginUser)
	if err != nil {
		t.Errorf("Error logging in: %v", err)
	}
}
