package services

import (
	"api/auth"
	"api/config"
	"api/models"
	"api/repositories"
	"context"
	"testing"
)

func setup() UserService {
	userRepository := repositories.NewMemoryUserRepository()
	tokenRepository := repositories.NewMemoryTokenRepository()
	authenticator := auth.NewJWTAuthenticator(config.AuthConfig{
		JWTSecret: "secret",
		Issuer:    "issuer",
	})
	return NewDefaultUserService(userRepository, tokenRepository, authenticator)
}

func TestDefaultUserServiceAddValidUser(t *testing.T) {
	service := setup()
	user := models.NewRegisterClientPayload("validEmail@gmail.com", "ValidUsername", "ValidPassword_2")

	err := service.AddClient(context.Background(), user)
	if err != nil {
		t.Errorf("AddClient returned error: %v", err)
	}

	err = service.AddClient(context.Background(), user)
	if err == nil {
		t.Errorf("AddClient returned no error when adding the same user.")
	}
}

func TestDefaultUserServiceAddInvalidUser(t *testing.T) {
	service := setup()
	user := models.NewRegisterClientPayload("valid.com", "ValidUsername", "ValidPassword_2")

	err := service.AddClient(context.Background(), user)
	if err == nil {
		t.Errorf("AddClient returned no error when adding invalid user.")
	}
}

func TestDefaultUserServiceAddLogin(t *testing.T) {
	service := setup()

	user := models.NewRegisterClientPayload("validEmail@gmail.com", "ValidUsername", "ValidPassword_2")

	err := service.AddClient(context.Background(), user)
	if err != nil {
		t.Errorf("AddClient returned error: %v", err)
	}

	err = service.AddClient(context.Background(), user)
	if err == nil {
		t.Errorf("AddClient returned no error when adding the same user.")
	}

	loginUser := models.LoginUserPayload{
		Username: "ValidUsername",
		Password: "ValidPassword_2",
	}

	_, err = service.Login(context.Background(), &loginUser)
	if err != nil {
		t.Errorf("Error logging in: %v", err)
	}
}
