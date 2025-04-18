package services

import (
	"api/auth"
	"api/config"
	"api/models"
	"api/repositories"
	"context"
	"testing"
)

func TestDefaultUserServiceAddValidUser(t *testing.T) {
	repo := repositories.NewMemoryUserRepository()
	authenticator := auth.NewJWTAuthenticator(config.AuthConfig{
		JWTSecret: "secret",
		Issuer:    "issuer",
	})
	service := NewDefaultUserService(repo, authenticator)
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
	repo := repositories.NewMemoryUserRepository()
	authenticator := auth.NewJWTAuthenticator(config.AuthConfig{
		JWTSecret: "secret",
		Issuer:    "issuer",
	})
	service := NewDefaultUserService(repo, authenticator)
	user := models.NewRegisterClientPayload("valid.com", "ValidUsername", "ValidPassword_2")

	err := service.AddClient(context.Background(), user)
	if err == nil {
		t.Errorf("AddClient returned no error when adding invalid user.")
	}
}
