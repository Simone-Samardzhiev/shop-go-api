package handlers

import (
	"api/auth"
	"api/config"
	"api/models"
	"api/repositories"
	"api/services"
	"bytes"
	"encoding/json"
	"github.com/gofiber/fiber/v2"
	"net/http"
	"net/http/httptest"
	"testing"
)

func setup() *DefaultUserHandler {
	userRepository := repositories.NewMemoryUserRepository()
	authenticator := auth.NewJWTAuthenticator(config.AuthConfig{
		JWTSecret: "secret",
		Issuer:    "issue",
	})
	tokenRepository := repositories.NewMemoryTokenRepository()
	service := services.NewDefaultUserService(userRepository, tokenRepository, authenticator)
	return NewDefaultUserHandler(service)
}

func TestDefaultUserHandlerRegisterClient(t *testing.T) {
	handler := setup()
	app := fiber.New()
	app.Post("/", handler.RegisterClient())

	user := models.NewRegisterClientPayload("validEmail@gmail.com", "ValidUsername", "ValidPassword_1")
	data, err := json.Marshal(user)
	if err != nil {
		t.Errorf("Failed to marshal user data")
	}

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)

	if err != nil {
		t.Errorf("Failed to make request: %v", err)
	}
	if resp.StatusCode != fiber.StatusCreated {
		t.Errorf("Unexpected response code: %v", resp.StatusCode)
	}
}

func TestDefaultUserHandlerRegisterClientWithInvalidUser(t *testing.T) {
	handler := setup()
	app := fiber.New()
	app.Post("/", handler.RegisterClient())

	user := models.NewRegisterClientPayload("invalid@gmail", "ValidUsername", "ValidPassword_1")
	data, err := json.Marshal(user)
	if err != nil {
		t.Errorf("Failed to marshal user data")
	}

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)

	if err != nil {
		t.Errorf("Failed to make request: %v", err)
	}
	if resp.StatusCode != fiber.StatusBadRequest {
		t.Errorf("Unexpected response code: %v", resp.StatusCode)
	}
}

func TestDefaultUserHandlerLogin(t *testing.T) {
	handler := setup()
	app := fiber.New()
	app.Post("/register", handler.RegisterClient())
	app.Post("/login", handler.Login())

	user := models.NewRegisterClientPayload("validEmail@gmail.com", "ValidUsername", "ValidPassword_1")
	data, err := json.Marshal(user)
	if err != nil {
		t.Errorf("Failed to marshal user data")
	}

	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Errorf("Failed to make request for registering: %v", err)
	}
	if resp.StatusCode != fiber.StatusCreated {
		t.Errorf("Unexpected response code: %v", resp.StatusCode)
	}

	req = httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	resp, err = app.Test(req, -1)
	if err != nil {
		t.Errorf("Failed to make request for login: %v", err)
	}
	if resp.StatusCode != fiber.StatusOK {
		t.Errorf("Unexpected response code: %v", resp.StatusCode)
	}
}
