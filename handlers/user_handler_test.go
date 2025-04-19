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
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// setup used for easier creation of DefaultUserHandler
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

// validUser returns io.Reader to a valid user.
func validUser() (io.Reader, error) {
	user := models.NewRegisterClientPayload("validEmail@gmail.com", "ValidUsername", "ValidPassword_1")
	data, err := json.Marshal(user)
	return bytes.NewReader(data), err
}

// validUser returns io.Reader to a invalid user.
func invalidUser() (io.Reader, error) {
	user := models.NewRegisterClientPayload("invalid", "ValidUsername", "ValidPassword_1")
	data, err := json.Marshal(user)
	return bytes.NewReader(data), err
}

// TestDefaultUserHandlerRegisterClient test if registration with valid payload works.
func TestDefaultUserHandlerRegisterClient(t *testing.T) {
	// Creating the app.
	handler := setup()
	app := fiber.New()
	app.Post("/", handler.RegisterClient())

	user, err := validUser()
	if err != nil {
		t.Errorf("Error creating a valid user: %v", err)
	}

	// Creating a new request.
	req := httptest.NewRequest(http.MethodPost, "/", user)
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)

	// Checking if the request is successful.
	if err != nil {
		t.Errorf("Failed to make request: %v", err)
	}
	if resp.StatusCode != fiber.StatusCreated {
		t.Errorf("Unexpected response code: %v", resp.StatusCode)
	}
}

func TestDefaultUserHandlerRegisterClientWithInvalidUser(t *testing.T) {
	// Creating an app.
	handler := setup()
	app := fiber.New()
	app.Post("/", handler.RegisterClient())

	user, err := invalidUser()
	if err != nil {
		t.Errorf("Error creating invalid: %v", err)
	}

	// Creating a new request.
	req := httptest.NewRequest(http.MethodPost, "/", user)
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)

	// Check if the status code is expected.
	if err != nil {
		t.Errorf("Failed to make request: %v", err)
	}
	if resp.StatusCode != fiber.StatusBadRequest {
		t.Errorf("Unexpected response code: %v", resp.StatusCode)
	}
}

// TestDefaultUserHandlerRegisterWithSameEmailOrCredentials if the handler returns an error
// if the user tries registering with the same email or username.
func TestDefaultUserHandlerRegisterWithSameEmailOrCredentials(t *testing.T) {
	handler := setup()
	app := fiber.New()
	app.Post("/", handler.RegisterClient())

	user, err := validUser()
	if err != nil {
		t.Errorf("Error creating a valid user: %v", err)
	}

	// Making a new register request.
	req := httptest.NewRequest(http.MethodPost, "/", user)
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)

	// Check if the request was successful.
	if err != nil {
		t.Errorf("Failed to make request: %v", err)
	}
	if resp.StatusCode != fiber.StatusCreated {
		t.Errorf("Unexpected response code: %v", resp.StatusCode)
	}

	// Send the same request with the same credentials.
	req = httptest.NewRequest(http.MethodPost, "/", user)
	req.Header.Set("Content-Type", "application/json")
	resp, err = app.Test(req, -1)

	// Check if the request was failed with StatusConflict.
	if err != nil {
		t.Errorf("Failed to make request: %v", err)
	}
	if resp.StatusCode != fiber.StatusConflict {
		t.Errorf("Unexpected response code: %v", resp.StatusCode)
	}
}

// TestDefaultUserHandlerLogin tests if login handler works expectedly.
func TestDefaultUserHandlerLogin(t *testing.T) {
	// Creating the app.
	handler := setup()
	app := fiber.New()
	app.Post("/register", handler.RegisterClient())
	app.Post("/login", handler.Login())

	user, err := validUser()
	if err != nil {
		t.Errorf("Error creating a valid user: %v", err)
	}

	// Creating a new request to register.
	req := httptest.NewRequest(http.MethodPost, "/register", user)
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)

	//  Check if the request is successful.
	if err != nil {
		t.Errorf("Failed to make request for registering: %v", err)
	}
	if resp.StatusCode != fiber.StatusCreated {
		t.Errorf("Unexpected response code: %v", resp.StatusCode)
	}

	// Creating a new request for login.
	req = httptest.NewRequest(http.MethodPost, "/login", user)
	req.Header.Set("Content-Type", "application/json")
	resp, err = app.Test(req, -1)

	//  Check if the request is successful.
	if err != nil {
		t.Errorf("Failed to make request for login: %v", err)
	}
	if resp.StatusCode != fiber.StatusOK {
		t.Errorf("Unexpected response code: %v", resp.StatusCode)
	}
}
