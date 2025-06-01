package handlers

import (
	"api/auth"
	"api/config"
	"api/models"
	"api/repositories"
	"api/services"
	"api/utils"
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Setup returns DefaultUserHandler.
//
// The service is configured with repositories.MemoryUserRepository,
// repositories.MemoryTokenRepository and auth.JWTAuthenticator.
func Setup() *DefaultUserHandler {
	userRepo := repositories.NewMemoryUserRepository()
	tokenRepo := repositories.NewMemoryTokenRepository()
	authenticator := auth.NewJWTAuthenticator(config.AuthConfig{
		JWTSecret: "secret",
		Issuer:    "issuer",
	})
	userService := services.NewDefaultUserService(userRepo, tokenRepo, authenticator)
	return NewDefaultUserHandler(userService)
}

// SetupWithUsers returns DefaultUserHandler.
//
// The service is configured with repositories.MemoryUserRepositoryWithUsers,
// repositories.MemoryTokenRepository and auth.JWTAuthenticator.
//
// The users are created with the method repositories.NewMemoryUserRepositoryWithUsers.
func SetupWithUsers() *DefaultUserHandler {
	userRepo, err := repositories.NewMemoryUserRepositoryWithUsers()
	if err != nil {
		panic(fmt.Errorf("error creating memory user repository: %v", err))
	}
	tokenRepo := repositories.NewMemoryTokenRepository()
	authenticator := auth.NewJWTAuthenticator(config.AuthConfig{
		JWTSecret: "secret",
		Issuer:    "issuer",
	})
	userService := services.NewDefaultUserService(userRepo, tokenRepo, authenticator)
	return NewDefaultUserHandler(userService)
}

func TestDefaultUserHandlerRegisterClient(t *testing.T) {
	handler := Setup()
	app := fiber.New()
	err := utils.SendRegisterRequest(app, handler.RegisterClient())
	if err != nil {
		t.Fatalf("SendRegisterRequest returned error: %v", err)
	}
}

func BenchmarkDefaultUserHandlerRegisterClient(b *testing.B) {
	handler := Setup()
	app := fiber.New()
	app.Post("/register", handler.RegisterClient())
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		b.StopTimer()

		uniqueID := uuid.New().String()
		payload := models.NewRegisterClientPayload(
			fmt.Sprintf("email%s@example.com", uniqueID),
			uniqueID,
			"Password_123",
		)

		data, err := json.Marshal(payload)
		if err != nil {
			b.Fatalf("json.Marshal returned error: %v", err)
		}
		buffer := bytes.NewBuffer(data)
		req := httptest.NewRequest(http.MethodPost, "/register", buffer)
		req.Header.Set("Content-Type", "application/json")

		b.StartTimer()

		response, err := app.Test(req, -1)
		if err != nil {
			b.Fatalf("Request failed: %v", err)
		}

		if response.StatusCode != http.StatusCreated {
			b.Fatalf("invalid response code: %v expected 201", response.StatusCode)
		}
	}
}
