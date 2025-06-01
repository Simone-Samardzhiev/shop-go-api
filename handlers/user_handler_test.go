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

// TestDefaultUserHandlerRegisterClient tests that adding valid clients works.
func TestDefaultUserHandlerRegisterClient(t *testing.T) {
	handler := Setup()
	app := fiber.New()
	err := utils.SendRegisterRequest(app, handler.RegisterClient())
	if err != nil {
		t.Fatalf("request failed with error: %v", err)
	}
}

// BenchmarkDefaultUserHandlerRegisterClient benchmarks the RegisterClient method.
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
			b.Fatalf("marshaling data returned error: %v", err)
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

// FuzzDefaultUserHandlerRegisterClient fuzzes the RegisterClient method.
func FuzzDefaultUserHandlerRegisterClient(f *testing.F) {
	handler := Setup()
	app := fiber.New()
	app.Post("/register", handler.RegisterClient())

	f.Add("example@email.com", "Username", "Password_123")
	f.Add("email@", "user", "password")
	f.Fuzz(func(t *testing.T, email, username, password string) {
		payload := models.NewRegisterClientPayload(email, username, password)
		data, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshaling data returned error: %v", err)
		}

		req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(data))
		req.Header.Set("Content-Type", "application/json")

		res, err := app.Test(req, -1)
		if err != nil {
			t.Fatalf("request failed with error: %v", err)
		}

		if res.StatusCode != http.StatusCreated && res.StatusCode != http.StatusBadRequest && res.StatusCode != http.StatusConflict {
			t.Fatalf("invalid response code: %v expected 201, 400 or 409", res.StatusCode)
		}
	})
}

// TestDefaultUserHandlerRegisterClientWithInvalidPayload tests that adding invalid clients fails.
func TestDefaultUserHandlerRegisterClientWithInvalidPayload(t *testing.T) {
	handler := Setup()
	app := fiber.New()
	app.Post("/register", handler.RegisterClient())

	payload := utils.InvalidRegisterClientPayload()
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshaling data returned error: %v", err)
	}
	buffer := bytes.NewBuffer(data)

	req := httptest.NewRequest(http.MethodPost, "/register", buffer)
	req.Header.Set("Content-Type", "application/json")

	res, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("request failed with error: %v", err)
	}

	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid response code: %v expected 400", res.StatusCode)
	}
}

// TestDefaultUserHandlerRegisterClientWithExistingEmailAndUsername tests
// that adding clients with existing email and username fails.
func TestDefaultUserHandlerRegisterClientWithExistingEmailAndUsername(t *testing.T) {
	handler := SetupWithUsers()
	app := fiber.New()
	app.Post("/register", handler.RegisterClient())

	payload := utils.ValidRegisterClientPayload()
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshaling data returned error: %v", err)
	}
	buffer := bytes.NewBuffer(data)

	req := httptest.NewRequest(http.MethodPost, "/register", buffer)
	req.Header.Set("Content-Type", "application/json")
	res, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("request failed with error: %v", err)
	}

	if res.StatusCode != http.StatusConflict {
		t.Fatalf("invalid response code: %v expected 409", res.StatusCode)
	}
}

// TestDefaultUserHandlerLogin tests that login works.
func TestDefaultUserHandlerLogin(t *testing.T) {
	handler := SetupWithUsers()
	app := fiber.New()
	_, err := utils.SendLoginRequest(app, handler.Login())
	if err != nil {
		t.Fatalf("request failed with error: %v", err)
	}
}

// BenchmarkDefaultUserHandlerLogin benchmarks the Login method.
func BenchmarkDefaultUserHandlerLogin(b *testing.B) {
	handler := SetupWithUsers()
	app := fiber.New()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := utils.SendLoginRequest(app, handler.Login())
		if err != nil {
			b.Fatalf("request failed with error: %v", err)
		}
	}
}

// FuzzDefaultUserHandlerLogin fuzzes the Login method.
func FuzzDefaultUserHandlerLogin(f *testing.F) {
	handler := SetupWithUsers()
	app := fiber.New()
	app.Post("/login", handler.Login())

	f.Add("Username1", "Password_123")
	f.Add("Username2", "Password_123")
	f.Add("", "")
	f.Add("sdajhsdjkhasjhkdjkasdjkashjdhjkashjbkdjhkasjdhlahjlsdjhlashkldhkasdhklahklsdhklashkldlahksjdlkhahlsjkdhkljasdjhlshjldjhasdjahjsdjlhashdjdajhsdhjahjsdjhasdhjashdljajhlsdhjasjhdahsdhjasdhjlhjsad", "jhdhjasjhdhjksadkgjasdghkaghjfdsghkasdgkasgkdgjkasdgjkagjsdhjsdhjshjdhjasdjhashjdakhjsd")
	f.Fuzz(func(t *testing.T, username, password string) {
		payload := models.NewLoginUserPayload(username, password)

		data, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshaling data returned error: %v", err)
		}

		req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(data))
		req.Header.Set("Content-Type", "application/json")
		res, err := app.Test(req, -1)
		if err != nil {
			t.Fatalf("request failed with error: %v", err)
		}

		if res.StatusCode == http.StatusOK {
			var tokens models.TokenGroup
			err = json.NewDecoder(res.Body).Decode(&tokens)
			if err != nil {
				t.Fatalf("decoding response failed with error: %v", err)
			}
		} else if res.StatusCode == http.StatusUnauthorized {
			var errorResponse utils.APIError
			err = json.NewDecoder(res.Body).Decode(&errorResponse)
			if err != nil {
				t.Fatalf("decoding response failed with error: %v", err)
			}
		} else {
			t.Fatalf("invalid response code: %v expected 200 or 401", res.StatusCode)
		}
	})
}
