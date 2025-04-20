package handlers

import (
	"api/auth"
	"api/config"
	"api/models"
	"api/repositories"
	"api/services"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	jwtware "github.com/gofiber/contrib/jwt"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Setup returns DefaultUserHandler
//
// The handler is mounted with repositories.MemoryUserRepository,
// repositories.MemoryTokenRepository, auth.JWTAuthenticator.
func Setup() *DefaultUserHandler {
	userRepository := repositories.NewMemoryUserRepository()
	tokenRepository := repositories.NewMemoryTokenRepository()
	authenticator := auth.NewJWTAuthenticator(config.AuthConfig{
		JWTSecret: "secret",
		Issuer:    "issuer",
	})
	service := services.NewDefaultUserService(userRepository, tokenRepository, authenticator)
	return NewDefaultUserHandler(service)
}

// SetUpWithAdmin returns DefaultUserHandler
//
// The handler is mounted with repositories.MemoryUserRepository,
// repositories.MemoryTokenRepository, auth.JWTAuthenticator.
// The admin account has been added to the repository, with the same credentials as
// ValidRegisterUserPayload and ValidUserLoginPayload.
func SetUpWithAdmin() *DefaultUserHandler {
	userRepository := repositories.NewMemoryUserRepository()
	hash, err := auth.HashPassword("Password_123")
	if err != nil {
		panic(fmt.Sprintf("Error hashing password: %v", err))
	}

	admin := models.NewUser(uuid.New(), "example@gmail.com", "Username", hash, models.Admin)
	err = userRepository.AddUser(context.Background(), admin)
	if err != nil {
		panic(fmt.Sprintf("Error adding user: %v", err))
	}

	tokenRepository := repositories.NewMemoryTokenRepository()
	authenticator := auth.NewJWTAuthenticator(config.AuthConfig{
		JWTSecret: "secret",
		Issuer:    "issuer",
	})
	service := services.NewDefaultUserService(userRepository, tokenRepository, authenticator)
	return NewDefaultUserHandler(service)
}

// ValidRegisterUserPayload returns io.Reader of valid models.RegisterClientPayload.
func ValidRegisterUserPayload() io.Reader {
	user := models.NewRegisterClientPayload("example@gmail.com", "Username", "Password_123")
	data, err := json.Marshal(user)
	if err != nil {
		panic(fmt.Sprintf("Failed to marshal register client payload: %v", err))
	}
	return bytes.NewReader(data)
}

// InvalidRegisterUserPayload returns io.Reader of invalid models.RegisterClientPayload.
func InvalidRegisterUserPayload() io.Reader {
	user := models.NewRegisterClientPayload("examplemail.com", "Username", "Password_123")
	data, err := json.Marshal(user)
	if err != nil {
		panic(fmt.Sprintf("Failed to marshal register client payload: %v", err))
	}
	return bytes.NewReader(data)
}

// ValidUserLoginPayload returns io.Reader of models.LoginUserPayload.
//
// The credentials are the same as ValidRegisterUserPayload.
func ValidUserLoginPayload() io.Reader {
	user := models.NewLoginUserPayload("Username", "Password_123")
	data, err := json.Marshal(user)
	if err != nil {
		panic(fmt.Sprintf("Failed to marshal user payload: %v", err))
	}
	return bytes.NewReader(data)
}

// Middleware return fiber.Handler used for authentication with JWT.
func Middleware() fiber.Handler {
	return jwtware.New(jwtware.Config{
		Claims: &auth.Claims{},
		SigningKey: jwtware.SigningKey{
			JWTAlg: jwt.SigningMethodHS256.Alg(),
			Key:    []byte("secret"),
		},
		SuccessHandler: func(c *fiber.Ctx) error {
			claims := c.Locals("user").(*jwt.Token).Claims.(*auth.Claims)
			c.Locals("user", claims)
			return c.Next()
		},
	})
}

// TestDefaultUserHandlerRegisterClient varifies that handler
// for registration succeeds with status http.StatusCreated,
// and attempt by another user to register with the same email
// or username result in fiber.StatusConflict
func TestDefaultUserHandlerRegisterClient(t *testing.T) {
	handler := Setup()
	app := fiber.New()
	app.Post("/", handler.RegisterClient())

	// The first attempt to register should succeed.
	req := httptest.NewRequest(http.MethodPost, "/", ValidRegisterUserPayload())
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("Invalid response code: %v expected 201", resp.StatusCode)
	}

	// The second attempt should fail.
	req = httptest.NewRequest(http.MethodPost, "/", ValidRegisterUserPayload())
	req.Header.Set("Content-Type", "application/json")
	resp, err = app.Test(req, -1)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("Invalid response code: %v expected 409", resp.StatusCode)
	}
}

// TestDefaultUserHandlerRegisterClientInvalidUser verifies that the handler for
// registration will return http.StatusBadRequest if the payload of the user is invalid
func TestDefaultUserHandlerRegisterClientInvalidUser(t *testing.T) {
	handler := Setup()
	app := fiber.New()
	app.Post("/", handler.RegisterClient())

	req := httptest.NewRequest(http.MethodPost, "/", InvalidRegisterUserPayload())
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("Invalid response code: %v expected 400", resp.StatusCode)
	}
}

// TestDefaultUserHandlerLogin verifies that the handler for login
// will correctly return models.TokenGroup and http.StatusOK when a user login with valid.
// If a user logins with incorrect credentials, the handler should return http.StatusUnauthorized
func TestDefaultUserHandlerLogin(t *testing.T) {
	handler := Setup()
	app := fiber.New()
	app.Post("/register", handler.RegisterClient())
	app.Post("/login", handler.Login())

	// Attempt to register a new user that should succeed.
	req := httptest.NewRequest(http.MethodPost, "/register", ValidRegisterUserPayload())
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("Invalid response code: %v expected 201", resp.StatusCode)
	}

	// Attempt to log in with the same credentials which should succeed.
	req = httptest.NewRequest(http.MethodPost, "/login", ValidUserLoginPayload())
	req.Header.Set("Content-Type", "application/json")
	resp, err = app.Test(req, -1)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Invalid response code: %v expected 200", resp.StatusCode)
	}

	// Check if the token are send correctly.
	var token models.TokenGroup
	err = json.NewDecoder(resp.Body).Decode(&token)
	if err != nil {
		t.Errorf("Failed to unmarshal tokens: %v", err)
	}

	// Attempt to log in with incorrect credentials.
	loginUser := models.NewLoginUserPayload("Username", "")
	data, err := json.Marshal(&loginUser)
	if err != nil {
		t.Fatalf("Failed to marshal login user payload: %v", err)
	}
	req = httptest.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	resp, err = app.Test(req, -1)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("Invalid response code: %v expected 200", resp.StatusCode)
	}
}

// TestDefaultUserHandlerRegisterUser verifies that admin can successfully register
// a new user. If the token that is sent is of auth.RefreshToken type,
// the result should be http.StatusUnauthorized.
func TestDefaultUserHandlerRegisterUser(t *testing.T) {
	handler := SetUpWithAdmin()
	app := fiber.New()
	app.Post("/register", Middleware(), handler.RegisterUser())
	app.Post("/login", handler.Login())

	// Attempt to log in as admin that should succeed.
	req := httptest.NewRequest(http.MethodPost, "/login", ValidUserLoginPayload())
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Invalid response code: %v expected 200", resp.StatusCode)
	}

	var token models.TokenGroup
	err = json.NewDecoder(resp.Body).Decode(&token)
	if err != nil {
		t.Fatalf("Failed to unmarshal tokens: %v", err)
	}

	// Attempt to register a new user as a delivery worker that should succeed.
	newUser := models.RegisterUserPayload{
		RegisterClientPayload: models.RegisterClientPayload{
			Email:    "another@gmail.com",
			Username: "DeliveryGuy",
			Password: "Delivery_123",
		},
		UserRole: models.Delivery,
	}
	data, err := json.Marshal(&newUser)
	if err != nil {
		t.Fatalf("Failed to marshal user payload: %v", err)
	}
	req = httptest.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	resp, err = app.Test(req, -1)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("Invalid response code: %v expected 201", resp.StatusCode)
	}

	req = httptest.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token.RefreshToken)
	resp, err = app.Test(req, -1)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("Invalid response code: %v expected 401", resp.StatusCode)
	}
}

// TestDefaultUserHandlerRegisterUserNotAdmin verifies that attempt to register
// a new user with a role is not possible without an admin token.
func TestDefaultUserHandlerRegisterUserNotAdmin(t *testing.T) {
	handler := Setup()
	app := fiber.New()
	app.Post("/register", handler.RegisterClient())
	app.Post("/login", handler.Login())
	app.Post("/register/user", Middleware(), handler.RegisterUser())

	// Attempt to register a new user that should succeed.
	req := httptest.NewRequest(http.MethodPost, "/register", ValidRegisterUserPayload())
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("Invalid response code: %v expected 201", resp.StatusCode)
	}

	// Attempt to log in with the same credentials which should succeed.
	req = httptest.NewRequest(http.MethodPost, "/login", ValidUserLoginPayload())
	req.Header.Set("Content-Type", "application/json")
	resp, err = app.Test(req, -1)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Invalid response code: %v expected 200", resp.StatusCode)
	}

	var token models.TokenGroup
	err = json.NewDecoder(resp.Body).Decode(&token)
	if err != nil {
		t.Errorf("Failed to unmarshal tokens: %v", err)
	}

	// Attempt to register a new user as a delivery worker that should not succeed,
	// because we the access token is for client.
	newUser := models.RegisterUserPayload{
		RegisterClientPayload: models.RegisterClientPayload{
			Email:    "another@gmail.com",
			Username: "DeliveryGuy",
			Password: "Delivery_123",
		},
		UserRole: models.Delivery,
	}
	data, err := json.Marshal(&newUser)
	if err != nil {
		t.Fatalf("Failed to marshal user payload: %v", err)
	}
	req = httptest.NewRequest(http.MethodPost, "/register/user", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	resp, err = app.Test(req, -1)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("Invalid response code: %v expected 401", resp.StatusCode)
	}
}
