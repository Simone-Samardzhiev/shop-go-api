package handlers

import (
	"api/auth"
	"api/config"
	"api/models"
	"api/repositories"
	"api/services"
	"api/utils"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	jwtware "github.com/gofiber/contrib/jwt"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
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

// Middleware returns middleware for JWT authentication.
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
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			return c.Status(http.StatusUnauthorized).JSON(utils.InvalidTokenAPIError())
		},
	})
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
		req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(data))
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

	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(data))
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

	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(data))
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

// TestDefaultUserHandlerRefreshSession tests that refreshing the session works.
func TestDefaultUserHandlerRefreshSession(t *testing.T) {
	handler := SetupWithUsers()
	app := fiber.New()
	app.Post("/refresh-session", Middleware(), handler.RefreshSession())
	tokens, err := utils.SendLoginRequest(app, handler.Login())
	if err != nil {
		t.Fatalf("request failed with error: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/refresh-session", nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tokens.RefreshToken))
	res, err := app.Test(req, -1)

	if err != nil {
		t.Fatalf("request failed with error: %v", err)
	}

	if res.StatusCode != http.StatusOK {
		t.Fatalf("invalid response code: %v expected 200", res.StatusCode)
	}

	var newTokens models.TokenGroup
	err = json.NewDecoder(res.Body).Decode(&newTokens)
	if err != nil {
		t.Fatalf("decoding response failed with error: %v", err)
	}

	if newTokens.AccessToken == "" || newTokens.RefreshToken == "" {
		t.Errorf("Expected non-empty tokens")
	}
}

// BenchmarkDefaultUserHandlerRefreshSession benchmarks the RefreshSession method.
func BenchmarkDefaultUserHandlerRefreshSession(b *testing.B) {
	handler := SetupWithUsers()
	app := fiber.New()
	app.Post("/refresh-session", Middleware(), handler.RefreshSession())
	tokens, err := utils.SendLoginRequest(app, handler.Login())
	if err != nil {
		b.Fatalf("request failed with error: %v", err)
	}
	refreshToken := tokens.RefreshToken
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		b.StopTimer()
		req := httptest.NewRequest(http.MethodPost, "/refresh-session", nil)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", refreshToken))

		b.StartTimer()
		res, err := app.Test(req, -1)
		if err != nil {
			b.Fatalf("request failed with error: %v", err)
		}
		b.StopTimer()

		if res.StatusCode != http.StatusOK {
			b.Fatalf("invalid response code: %v expected 200", res.StatusCode)
		}

		var newTokens models.TokenGroup
		err = json.NewDecoder(res.Body).Decode(&newTokens)
		if err != nil {
			b.Fatalf("decoding response failed with error: %v", err)
		}

		if newTokens.AccessToken == "" || newTokens.RefreshToken == "" {
			b.Errorf("Expected non-empty tokens")
		}
		refreshToken = newTokens.RefreshToken
	}
}

// FuzzDefaultUserHandlerRefreshSession fuzzes the RefreshSession method.
func FuzzDefaultUserHandlerRefreshSession(f *testing.F) {
	handler := SetupWithUsers()
	app := fiber.New()
	app.Post("/refresh-session", Middleware(), handler.RefreshSession())
	tokens, err := utils.SendLoginRequest(app, handler.Login())
	if err != nil {
		f.Fatalf("request failed with error: %v", err)
	}

	f.Add(tokens.RefreshToken)
	f.Add("")
	f.Add("refresh-token")
	f.Add("dasdhjafjgksgakldfgkhashfkgashdfgyujsdygfysadgfasgkyhdfgkhjskghdf")

	f.Fuzz(func(t *testing.T, refreshToken string) {
		req := httptest.NewRequest(http.MethodPost, "/refresh-session", nil)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", base64.StdEncoding.EncodeToString([]byte(refreshToken))))

		res, err := app.Test(req, -1)
		if err != nil {
			t.Fatalf("request failed with error: %v", err)
		}

		if res.StatusCode == http.StatusOK {
			var newTokens models.TokenGroup
			err = json.NewDecoder(res.Body).Decode(&newTokens)
			if err != nil {
				t.Errorf("decoding response failed with error: %v", err)
			}
			if newTokens.AccessToken == "" || newTokens.RefreshToken == "" {
				t.Fatalf("Expected non-empty tokens")
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

// TestDefaultUserHandlerRefreshSessionWithInvalidToken tests that refreshing the session fails with invalid token.
func TestDefaultUserHandlerRefreshSessionWithInvalidToken(t *testing.T) {
	handler := Setup()
	app := fiber.New()
	app.Post("/refresh-session", Middleware(), handler.RefreshSession())

	req := httptest.NewRequest(http.MethodPost, "/refresh-session", nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer invalid-token")

	res, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("request failed with error: %v", err)
	}

	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("invalid response code: %v expected 401", res.StatusCode)
	}
}
