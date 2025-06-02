package handlers

import (
	"api/auth"
	"api/config"
	"api/models"
	"api/repositories"
	"api/services"
	"api/utils"
	"encoding/json"
	"fmt"
	jwtware "github.com/gofiber/contrib/jwt"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"net/http"
	"strings"
	"testing"
	"unicode"
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

func TestDefaultUserHandlerRegisterClient(t *testing.T) {
	handler := Setup()
	app := fiber.New()
	app.Post("/register", handler.RegisterClient())

	tests := []struct {
		name           string
		body           *models.RegisterClientPayload
		expectedStatus int
	}{
		{
			name:           "Valid payload",
			body:           utils.ValidRegisterClientPayload(),
			expectedStatus: http.StatusCreated,
		},
		{
			name:           "Already registered",
			body:           utils.ValidRegisterClientPayload(),
			expectedStatus: http.StatusConflict,
		}, {
			name:           "Invalid payload(invalid email)",
			body:           models.NewRegisterClientPayload("invalid@gmail", "Username123", "Password_123"),
			expectedStatus: http.StatusBadRequest,
		}, {
			name:           "Invalid payload(invalid username)",
			body:           models.NewRegisterClientPayload("email@example.com", "user", "Password_123"),
			expectedStatus: http.StatusBadRequest,
		}, {
			name:           "Invalid payload(invalid password)",
			body:           models.NewRegisterClientPayload("email@example.com", "Username123", "Password"),
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res := utils.SendRequestTest(t, app, "POST", "/register", "", test.body)
			if res.StatusCode != test.expectedStatus {
				t.Errorf("Expected status code %v, got %v", test.expectedStatus, res.StatusCode)
			}
		})
	}
}

func BenchmarkDefaultUserHandlerRegisterClient(b *testing.B) {
	handler := Setup()
	app := fiber.New()
	app.Post("/register", handler.RegisterClient())

	for b.Loop() {
		id := uuid.New().String()
		email := fmt.Sprintf("example%s@email.com", id)
		username := id
		password := "Password_123"

		res := utils.SendRequestBenchmark(b, app, "POST", "/register", "", models.NewRegisterClientPayload(email, username, password))
		if res.StatusCode != http.StatusCreated {
			b.Fatalf("Expected status code %v, got %v", http.StatusCreated, res.StatusCode)
		}
	}
}

func FuzzDefaultUserHandlerRegisterClient(f *testing.F) {
	handler := Setup()
	app := fiber.New()
	app.Post("/register", handler.RegisterClient())
	expectedStatusCodes := map[int]bool{
		http.StatusCreated:    true,
		http.StatusBadRequest: true,
		http.StatusConflict:   true,
	}

	f.Add("example@email.com", "Username123", "Password_123")
	f.Add("", "", "")
	f.Add("asdasdfjdsfjkshjdfjhsadjkflasjfhdsdfjhhsdfhldkhja", "fhjahjdfhjlksadlfhjsfdhjfhjadfshjkdfahjkshkjsdf", "fjhashgfaghsdfghjsghjkdfghksgdhfjhgfkdsjshgfjghs")

	f.Fuzz(func(t *testing.T, email, username, password string) {
		res := utils.SendRequestTest(t, app, "POST", "/register", "", models.NewRegisterClientPayload(email, username, password))
		if !expectedStatusCodes[res.StatusCode] {
			t.Fatalf("Unexpected status code %v", res.StatusCode)
		}
	})
}

func TestDefaultUserHandlerLogin(t *testing.T) {
	handler := SetupWithUsers()
	app := fiber.New()
	app.Post("/login", handler.Login())

	tests := []struct {
		name           string
		body           *models.LoginUserPayload
		expectedStatus int
	}{
		{
			name:           "Login as admin",
			body:           utils.ValidAdminLoginPayload(),
			expectedStatus: http.StatusOK,
		}, {
			name:           "Login as client",
			body:           utils.ValidLoginClintPayload(),
			expectedStatus: http.StatusOK,
		}, {
			name:           "Wrong credentials",
			body:           models.NewLoginUserPayload("someEmail@gmail.com", "someUsername"),
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res := utils.SendRequestTest(t, app, "POST", "/login", "", test.body)
			if res.StatusCode != test.expectedStatus {
				t.Errorf("Expected status code %v, got %v", test.expectedStatus, res.StatusCode)
			}
		})
	}
}

func BenchmarkDefaultUserHandlerLogin(b *testing.B) {
	handler := SetupWithUsers()
	app := fiber.New()
	app.Post("/login", handler.Login())

	for b.Loop() {
		res := utils.SendRequestBenchmark(b, app, "POST", "/login", "", utils.ValidLoginClintPayload())
		if res.StatusCode != http.StatusOK {
			b.Fatalf("Expected status code %v, got %v", http.StatusOK, res.StatusCode)
		}
	}
}

func FuzzDefaultUserHandlerLogin(f *testing.F) {
	handler := SetupWithUsers()
	app := fiber.New()
	app.Post("/login", handler.Login())

	expectedStatusCodes := map[int]bool{
		http.StatusOK:           true,
		http.StatusUnauthorized: true,
	}

	f.Add("UserExample", "Password_123")
	f.Add("Username1", "Password_123")
	f.Add("", "")

	f.Fuzz(func(t *testing.T, username, password string) {
		res := utils.SendRequestTest(t, app, "POST", "/login", "", models.NewLoginUserPayload(username, username))
		if !expectedStatusCodes[res.StatusCode] {
			t.Fatalf("Unexpected status code %v", res.StatusCode)
		}
	})
}

func TestDefaultUserHandlerRegisterUser(t *testing.T) {
	handler := SetupWithUsers()
	app := fiber.New()
	app.Post("/register", Middleware(), handler.RegisterUser())
	app.Post("/login", handler.Login())

	adminTokens := utils.SendLoginAsAdminTest(t, app, "/login")
	clientTokens := utils.SendLoginAsClientTest(t, app, "/login")

	tests := []struct {
		name           string
		body           *models.RegisterUserPayload
		token          string
		expectedStatus int
	}{
		{
			name:           "Register new user that works in workshop as admin",
			body:           models.NewRegisterUserPayload("email@example.com", "Username123", "Password_123", models.Workshop),
			token:          adminTokens.AccessToken,
			expectedStatus: http.StatusCreated,
		}, {
			name:           "Register new user that works in workshop as admin with invalid token",
			body:           models.NewRegisterUserPayload("email@example.com", "Username123", "Password_123", models.Workshop),
			token:          clientTokens.AccessToken,
			expectedStatus: http.StatusUnauthorized,
		}, {
			name:           "Register new user that works in workshop as admin without any token",
			body:           models.NewRegisterUserPayload("email@example.com", "Username123", "Password_123", models.Workshop),
			token:          "",
			expectedStatus: http.StatusUnauthorized,
		}, {
			name:           "Register new user that works in workshop as admin with refresh token",
			body:           models.NewRegisterUserPayload("email@example.com", "Username123", "Password_123", models.Workshop),
			token:          adminTokens.RefreshToken,
			expectedStatus: http.StatusUnauthorized,
		}, {
			name:           "Register new user with invalid role that works in workshop as admin",
			body:           models.NewRegisterUserPayload("email@example.com", "Username123", "Password_123", "InvalidRole"),
			token:          adminTokens.AccessToken,
			expectedStatus: http.StatusBadRequest,
		}, {
			name:           "Register new user, whose email and username are already in use, with that works in workshop as admin",
			body:           models.NewRegisterUserPayload("email@example.com", "Username123", "Password_123", models.Workshop),
			token:          adminTokens.AccessToken,
			expectedStatus: http.StatusConflict,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res := utils.SendRequestTest(t, app, "POST", "/register", test.token, test.body)
			if res.StatusCode != test.expectedStatus {
				t.Errorf("Expected status code %v, got %v", test.expectedStatus, res.StatusCode)
			}
		})
	}
}

func BenchmarkDefaultUserHandlerRegisterUser(b *testing.B) {
	handler := SetupWithUsers()
	app := fiber.New()
	app.Post("/register", Middleware(), handler.RegisterUser())
	app.Post("/login", handler.Login())

	adminTokens := utils.SendLoginAsAdminBenchmark(b, app, "/login")

	for b.Loop() {
		id := uuid.New().String()
		email := fmt.Sprintf("example%s@email.com", id)
		username := id
		password := "Password_123"

		req := utils.SendRequestBenchmark(
			b,
			app,
			"POST",
			"/register",
			adminTokens.AccessToken,
			models.NewRegisterUserPayload(email, username, password, models.Client),
		)
		if req.StatusCode != http.StatusCreated {
			b.Fatalf("Expected status code %v, got %v", http.StatusCreated, req.StatusCode)
		}
	}
}

func FuzzDefaultUserHandlerRegisterUser(f *testing.F) {
	handler := SetupWithUsers()
	app := fiber.New()
	app.Post("/register", Middleware(), handler.RegisterUser())
	app.Post("/login", handler.Login())

	expectedStatusCodes := map[int]bool{
		http.StatusCreated:      true,
		http.StatusBadRequest:   true,
		http.StatusConflict:     true,
		http.StatusUnauthorized: true,
	}

	adminTokens := utils.SendLoginAsAdminFuzz(f, app, "/login")
	clientTokens := utils.SendLoginAsClientFuzz(f, app, "/login")

	f.Add(adminTokens.AccessToken, "example@email.com", "Username", "Password_124", models.Workshop)
	f.Add(clientTokens.AccessToken, "", "", "", "")
	f.Add(clientTokens.RefreshToken, "invalidEmail", "user", "pass", "invalidRole")
	f.Add(adminTokens.RefreshToken, "email@example.com", "NewUser", "NewPassword_123", models.Client)

	f.Fuzz(func(t *testing.T, token, email, username, password, role string) {
		// Validate that the token is printable ASCII
		var builder strings.Builder
		builder.Grow(len(token))
		for _, c := range token {
			if c >= 0x20 && c <= 0x7E {
				builder.WriteRune(c)
			}
		}

		res := utils.SendRequestTest(
			t,
			app,
			"POST",
			"/register",
			builder.String(),
			models.NewRegisterUserPayload(email, username, password, role),
		)
		if !expectedStatusCodes[res.StatusCode] {
			t.Fatalf("Unexpected status code %v", res.StatusCode)
		}
	})
}

func TestDefaultUserHandlerGetUsers(t *testing.T) {
	handler := SetupWithUsers()
	app := fiber.New()
	app.Post("/login", handler.Login())
	app.Get("/users", Middleware(), handler.GetUsers())

	tokens := utils.SendLoginAsAdminTest(t, app, "/login")

	tests := []struct {
		name           string
		expectedStatus int
		query          string
		token          string
		expectedEmails []string
	}{
		{
			name:           "Get users as admin with limit 4 and page 1",
			expectedStatus: http.StatusOK,
			query:          "?limit=4&page=1",
			token:          tokens.AccessToken,
			expectedEmails: []string{"admin@example.com", "email1@example.com", "email2@example.com", "email3@example.com"},
		}, {
			name:           "Get users as admin with limit 4 and page 2",
			expectedStatus: http.StatusOK,
			query:          "?limit=4&page=2",
			token:          tokens.AccessToken,
			expectedEmails: []string{"email4@example.com", "email5@example.com", "email6@example.com", "email7@example.com"},
		}, {
			name:           "Get users as admin with limit 4 and page 3",
			expectedStatus: http.StatusOK,
			query:          "?limit=4&page=3",
			token:          tokens.AccessToken,
			expectedEmails: []string{"email8@example.com", "email9@example.com"},
		}, {
			name:           "Get users as admin with limit 4 and page 4",
			expectedStatus: http.StatusOK,
			token:          tokens.AccessToken,
			query:          "?limit=4&page=4",
			expectedEmails: []string{},
		}, {
			name:           "Get users as admin with limit 4 and page 1 with role client",
			expectedStatus: http.StatusOK,
			query:          "?limit=4&page=1&role=client",
			token:          tokens.AccessToken,
			expectedEmails: []string{"email4@example.com", "email5@example.com", "email6@example.com", "email9@example.com"},
		}, {
			name:           "Missing token",
			expectedStatus: http.StatusUnauthorized,
			query:          "",
			token:          "",
			expectedEmails: nil,
		}, {
			name:           "Invalid token",
			expectedStatus: http.StatusUnauthorized,
			query:          "",
			token:          tokens.RefreshToken,
			expectedEmails: nil,
		}, {
			name:           "Missing query",
			expectedStatus: http.StatusOK,
			query:          "?limit=100&page=-2",
			token:          tokens.AccessToken,
			expectedEmails: []string{"admin@example.com", "email1@example.com", "email2@example.com", "email3@example.com", "email4@example.com", "email5@example.com", "email6@example.com", "email7@example.com", "email8@example.com", "email9@example.com"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res := utils.SendRequestTest(t, app, "GET", "/users"+test.query, test.token, test.query)
			if res.StatusCode != test.expectedStatus {
				t.Fatalf("Expected status code %v, got %v", test.expectedStatus, res.StatusCode)
			}
			if test.expectedStatus == http.StatusUnauthorized {
				return
			}

			var users []models.UserInfo
			err := json.NewDecoder(res.Body).Decode(&users)
			if err != nil {
				t.Fatalf("Error unmarshalling response body: %v", err)
			}
			if len(users) != len(test.expectedEmails) {
				t.Fatalf("Expected %v users, got %v", len(test.expectedEmails), len(users))
			}

			for i, _ := range users {
				if users[i].Email != test.expectedEmails[i] {
					t.Fatalf("Expected email %v, got %v", test.expectedEmails[i], users[i].Email)
				}
			}
		})
	}
}

func BenchmarkDefaultUserHandlerGetUsers(b *testing.B) {
	handler := SetupWithUsers()
	app := fiber.New()
	app.Post("/login", handler.Login())
	app.Get("/users", Middleware(), handler.GetUsers())

	tokens := utils.SendLoginAsAdminBenchmark(b, app, "/login")

	for b.Loop() {
		res := utils.SendRequestBenchmark(b, app, "GET", "/users?limit=100&page=1", tokens.AccessToken, "?limit=100&page=1")
		if res.StatusCode != http.StatusOK {
			b.Fatalf("Expected status code %v, got %v", http.StatusOK, res.StatusCode)
		}
	}
}

func FuzzDefaultUserHandlerGetUsers(f *testing.F) {
	handler := SetupWithUsers()
	app := fiber.New()
	app.Post("/login", handler.Login())
	app.Get("/users", Middleware(), handler.GetUsers())

	expectedStatusCodes := map[int]bool{
		http.StatusOK:           true,
		http.StatusUnauthorized: true,
		http.StatusBadRequest:   true,
		http.StatusNotFound:     true,
	}

	tokens := utils.SendLoginAsAdminFuzz(f, app, "/login")

	f.Add(tokens.AccessToken, "?limit=100&page=1")
	f.Fuzz(func(t *testing.T, token, query string) {
		// Validate that the token is printable ASCII
		var tokenBuilder strings.Builder
		tokenBuilder.Grow(len(token))
		for _, c := range token {
			if c >= 0x20 && c <= 0x7E {
				tokenBuilder.WriteRune(c)
			}
		}

		// Validate that the query is printable ASCII
		var queryBuilder strings.Builder
		for _, c := range query {
			if unicode.IsLetter(c) || c == '=' || c == '&' || c == '?' {
				queryBuilder.WriteRune(c)
			}
		}
		finalQuery := queryBuilder.String()
		if len(finalQuery) > 0 {
			if finalQuery[0] != '?' {
				finalQuery = "?" + finalQuery
			}
		}
		query = finalQuery

		res := utils.SendRequestTest(t, app, "GET", "/users"+query, tokenBuilder.String(), query)
		if !expectedStatusCodes[res.StatusCode] {
			t.Fatalf("Unexpected status code %v", res.StatusCode)
		}
	})
}
