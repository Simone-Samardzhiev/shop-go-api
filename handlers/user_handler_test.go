package handlers_test

import (
	"api/auth"
	"api/config"
	"api/handlers"
	"api/models"
	"api/repositories"
	"api/services"
	"api/testutils"
	"api/utils"
	"bytes"
	"encoding/json"
	jwtware "github.com/gofiber/contrib/jwt"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"net/http"
	"net/url"
	"strconv"
	"testing"
)

// DefaultUserHandler creates a new instance of DefaultUserHandler with users.
func DefaultUserHandler() (*handlers.DefaultUserHandler, error) {
	userRepo, err := testutils.NewMemoryUserRepositoryWithUsers()
	if err != nil {
		return nil, err
	}
	tokenRepo := repositories.NewMemoryTokenRepository(nil)
	authenticator := auth.NewJWTAuthenticator(config.AuthConfig{
		JWTSecret: "secret",
		Issuer:    "test",
	})
	service := services.NewDefaultUserService(userRepo, tokenRepo, authenticator)
	return handlers.NewDefaultUserHandler(service), nil
}

// Middleware returns JWT middleware.
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

func TestDefaultUserHandler_RegisterClient(t *testing.T) {
	handler, err := DefaultUserHandler()
	if err != nil {
		t.Fatalf("Error creating user handler: %v", err)
	}
	app := fiber.New()
	app.Post("/register", handler.RegisterClient())

	tests := []struct {
		name           string
		body           *models.RegisterClientPayload
		expectedStatus int
	}{
		{
			name:           "Send valid payload",
			body:           models.NewRegisterClientPayload("NewUser@example.com", "NewUser123", "Strong_12"),
			expectedStatus: fiber.StatusCreated,
		}, {
			name:           "Send invalid payload",
			body:           models.NewRegisterClientPayload("", "", ""),
			expectedStatus: fiber.StatusBadRequest,
		}, {
			name:           "Send valid payload with duplicate email",
			body:           models.NewRegisterClientPayload("NewUser@example.com", "NewUser321", "Strong_12"),
			expectedStatus: fiber.StatusConflict,
		}, {
			name:           "Send valid payload with duplicate username",
			body:           models.NewRegisterClientPayload("NewUser@email.com", "NewUser123", "Strong_12"),
			expectedStatus: fiber.StatusConflict,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res, requestErr := testutils.SendRequest(app, "/register", "POST", "", test.body)
			if requestErr != nil {
				t.Errorf("Error sending request: %v", requestErr)
			}

			if res.StatusCode != test.expectedStatus {
				t.Errorf("Expected status %d, got %d", test.expectedStatus, res.StatusCode)
			}
		})
	}

}

func BenchmarkDefaultUserHandler_RegisterClient(b *testing.B) {
	handler, err := DefaultUserHandler()
	if err != nil {
		b.Fatalf("Error creating user handler: %v", err)
	}

	app := fiber.New()
	app.Post("/register", handler.RegisterClient())

	for b.Loop() {
		id := uuid.New().String()
		email := id + "@example.com"
		username := id + "username"
		password := id + "<PASSWORD>"
		body := models.NewRegisterClientPayload(email, username, password)

		_, requestErr := testutils.SendRequest(app, "/register", "POST", "", body)
		if requestErr != nil {
			b.Errorf("Error sending request: %v", err)
		}
	}
}

func FuzzDefaultUserHandler_RegisterClient(f *testing.F) {
	handler, err := DefaultUserHandler()
	if err != nil {
		f.Fatalf("Error creating user handler: %v", err)
	}
	app := fiber.New()
	app.Post("/register", handler.RegisterClient())

	f.Add("email", "username", "password")
	f.Add("", "", "")
	f.Add("validEmail@example.com", "ValidUsername", "String_pass123")

	f.Fuzz(func(t *testing.T, email, username, password string) {
		body := models.NewRegisterClientPayload(email, username, password)
		_, requestErr := testutils.SendRequest(app, "/register", "POST", "", body)
		if requestErr != nil {
			t.Errorf("Error sending request: %v", err)
		}
	})
}

func TestDefaultUserHandler_RegisterUser(t *testing.T) {
	handler, err := DefaultUserHandler()
	if err != nil {
		t.Fatalf("Error creating user handler: %v", err)
	}
	app := fiber.New()
	app.Post("/register", Middleware(), handler.RegisterUser())
	app.Post("/login", handler.Login())
	tokens, err := testutils.LoginAsAdmin(app, "/login")
	if err != nil {
		t.Fatalf("Error logging in as admin: %v", err)
	}

	tests := []struct {
		name           string
		payload        *models.RegisterUserPayload
		token          string
		expectedStatus int
	}{
		{
			name:           "Register valid user",
			payload:        models.NewRegisterUserPayload("example1@email.com", "ValidUsername1", "Strong_pass123", models.Client),
			token:          tokens.AccessToken,
			expectedStatus: fiber.StatusCreated,
		}, {
			name:           "Register valid user with duplicate email",
			payload:        models.NewRegisterUserPayload("example1@email.com", "ValidUsername2", "Strong_pass123", models.Client),
			token:          tokens.AccessToken,
			expectedStatus: fiber.StatusConflict,
		}, {
			name:           "Register valid user with duplicate username",
			payload:        models.NewRegisterUserPayload("example2@email.com", "ValidUsername1", "Strong_pass123", models.Client),
			token:          tokens.AccessToken,
			expectedStatus: fiber.StatusConflict,
		}, {
			name:           "Register user with invalid payload",
			payload:        models.NewRegisterUserPayload("", "", "", ""),
			token:          tokens.AccessToken,
			expectedStatus: fiber.StatusBadRequest,
		}, {
			name:           "Register user with invalid token",
			payload:        models.NewRegisterUserPayload("example2@email.com", "ValidUsername2", "Strong_pass123", models.Client),
			token:          "",
			expectedStatus: fiber.StatusUnauthorized,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res, requestErr := testutils.SendRequest(app, "/register", "POST", test.token, test.payload)

			if requestErr != nil {
				t.Errorf("Error sending request: %v", requestErr)
			}
			if res.StatusCode != test.expectedStatus {
				t.Errorf("Expected status %d, got %d", test.expectedStatus, res.StatusCode)
			}
		})
	}
}

func BenchmarkDefaultUserHandler_RegisterUser(b *testing.B) {
	handler, err := DefaultUserHandler()
	if err != nil {
		b.Fatalf("Error creating user handler: %v", err)
	}
	app := fiber.New()
	app.Post("/register", Middleware(), handler.RegisterUser())
	app.Post("/login", handler.Login())
	tokens, err := testutils.LoginAsAdmin(app, "/login")
	if err != nil {
		b.Fatalf("Error logging in as admin: %v", err)
	}

	for b.Loop() {
		id := uuid.New().String()
		email := id + "@example.com"
		username := id + "username"
		password := id + "String_pass123"
		body := models.NewRegisterUserPayload(email, username, password, models.Client)
		_, requestErr := testutils.SendRequest(app, "/register", "POST", tokens.AccessToken, body)
		if requestErr != nil {
			b.Errorf("Error sending request: %v", err)
		}
	}
}

func FuzzDefaultUserHandler_RegisterUser(f *testing.F) {
	handler, err := DefaultUserHandler()
	if err != nil {
		f.Fatalf("Error creating user handler: %v", err)
	}
	app := fiber.New()
	app.Post("/register", Middleware(), handler.RegisterUser())
	app.Post("/login", handler.Login())
	tokens, err := testutils.LoginAsAdmin(app, "/login")
	if err != nil {
		f.Fatalf("Error logging in as admin: %v", err)
	}

	f.Add("email", "username", "password", "role", tokens.AccessToken)
	f.Add("", "", "", "", tokens.AccessToken)
	f.Add("sda", "dasda", "qweq", "", "")

	f.Fuzz(func(t *testing.T, email, username, password, role, token string) {
		token = testutils.FilterToken(token)

		body := models.NewRegisterUserPayload(email, username, password, models.Client)
		_, requestErr := testutils.SendRequest(app, "/register", "POST", token, body)
		if requestErr != nil {
			t.Errorf("Error sending request: %v", err)
		}
	})
}

func TestDefaultUserHandler_Login(t *testing.T) {
	handler, err := DefaultUserHandler()
	if err != nil {
		t.Fatalf("Error creating user handler: %v", err)
	}
	app := fiber.New()
	app.Post("/login", handler.Login())

	tests := []struct {
		name           string
		payload        *models.LoginUserPayload
		expectedStatus int
	}{
		{
			name:           "Login with valid admin credentials",
			payload:        models.NewLoginUserPayload("john_doe", "Password1!"),
			expectedStatus: fiber.StatusOK,
		}, {
			name:           "Login with valid client credentials",
			payload:        models.NewLoginUserPayload("gracier", "SuperPass18)"),
			expectedStatus: fiber.StatusOK,
		}, {
			name:           "Login with valid delivery credentials",
			payload:        models.NewLoginUserPayload("alexw", "MySecretPass3#"),
			expectedStatus: fiber.StatusOK,
		}, {
			name:           "Login with valid workshop credentials",
			payload:        models.NewLoginUserPayload("lilyd", "LastPass20@"),
			expectedStatus: fiber.StatusOK,
		}, {
			name:           "Login with invalid credentials",
			payload:        models.NewLoginUserPayload("", ""),
			expectedStatus: fiber.StatusUnauthorized,
		}, {
			name:           "Login to deactivated account",
			payload:        models.NewLoginUserPayload("jane_s", "SecurePass2@"),
			expectedStatus: fiber.StatusForbidden,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res, requestErr := testutils.SendRequest(app, "/login", "POST", "", test.payload)
			if requestErr != nil {
				t.Errorf("Error sending request: %v", requestErr)
			}
			if res.StatusCode != test.expectedStatus {
				t.Errorf("Expected status %d, got %d", test.expectedStatus, res.StatusCode)
			}

			var tokens models.TokenGroup
			decoderErr := json.NewDecoder(res.Body).Decode(&tokens)
			if decoderErr != nil {
				t.Errorf("Error decoding response: %v", decoderErr)
			}
		})
	}
}

func BenchmarkDefaultUserHandler_Login(b *testing.B) {
	handler, err := DefaultUserHandler()
	if err != nil {
		b.Fatalf("Error creating user handler: %v", err)
	}
	app := fiber.New()
	app.Post("/login", handler.Login())

	for b.Loop() {
		_, requestErr := testutils.SendRequest(app, "/login", "POST", "", models.NewLoginUserPayload("john_doe", "Password1!"))
		if requestErr != nil {
			b.Errorf("Error sending request: %v", requestErr)
		}
	}
}

func FuzzDefaultUserHandler_Login(f *testing.F) {
	handler, err := DefaultUserHandler()
	if err != nil {
		f.Fatalf("Error creating user handler: %v", err)
	}
	app := fiber.New()
	app.Post("/login", handler.Login())

	f.Add("username", "password")
	f.Add("", "")
	f.Fuzz(func(t *testing.T, username, password string) {
		_, requestErr := testutils.SendRequest(app, "/login", "POST", "", models.NewLoginUserPayload(username, password))
		if requestErr != nil {
			t.Errorf("Error sending request: %v", requestErr)
		}
	})
}

func TestDefaultUserHandler_RefreshSession(t *testing.T) {
	handler, err := DefaultUserHandler()
	if err != nil {
		t.Fatalf("Error creating user handler: %v", err)
	}
	app := fiber.New()
	app.Post("/login", handler.Login())
	app.Post("/refresh", Middleware(), handler.RefreshSession())
	tokens, err := testutils.LoginAsAdmin(app, "/login")
	if err != nil {
		t.Fatalf("Error logging in as admin: %v", err)
	}

	tests := []struct {
		name           string
		token          string
		expectedStatus int
	}{
		{
			name:           "Refresh with valid token",
			token:          tokens.RefreshToken,
			expectedStatus: fiber.StatusOK,
		}, {
			name:           "Refresh with invalid token",
			token:          "",
			expectedStatus: fiber.StatusUnauthorized,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res, requestErr := testutils.SendRequest(app, "/refresh", "POST", test.token, nil)
			if requestErr != nil {
				t.Errorf("Error sending request: %v", requestErr)
			}
			if res.StatusCode != test.expectedStatus {
				t.Errorf("Expected status %d, got %d", test.expectedStatus, res.StatusCode)
			}

			var receivedTokens models.TokenGroup
			decoderErr := json.NewDecoder(res.Body).Decode(&receivedTokens)
			if decoderErr != nil {
				t.Errorf("Error decoding response: %v", decoderErr)
			}
		})
	}
}

func BenchmarkDefaultUserHandler_RefreshSession(b *testing.B) {
	handler, err := DefaultUserHandler()
	if err != nil {
		b.Fatalf("Error creating user handler: %v", err)
	}
	app := fiber.New()
	app.Post("/login", handler.Login())
	app.Post("/refresh", handler.RefreshSession())
	tokens, err := testutils.LoginAsAdmin(app, "/login")
	if err != nil {
		b.Fatalf("Error logging in as admin: %v", err)
	}

	for b.Loop() {
		res, requestErr := testutils.SendRequest(app, "/refresh", "POST", tokens.RefreshToken, nil)
		if requestErr != nil {
			b.Errorf("Error sending request: %v", requestErr)
		}

		var receivedTokens models.TokenGroup
		decoderErr := json.NewDecoder(res.Body).Decode(&receivedTokens)
		if decoderErr != nil {
			b.Errorf("Error decoding response: %v", decoderErr)
		}
		tokens.RefreshToken = receivedTokens.RefreshToken
	}
}

func FuzzDefaultUserHandler_RefreshSession(f *testing.F) {
	handler, err := DefaultUserHandler()
	if err != nil {
		f.Fatalf("Error creating user handler: %v", err)
	}
	app := fiber.New()
	app.Post("/login", handler.Login())
	app.Post("/refresh", Middleware(), handler.RefreshSession())
	tokens, err := testutils.LoginAsAdmin(app, "/login")
	if err != nil {
		f.Fatalf("Error logging in as admin: %v", err)
	}

	f.Add(tokens.RefreshToken)
	f.Add(tokens.AccessToken)
	f.Add("")
	f.Add("token")

	f.Fuzz(func(t *testing.T, token string) {
		token = testutils.FilterToken(token)
		_, requestErr := testutils.SendRequest(app, "/refresh", "POST", token, nil)
		if requestErr != nil {
			t.Errorf("Error sending request: %v", requestErr)
		}
	})
}

func TestDefaultUserHandler_GetUsers(t *testing.T) {
	handler, err := DefaultUserHandler()
	if err != nil {
		t.Fatalf("Error creating user handler: %v", err)
	}
	app := fiber.New()
	app.Post("/login", handler.Login())
	app.Get("/users", Middleware(), handler.GetUsers())
	tokens, err := testutils.LoginAsAdmin(app, "/login")
	if err != nil {
		t.Fatalf("Error logging in as admin: %v", err)
	}

	role := models.Client

	tests := []struct {
		name           string
		token          string
		limit          int
		page           int
		role           *string
		expectedStatus int
		expectedEmails []string
	}{
		{
			name:           "Get users(limit=4, page=1, role=nil)",
			token:          tokens.AccessToken,
			limit:          4,
			page:           1,
			role:           nil,
			expectedStatus: fiber.StatusOK,
			expectedEmails: []string{"user1@example.com", "jane_smith@example.com", "alex.wilson@example.com", "emma.davis@example.com"},
		}, {
			name:           "Get users(limit=4, page=2, role=nil)",
			token:          tokens.AccessToken,
			limit:          4,
			page:           2,
			role:           nil,
			expectedStatus: fiber.StatusOK,
			expectedEmails: []string{"michael.brown@example.com", "olivia.jones@example.com", "william.garcia@example.com", "sophia.rodriguez@example.com"},
		}, {
			name:           "Get users(limit=4, page=1, role=client)",
			token:          tokens.AccessToken,
			limit:          4,
			page:           1,
			role:           &role,
			expectedStatus: fiber.StatusOK,
			expectedEmails: []string{"jane_smith@example.com", "olivia.jones@example.com", "isabella.hernandez@example.com", "chloe.sanchez@example.com"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			params := url.Values{}
			params.Add("limit", strconv.Itoa(test.limit))
			params.Add("page", strconv.Itoa(test.page))
			if test.role != nil {
				params.Add("role", *test.role)
			}

			fullUrl := "/users?" + params.Encode()
			res, requestErr := testutils.SendRequest(app, fullUrl, "GET", test.token, nil)
			if requestErr != nil {
				t.Errorf("Error sending request: %v", requestErr)
			}
			if res.StatusCode != test.expectedStatus {
				t.Errorf("Expected status %d, got %d", test.expectedStatus, res.StatusCode)
			}

			var users []models.UserInfo
			decoderErr := json.NewDecoder(res.Body).Decode(&users)
			if decoderErr != nil {
				t.Fatalf("Error decoding response: %v", decoderErr)
				return
			}

			if len(users) != len(test.expectedEmails) {
				t.Fatalf("Expected %d users, got %d", len(test.expectedEmails), len(users))
			}
			for i, user := range users {
				if user.Email != test.expectedEmails[i] {
					t.Errorf("Expected email %s, got %s", test.expectedEmails[i], user.Email)
				}
			}
		})
	}
}

func BenchmarkDefaultUserHandler_GetUsers(b *testing.B) {
	handler, err := DefaultUserHandler()
	if err != nil {
		b.Fatalf("Error creating user handler: %v", err)
	}
	app := fiber.New()
	app.Post("/login", handler.Login())
	app.Get("/users", Middleware(), handler.GetUsers())
	tokens, err := testutils.LoginAsAdmin(app, "/login")
	if err != nil {
		b.Fatalf("Error logging in as admin: %v", err)
	}

	expectedEmails := []string{"user1@example.com", "jane_smith@example.com", "alex.wilson@example.com", "emma.davis@example.com"}

	for b.Loop() {
		params := url.Values{}
		params.Add("limit", "4")
		params.Add("page", "1")
		res, requestErr := testutils.SendRequest(app, "/users?"+params.Encode(), "GET", tokens.AccessToken, nil)
		if requestErr != nil {
			b.Errorf("Error sending request: %v", requestErr)
		}

		var users []models.UserInfo
		decoderErr := json.NewDecoder(res.Body).Decode(&users)
		if decoderErr != nil {
			b.Fatalf("Error decoding response: %v", decoderErr)
			return
		}

		if len(users) != len(expectedEmails) {
			b.Fatalf("Expected %d users, got %d", len(expectedEmails), len(users))
		}

		for i, user := range users {
			if user.Email != expectedEmails[i] {
				b.Errorf("Expected email %s, got %s", expectedEmails[i], user.Email)
			}
		}
	}
}

func FuzzDefaultUserHandler_GetUsers(f *testing.F) {
	handler, err := DefaultUserHandler()
	if err != nil {
		f.Fatalf("Error creating user handler: %v", err)
	}
	app := fiber.New()
	app.Post("/login", handler.Login())
	app.Get("/users", Middleware(), handler.GetUsers())
	tokens, err := testutils.LoginAsAdmin(app, "/login")
	if err != nil {
		f.Fatalf("Error logging in as admin: %v", err)
	}

	f.Add(1, 1, "client")
	f.Add(5, 5, "")
	f.Add(10, 20, "role")
	f.Add(50, 30, "1")
	f.Fuzz(func(t *testing.T, limit, page int, role string) {
		token := testutils.FilterToken(tokens.AccessToken)
		params := url.Values{}
		params.Add("limit", strconv.Itoa(limit))
		params.Add("page", strconv.Itoa(page))
		if role != "" {
			role = "client"
		} else if len(role) > 256 {
			role = role[:256]
		}
		params.Add("role", role)

		_, requestErr := testutils.SendRequest(app, "/users?"+params.Encode(), "GET", token, nil)
		if requestErr != nil {
			t.Errorf("Error sending request: %v", requestErr)
		}
	})
}

func TestDefaultUserHandler_GetUserById(t *testing.T) {
	handler, err := DefaultUserHandler()
	if err != nil {
		t.Fatalf("Error creating user handler: %v", err)
	}
	app := fiber.New()
	app.Post("/login", handler.Login())
	app.Get("/users/:id", Middleware(), handler.GetUserById())
	tokens, err := testutils.LoginAsAdmin(app, "/login")
	if err != nil {
		t.Fatalf("Error logging in as admin: %v", err)
	}

	tests := []struct {
		userId         string
		expectedStatus int
		expectedEmail  string
	}{
		{
			userId:         "a1b2c3d4-e5f6-7890-1234-567890abcdef",
			expectedStatus: fiber.StatusOK,
			expectedEmail:  "user1@example.com",
		}, {
			userId:         "b2c3d4e5-f6a7-8901-2345-67890abcdef1",
			expectedStatus: fiber.StatusOK,
			expectedEmail:  "jane_smith@example.com",
		}, {
			userId:         uuid.New().String(),
			expectedStatus: fiber.StatusNotFound,
			expectedEmail:  "",
		},
	}

	for _, test := range tests {
		t.Run(test.userId, func(t *testing.T) {
			res, requestErr := testutils.SendRequest(app, "/users/"+test.userId, "GET", tokens.AccessToken, nil)
			if requestErr != nil {
				t.Fatalf("Error sending request: %v", requestErr)
			}
			if res.StatusCode != test.expectedStatus {
				t.Fatalf("Expected status %d, got %d", test.expectedStatus, res.StatusCode)
			}

			var user models.UserInfo
			decoderErr := json.NewDecoder(res.Body).Decode(&user)
			if decoderErr != nil {
				t.Fatalf("Error decoding response: %v", decoderErr)
			}
			if user.Email != test.expectedEmail {
				t.Errorf("Expected email %s, got %s", test.expectedEmail, user.Email)
			}
		})
	}
}

func BenchmarkDefaultUserHandler_GetUserById(b *testing.B) {
	handler, err := DefaultUserHandler()
	if err != nil {
		b.Fatalf("Error creating user handler: %v", err)
	}
	app := fiber.New()
	app.Post("/login", handler.Login())
	app.Get("/users/:id", Middleware(), handler.GetUserById())
	tokens, err := testutils.LoginAsAdmin(app, "/login")
	if err != nil {
		b.Fatalf("Error logging in as admin: %v", err)
	}

	for b.Loop() {
		_, requestErr := testutils.SendRequest(app, "/users/a1b2c3d4-e5f6-7890-1234-567890abcdef", "GET", tokens.AccessToken, nil)
		if requestErr != nil {
			b.Errorf("Error sending request: %v", requestErr)
		}
	}
}

func FuzzDefaultUserHandler_GetUserById(f *testing.F) {
	handler, err := DefaultUserHandler()
	if err != nil {
		f.Fatalf("Error creating user handler: %v", err)
	}
	app := fiber.New()
	app.Post("/login", handler.Login())
	app.Get("/users/:id", Middleware(), handler.GetUserById())
	tokens, err := testutils.LoginAsAdmin(app, "/login")
	if err != nil {
		f.Fatalf("Error logging in as admin: %v", err)
	}

	f.Add(uuid.New().String())
	f.Add(uuid.New().String())
	f.Add("")

	f.Fuzz(func(t *testing.T, userId string) {
		userId = testutils.FilterPathValue(userId)

		_, requestErr := testutils.SendRequest(app, "/users/"+userId, "GET", tokens.AccessToken, nil)
		if requestErr != nil {
			t.Errorf("Error sending request: %v", requestErr)
		}
	})
}

func TestDefaultUserHandler_GetUserByEmail(t *testing.T) {
	handler, err := DefaultUserHandler()
	if err != nil {
		t.Fatalf("Error creating user handler: %v", err)
	}
	app := fiber.New()
	app.Post("/login", handler.Login())
	app.Get("/users/email/:email", Middleware(), handler.GetUserByEmail())
	tokens, err := testutils.LoginAsAdmin(app, "/login")
	if err != nil {
		t.Fatalf("Error logging in as admin: %v", err)
	}

	tests := []struct {
		name             string
		email            string
		expectedStatus   int
		expectedUsername string
	}{
		{
			name:             "Get user by existing email",
			email:            "user1@example.com",
			expectedStatus:   fiber.StatusOK,
			expectedUsername: "john_doe",
		}, {
			name:             "Get user by non-existing email",
			email:            "g",
			expectedStatus:   fiber.StatusNotFound,
			expectedUsername: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res, requestErr := testutils.SendRequest(app, "/users/email/"+test.email, "GET", tokens.AccessToken, nil)
			if requestErr != nil {
				t.Fatalf("Error sending request: %v", requestErr)
			}
			if res.StatusCode != test.expectedStatus {
				t.Fatalf("Expected status %d, got %d", test.expectedStatus, res.StatusCode)
			}

			var user models.UserInfo
			decoderErr := json.NewDecoder(res.Body).Decode(&user)
			if decoderErr != nil {
				t.Fatalf("Error decoding response: %v", decoderErr)
			}
			if user.Username != test.expectedUsername {
				t.Errorf("Expected username %s, got %s", test.expectedUsername, user.Username)
			}
		})
	}
}

func BenchmarkDefaultUserHandler_GetUserByEmail(b *testing.B) {
	handler, err := DefaultUserHandler()
	if err != nil {
		b.Fatalf("Error creating user handler: %v", err)
	}
	app := fiber.New()
	app.Post("/login", handler.Login())
	app.Get("/users/email/:email", Middleware(), handler.GetUserByEmail())
	tokens, err := testutils.LoginAsAdmin(app, "/login")
	if err != nil {
		b.Fatalf("Error logging in as admin: %v", err)
	}

	for b.Loop() {
		_, requestErr := testutils.SendRequest(app, "/users/email/"+"user1@example.com", "GET", tokens.AccessToken, nil)
		if requestErr != nil {
			b.Errorf("Error sending request: %v", requestErr)
		}
	}
}

func FuzzDefaultUserHandler_GetUserByEmail(f *testing.F) {
	handler, err := DefaultUserHandler()
	if err != nil {
		f.Fatalf("Error creating user handler: %v", err)
	}
	app := fiber.New()
	app.Post("/login", handler.Login())
	app.Get("/users/email/:email", Middleware(), handler.GetUserByEmail())
	tokens, err := testutils.LoginAsAdmin(app, "/login")
	if err != nil {
		f.Fatalf("Error logging in as admin: %v", err)
	}

	f.Add("email@example.com", tokens.AccessToken)
	f.Add("", "")
	f.Fuzz(func(t *testing.T, email, token string) {
		email = testutils.FilterPathValue(email)
		token = testutils.FilterToken(token)

		_, requestErr := testutils.SendRequest(app, "/users/email/"+email, "GET", tokens.AccessToken, nil)
		if requestErr != nil {
			t.Errorf("Error sending request: %v", requestErr)
		}
	})
}

func TestDefaultUserHandler_GetUserByUsername(t *testing.T) {
	handler, err := DefaultUserHandler()
	if err != nil {
		t.Fatalf("Error creating user handler: %v", err)
	}
	app := fiber.New()
	app.Post("/login", handler.Login())
	app.Get("/users/username/:username", Middleware(), handler.GetUserByUsername())
	tokens, err := testutils.LoginAsAdmin(app, "/login")
	if err != nil {
		t.Fatalf("Error logging in as admin: %v", err)
	}

	tests := []struct {
		name           string
		username       string
		expectedStatus int
		expectedEmail  string
	}{
		{
			name:           "Get user with existing username",
			username:       "john_doe",
			expectedStatus: fiber.StatusOK,
			expectedEmail:  "user1@example.com",
		}, {
			name:           "Get user with non-existing username",
			username:       "g",
			expectedStatus: fiber.StatusNotFound,
			expectedEmail:  "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res, requestErr := testutils.SendRequest(app, "/users/username/"+test.username, "GET", tokens.AccessToken, nil)
			if requestErr != nil {
				t.Fatalf("Error sending request: %v", requestErr)
			}
			if res.StatusCode != test.expectedStatus {
				t.Fatalf("Expected status %d, got %d", test.expectedStatus, res.StatusCode)
			}
		})
	}
}

func BenchmarkDefaultUserHandler_GetUserByUsername(b *testing.B) {
	handler, err := DefaultUserHandler()
	if err != nil {
		b.Fatalf("Error creating user handler: %v", err)
	}
	app := fiber.New()
	app.Post("/login", handler.Login())
	app.Get("/users/username/:username", Middleware(), handler.GetUserByUsername())
	tokens, err := testutils.LoginAsAdmin(app, "/login")
	if err != nil {
		b.Fatalf("Error logging in as admin: %v", err)
	}

	for b.Loop() {
		_, requestErr := testutils.SendRequest(app, "/users/username/"+"john_doe", "GET", tokens.AccessToken, nil)
		if requestErr != nil {
			b.Errorf("Error sending request: %v", requestErr)
		}
	}
}

func FuzzDefaultUserHandler_GetUserByUsername(f *testing.F) {
	handler, err := DefaultUserHandler()
	if err != nil {
		f.Fatalf("Error creating user handler: %v", err)
	}
	app := fiber.New()
	app.Post("/login", handler.Login())
	app.Get("/users/username/:username", Middleware(), handler.GetUserByUsername())
	tokens, err := testutils.LoginAsAdmin(app, "/login")
	if err != nil {
		f.Fatalf("Error logging in as admin: %v", err)
	}

	f.Add("john_doe", tokens.AccessToken)
	f.Add("", "")
	f.Fuzz(func(t *testing.T, username, token string) {
		username = testutils.FilterPathValue(username)
		token = testutils.FilterToken(token)

		_, requestErr := testutils.SendRequest(app, "/users/username/"+username, "GET", tokens.AccessToken, nil)
		if requestErr != nil {
			t.Errorf("Error sending request: %v", requestErr)
		}
	})
}

func TestDefaultUserHandler_UpdateUser(t *testing.T) {
	handler, err := DefaultUserHandler()
	if err != nil {
		t.Fatalf("Error creating user handler: %v", err)
	}
	app := fiber.New()
	app.Post("/login", handler.Login())
	app.Patch("/users/update", Middleware(), handler.UpdateUser())
	tokens, err := testutils.LoginAsAdmin(app, "/login")
	if err != nil {
		t.Fatalf("Error logging in as admin: %v", err)
	}

	tests := []struct {
		name           string
		payload        *models.UpdateUserPayload
		expectedStatus int
	}{
		{
			name:           "Successful update",
			payload:        models.NewUpdateUserPayload(uuid.MustParse("b2c3d4e5-f6a7-8901-2345-67890abcdef1"), "NewEmail1@gmail.com", "NewUsername1", false, models.Client),
			expectedStatus: http.StatusOK,
		}, {
			name:           "Unsuccessful update/User not found",
			payload:        models.NewUpdateUserPayload(uuid.New(), "NewEmail2@gmail.com", "NewUsername2", false, models.Client),
			expectedStatus: http.StatusNotFound,
		}, {
			name:           "Unsuccessful update/User payload in not valid",
			payload:        models.NewUpdateUserPayload(uuid.New(), "", "", true, ""),
			expectedStatus: http.StatusBadRequest,
		}, {
			name:           "Unsuccessful update/User email already exists",
			payload:        models.NewUpdateUserPayload(uuid.MustParse("d4e5f6a7-b8c9-0123-4567-890abcdef345"), "alex.wilson@example.com", "NewUsername3", true, models.Client),
			expectedStatus: http.StatusConflict,
		}, {
			name:           "Unsuccessful update/User username already exists",
			payload:        models.NewUpdateUserPayload(uuid.MustParse("e5f6a7b8-c9d0-1234-5678-90abcdef4567"), "NewEmail3@gmail.com", "john_doe", true, models.Client),
			expectedStatus: http.StatusConflict,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res, requestErr := testutils.SendRequest(app, "/users/update", "PATCH", tokens.AccessToken, test.payload)
			if requestErr != nil {
				t.Fatalf("Error sending request: %v", requestErr)
			}

			if test.expectedStatus != res.StatusCode {
				t.Errorf("Expected status %d, got %d", test.expectedStatus, res.StatusCode)
			}
		})
	}
}

func BenchmarkUserHandler_UpdateUser(b *testing.B) {
	handler, err := DefaultUserHandler()
	if err != nil {
		b.Fatalf("Error creating user handler: %v", err)
	}
	app := fiber.New()
	app.Post("/login", handler.Login())
	app.Patch("/users/update", Middleware(), handler.UpdateUser())
	tokens, err := testutils.LoginAsAdmin(app, "/login")
	if err != nil {
		b.Fatalf("Error logging in as admin: %v", err)
	}

	for b.Loop() {
		res, requestErr := testutils.SendRequest(app, "/users/update", "PATCH", tokens.AccessToken, models.NewUpdateUserPayload(uuid.MustParse("b2c3d4e5-f6a7-8901-2345-67890abcdef1"), "NewEmail1@gmail.com", "NewUsername1", true, models.Client))
		if requestErr != nil {
			b.Fatalf("Error sending request: %v", requestErr)
		}
		if res.StatusCode != fiber.StatusOK {
			b.Fatalf("Expected status %d, got %d", fiber.StatusOK, res.StatusCode)
		}
	}
}

func FuzzDefaultUserHandler_UpdateUser(f *testing.F) {
	handler, err := DefaultUserHandler()
	if err != nil {
		f.Fatalf("Error creating user handler: %v", err)
	}
	app := fiber.New()
	app.Post("/login", handler.Login())
	app.Patch("/users/update", Middleware(), handler.UpdateUser())
	tokens, err := testutils.LoginAsAdmin(app, "/login")
	if err != nil {
		f.Fatalf("Error logging in as admin: %v", err)
	}

	f.Add(tokens.AccessToken, []byte{}, "email", "username", true, "client")
	f.Add("", []byte{}, "", "", false, "")
	f.Fuzz(func(t *testing.T, token string, userId []byte, email, username string, active bool, role string) {
		token = testutils.FilterToken(token)
		if userId == nil || len(userId) != 16 {
			userId = bytes.Repeat([]byte{0}, 16)
		}

		_, requestErr := testutils.SendRequest(app, "/users/update", "PATCH", token, models.NewUpdateUserPayload(uuid.UUID(userId), email, username, active, role))
		if requestErr != nil {
			t.Errorf("Error sending request: %v", requestErr)
		}
	})
}

func TestDefaultUserHandler_DeleteUser(t *testing.T) {
	handler, err := DefaultUserHandler()
	if err != nil {
		t.Fatalf("Error creating user handler: %v", err)
	}
	app := fiber.New()
	app.Post("/login", handler.Login())
	app.Delete("/users/:id", Middleware(), handler.DeleteUser())
	tokens, err := testutils.LoginAsAdmin(app, "/login")
	if err != nil {
		t.Fatalf("Error logging in as admin: %v", err)
	}

	tests := []struct {
		name           string
		userId         uuid.UUID
		expectedStatus int
	}{
		{
			name:           "Delete a user with existing id",
			userId:         uuid.MustParse("a1b2c3d4-e5f6-7890-1234-567890abcdef"),
			expectedStatus: http.StatusOK,
		}, {
			name:           "Delete a user with non-existing id",
			userId:         uuid.New(),
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res, requestErr := testutils.SendRequest(app, "/users/"+test.userId.String(), "DELETE", tokens.AccessToken, nil)
			if requestErr != nil {
				t.Fatalf("Error sending request: %v", requestErr)
			}
			if res.StatusCode != test.expectedStatus {
				t.Errorf("Expected status %d, got %d", test.expectedStatus, res.StatusCode)
			}
		})
	}
}

func BenchmarkDefaultUserHandler_DeleteUser(b *testing.B) {
	handler, err := DefaultUserHandler()
	if err != nil {
		b.Fatalf("Error creating user handler: %v", err)
	}
	app := fiber.New()
	app.Post("/login", handler.Login())
	app.Delete("/users/:id", Middleware(), handler.DeleteUser())
	tokens, err := testutils.LoginAsAdmin(app, "/login")
	if err != nil {
		b.Fatalf("Error logging in as admin: %v", err)
	}

	for b.Loop() {
		_, requestErr := testutils.SendRequest(app, "/users/a1b2c3d4-e5f6-7890-1234-567890abcdef", "DELETE", tokens.AccessToken, nil)
		if requestErr != nil {
			b.Fatalf("Error sending request: %v", requestErr)
		}
	}
}

func FuzzDefaultUserHandler_DeleteUser(f *testing.F) {
	handler, err := DefaultUserHandler()
	if err != nil {
		f.Fatalf("Error creating user handler: %v", err)
	}
	app := fiber.New()
	app.Post("/login", handler.Login())
	app.Delete("/users/:id", Middleware(), handler.DeleteUser())
	tokens, err := testutils.LoginAsAdmin(app, "/login")
	if err != nil {
		f.Fatalf("Error logging in as admin: %v", err)
	}

	f.Add(tokens.AccessToken, uuid.New().String())
	f.Add("", "")

	f.Fuzz(func(t *testing.T, token string, userId string) {
		token = testutils.FilterToken(token)
		userId = testutils.FilterPathValue(userId)

		_, reqErr := testutils.SendRequest(app, "/users/"+userId, "DELETE", token, nil)
		if reqErr != nil {
			t.Errorf("Error sending request: %v", reqErr)
		}
	})
}

func TestDefaultUserHandler_ForceLogoutUser(t *testing.T) {
	handler, err := DefaultUserHandler()
	if err != nil {
		t.Fatalf("Error creating user handler: %v", err)
	}
	app := fiber.New()
	app.Post("/login", handler.Login())
	app.Patch("/users/forceLogout/:id", Middleware(), handler.ForceLogoutUser())
	tokens, err := testutils.LoginAsAdmin(app, "/login")
	if err != nil {
		t.Fatalf("Error logging in as admin: %v", err)
	}

	tests := []struct {
		name           string
		userId         uuid.UUID
		expectedStatus int
	}{
		{
			name:           "Force logout a user with existing id",
			userId:         uuid.MustParse("a1b2c3d4-e5f6-7890-1234-567890abcdef"),
			expectedStatus: http.StatusOK,
		}, {
			name:           "Force logout a user with non-existing id",
			userId:         uuid.New(),
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res, requestErr := testutils.SendRequest(app, "/users/forceLogout/"+test.userId.String(), "PATCH", tokens.AccessToken, nil)
			if requestErr != nil {
				t.Fatalf("Error sending request: %v", requestErr)
			}
			if res.StatusCode != test.expectedStatus {
				t.Errorf("Expected status %d, got %d", test.expectedStatus, res.StatusCode)
			}
		})
	}
}

func BenchmarkDefaultUserHandler_ForceLogoutUser(b *testing.B) {
	handler, err := DefaultUserHandler()
	if err != nil {
		b.Fatalf("Error creating user handler: %v", err)
	}
	app := fiber.New()
	app.Post("/login", handler.Login())
	app.Patch("/users/forceLogout/:id", Middleware(), handler.ForceLogoutUser())
	tokens, err := testutils.LoginAsAdmin(app, "/login")
	if err != nil {
		b.Fatalf("Error logging in as admin: %v", err)
	}
	id := uuid.New().String()

	for b.Loop() {
		_, requestErr := testutils.SendRequest(app, "/users/forceLogout/"+id, "POST", tokens.AccessToken, nil)

		if requestErr != nil {
			b.Fatalf("Error sending request: %v", requestErr)
		}
	}
}

func FuzzDefaultUserHandler_ForceLogoutUser(f *testing.F) {
	handler, err := DefaultUserHandler()
	if err != nil {
		f.Fatalf("Error creating user handler: %v", err)
	}
	app := fiber.New()
	app.Post("/login", handler.Login())
	app.Patch("/users/forceLogout/:id", Middleware(), handler.ForceLogoutUser())
	tokens, err := testutils.LoginAsAdmin(app, "/login")
	if err != nil {
		f.Fatalf("Error logging in as admin: %v", err)
	}

	f.Add(tokens.AccessToken, uuid.New().String())
	f.Add("", "")

	f.Fuzz(func(t *testing.T, token string, userId string) {
		token = testutils.FilterToken(token)
		userId = testutils.FilterPathValue(userId)
		_, requestErr := testutils.SendRequest(app, "/users/forceLogout/"+userId, "PATCH", token, nil)
		if requestErr != nil {
			t.Errorf("Error sending request: %v", requestErr)
		}
	})
}

func TestDefaultUserHandler_ChangeUserPassword(t *testing.T) {
	handler, err := DefaultUserHandler()
	if err != nil {
		t.Fatalf("Error creating user handler: %v", err)
	}
	app := fiber.New()
	app.Post("/login", handler.Login())
	app.Patch("/users/changePassword", Middleware(), handler.ChangeUserPassword())
	tokens, err := testutils.LoginAsAdmin(app, "/login")
	if err != nil {
		t.Fatalf("Error logging in as admin: %v", err)
	}

	type payload struct {
		Id       uuid.UUID `json:"id"`
		Password string    `json:"password"`
	}
	tests := []struct {
		name           string
		payload        *payload
		expectedStatus int
	}{
		{
			name: "Update with valid password and existing user",
			payload: &payload{
				Id:       uuid.MustParse("a1b2c3d4-e5f6-7890-1234-567890abcdef"),
				Password: "NewValidPassword_123",
			},
			expectedStatus: http.StatusOK,
		}, {
			name: "Update with valid password and non-existing user",
			payload: &payload{
				Id:       uuid.New(),
				Password: "NewValidPassword_123",
			},
			expectedStatus: http.StatusNotFound,
		}, {
			name: "Update with invalid password",
			payload: &payload{
				Id:       uuid.Nil,
				Password: "",
			},
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res, requestErr := testutils.SendRequest(app, "/users/changePassword", "PATCH", tokens.AccessToken, test.payload)
			if requestErr != nil {
				t.Fatalf("Error sending request: %v", requestErr)
			}
			if res.StatusCode != test.expectedStatus {
				t.Errorf("Expected status %d, got %d", test.expectedStatus, res.StatusCode)
			}
		})
	}
}

func BenchmarkDefaultUserHandler_ChangeUserPassword(b *testing.B) {
	handler, err := DefaultUserHandler()
	if err != nil {
		b.Fatalf("Error creating user handler: %v", err)
	}
	app := fiber.New()
	app.Post("/login", handler.Login())
	app.Patch("/users/changePassword", Middleware(), handler.ChangeUserPassword())
	tokens, err := testutils.LoginAsAdmin(app, "/login")
	if err != nil {
		b.Fatalf("Error logging in as admin: %v", err)
	}

	var payload = struct {
		Id       uuid.UUID `json:"id"`
		Password string    `json:"password"`
	}{
		Id:       uuid.MustParse("a1b2c3d4-e5f6-7890-1234-567890abcdef"),
		Password: "NewValidPassword_123",
	}

	for b.Loop() {
		_, requestErr := testutils.SendRequest(app, "/users/changePassword", "PATCH", tokens.AccessToken, &payload)
		if requestErr != nil {
			b.Fatalf("Error sending request: %v", requestErr)
		}
	}
}

func FuzzDefaultUserHandler_ChangeUserPassword(f *testing.F) {
	handler, err := DefaultUserHandler()
	if err != nil {
		f.Fatalf("Error creating user handler: %v", err)
	}
	app := fiber.New()
	app.Post("/login", handler.Login())
	app.Patch("/users/changePassword", Middleware(), handler.ChangeUserPassword())
	tokens, err := testutils.LoginAsAdmin(app, "/login")
	if err != nil {
		f.Fatalf("Error logging in as admin: %v", err)
	}

	f.Add(tokens.AccessToken, uuid.New().String(), "NewValidPassword_123")
	f.Add("", uuid.Nil.String(), "")

	f.Fuzz(func(t *testing.T, token string, id string, password string) {
		token = testutils.FilterToken(token)

		payload := struct {
			Id       string `json:"id"`
			Password string `json:"password"`
		}{
			Id:       id,
			Password: password,
		}
		_, requestErr := testutils.SendRequest(app, "/users/changePassword", "PATCH", token, &payload)
		if requestErr != nil {
			t.Errorf("Error sending request: %v", requestErr)
		}
	})
}
