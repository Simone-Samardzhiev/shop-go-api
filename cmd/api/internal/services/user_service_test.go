package services_test

import (
	"context"
	"fmt"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"reflect"
	"shop/cmd/api/internal/auth"
	"shop/cmd/api/internal/config"
	"shop/cmd/api/internal/models"
	"shop/cmd/api/internal/services"
	"shop/cmd/api/internal/testutils"
	"shop/cmd/api/internal/utils"
	"testing"
)

func DefaultUserService(t *testing.T) *services.DefaultUserService {
	t.Helper()

	userRepo, err := testutils.NewMemoryUserRepositoryWithUsers()
	if err != nil {
		t.Fatalf("Error creating memory user repository: %v", err)
	}
	tokenRepo, err := testutils.NewMemoryTokenRepositoryWithTokens()
	if err != nil {
		t.Fatalf("Error creating memory token repository: %v", err)
	}
	authenticator := auth.NewJWTAuthenticator(config.AuthConfig{
		JWTSecret: "secret",
		Issuer:    "test",
	})

	return services.NewDefaultUserService(userRepo, tokenRepo, authenticator)
}

func TestDefaultUserService_AddClient(t *testing.T) {
	service := DefaultUserService(t)

	tests := []struct {
		name           string
		payload        *models.RegisterClientPayload
		expectedStatus int
	}{
		{
			name:           "Add valid payload",
			payload:        models.NewRegisterClientPayload("newUser@gmail.com", "NewUsername", "Strong_pass_1"),
			expectedStatus: fiber.StatusCreated,
		}, {
			name:           "Add client with duplicate username",
			payload:        models.NewRegisterClientPayload("newUser@gmail.com", "NewUsername1", "Strong_pass_1"),
			expectedStatus: fiber.StatusConflict,
		}, {
			name:           "Add client with duplicate username",
			payload:        models.NewRegisterClientPayload("newUser1@username.com", "NewUsername", "Strong_pass_1"),
			expectedStatus: fiber.StatusConflict,
		}, {
			name:           "Add client with invalid payload",
			payload:        models.NewRegisterClientPayload("", "", ""),
			expectedStatus: fiber.StatusBadRequest,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			apiError := service.AddClient(context.Background(), test.payload)

			if apiError == nil && test.expectedStatus == fiber.StatusCreated {
				return
			} else if apiError == nil {
				t.Fatalf("Expected an error got nil")
			}

			if apiError.Status != test.expectedStatus {
				t.Errorf("Expected status %d, got %d", test.expectedStatus, apiError.Status)
			}
		})
	}
}

func TestDefaultUserService_Login(t *testing.T) {
	service := DefaultUserService(t)

	tests := []struct {
		name           string
		payload        *models.LoginUserPayload
		expectedStatus int
	}{
		{
			name:           "Login with valid credentials",
			payload:        models.NewLoginUserPayload("john_doe", "Password1!"),
			expectedStatus: fiber.StatusOK,
		}, {
			name:           "Login with invalid credentials",
			payload:        models.NewLoginUserPayload("john_doe", "Passworddqwe1!"),
			expectedStatus: fiber.StatusUnauthorized,
		}, {
			name:           "Login with inactive user",
			payload:        models.NewLoginUserPayload("jane_s", "SecurePass2@"),
			expectedStatus: fiber.StatusForbidden,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, apiError := service.Login(context.Background(), test.payload)

			if apiError == nil && test.expectedStatus == fiber.StatusOK {
				return
			}
			if apiError.Status != test.expectedStatus {
				t.Errorf("Expected status %d, got %d", test.expectedStatus, apiError.Status)
			}
		})
	}
}

func TestDefaultUserService_RefreshSession(t *testing.T) {
	service := DefaultUserService(t)
	tokens, loginError := service.Login(context.Background(), models.NewLoginUserPayload("john_doe", "Password1!"))
	if loginError != nil {
		t.Fatalf("Error logging in: %v", loginError)
	}

	claims, err := jwt.ParseWithClaims(tokens.AccessToken, &auth.Claims{}, func(token *jwt.Token) (any, error) {
		return []byte("secret"), nil
	})
	if err != nil {
		t.Fatalf("Error parsing access token: %v", err)
	}
	accessToken, ok := claims.Claims.(*auth.Claims)
	if !ok {
		t.Fatalf("Error casting access token claims")
	}
	claims, err = jwt.ParseWithClaims(tokens.RefreshToken, &auth.Claims{}, func(token *jwt.Token) (any, error) {
		return []byte("secret"), nil
	})
	if err != nil {
		t.Fatalf("Error parsing refresh token: %v", err)
	}
	refreshToken, ok := claims.Claims.(*auth.Claims)
	if !ok {
		t.Fatalf("Error casting refresh token claims")
	}

	tests := []struct {
		name           string
		claims         *auth.Claims
		expectedStatus int
	}{
		{
			name:           "Refresh session with valid refresh token",
			claims:         refreshToken,
			expectedStatus: fiber.StatusOK,
		}, {
			name: "Refresh session with invalid refresh token",
			claims: &auth.Claims{
				TokenType: auth.RefreshToken,
				Role:      models.Client,
				RegisteredClaims: jwt.RegisteredClaims{
					Subject: "invalid_refresh_token",
				},
			},
			expectedStatus: fiber.StatusUnauthorized,
		}, {
			name:           "Refresh session with access token",
			claims:         accessToken,
			expectedStatus: fiber.StatusUnauthorized,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, apiError := service.RefreshSession(context.Background(), test.claims)

			if apiError == nil && test.expectedStatus == fiber.StatusOK {
				return
			}

			if apiError.Status != test.expectedStatus {
				t.Errorf("Expected status %d, got %d", test.expectedStatus, apiError.Status)
			}
		})
	}
}

func TestDefaultUserService_GetUsers(t *testing.T) {
	service := DefaultUserService(t)
	role := models.Client

	tests := []struct {
		limit          int
		page           int
		role           *models.UserRole
		expectedEmails []string
	}{
		{
			limit:          4,
			page:           1,
			role:           nil,
			expectedEmails: []string{"user1@example.com", "jane_smith@example.com", "alex.wilson@example.com", "emma.davis@example.com"},
		}, {
			limit:          4,
			page:           2,
			role:           nil,
			expectedEmails: []string{"michael.brown@example.com", "olivia.jones@example.com", "william.garcia@example.com", "sophia.rodriguez@example.com"},
		}, {
			limit:          4,
			page:           1,
			role:           &role,
			expectedEmails: []string{"jane_smith@example.com", "olivia.jones@example.com", "isabella.hernandez@example.com", "chloe.sanchez@example.com"},
		},
	}

	for i, test := range tests {
		t.Run(fmt.Sprintf("test-%d", i), func(t *testing.T) {
			result, err := service.GetUsers(context.Background(), test.limit, test.page, test.role)

			if err != nil {
				t.Errorf("Error getting users: %v", err)
			}
			if len(result) != len(test.expectedEmails) {
				t.Errorf("Expected %d users, got %d", len(test.expectedEmails), len(result))
			}

			for j := 0; i < len(result); i++ {
				if result[j].Email != test.expectedEmails[j] {
					t.Errorf("Expected username %v, got %v", test.expectedEmails[i], result[i].Email)
				}
			}
		})
	}
}

func TestDefaultUserService_GetUserByID(t *testing.T) {
	service := DefaultUserService(t)

	tests := []struct {
		id            uuid.UUID
		expectedEmail string
	}{
		{
			id:            uuid.MustParse("d0e1f2a3-b4c5-6789-0123-def90123abcd"),
			expectedEmail: "isabella.hernandez@example.com",
		}, {
			id:            uuid.MustParse("c9d0e1f2-a3b4-5678-9012-cdef89012abc"),
			expectedEmail: "james.martinez@example.com",
		}, {
			id:            uuid.New(),
			expectedEmail: "",
		},
	}

	for i, test := range tests {
		t.Run(fmt.Sprintf("test-%d", i), func(t *testing.T) {
			result, err := service.GetUserById(context.Background(), test.id)

			if test.expectedEmail == "" && !reflect.DeepEqual(err, utils.UserNotFoundAPIError()) {
				t.Errorf("Expected error %v, got %v", *utils.UserNotFoundAPIError(), err)
				return
			} else if test.expectedEmail == "" && reflect.DeepEqual(err, utils.UserNotFoundAPIError()) {
				return
			}

			if result.Email != test.expectedEmail {
				t.Errorf("Expected username %v, got %v", test.expectedEmail, result.Email)
			}
		})
	}
}

func TestDefaultUserService_GetUserByEmail(t *testing.T) {
	service := DefaultUserService(t)
	tests := []struct {
		name             string
		email            string
		expectedUsername string
		expectedError    *utils.APIError
	}{
		{
			name:             "Get user with existing username",
			email:            "user1@example.com",
			expectedUsername: "john_doe",
			expectedError:    nil,
		}, {
			name:             "Get user with non-existing username",
			email:            "",
			expectedUsername: "",
			expectedError:    utils.UserNotFoundAPIError(),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, apiError := service.GetUserByEmail(context.Background(), test.email)
			if !reflect.DeepEqual(apiError, test.expectedError) {
				t.Errorf("Expected error %v, got %v", test.expectedError, apiError)
			} else if test.expectedError == nil && result.Username != test.expectedUsername {
				t.Errorf("Expected username %v, got %v", test.expectedUsername, result.Username)
			}
		})
	}
}

func TestDefaultUserService_GetUserByUsername(t *testing.T) {
	service := DefaultUserService(t)
	tests := []struct {
		name          string
		username      string
		expectedEmail string
		expectedError *utils.APIError
	}{
		{
			name:          "Get user with existing username",
			username:      "john_doe",
			expectedEmail: "user1@example.com",
			expectedError: nil,
		}, {
			name:          "Get user with non-existing username",
			username:      "",
			expectedEmail: "",
			expectedError: utils.UserNotFoundAPIError(),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, apiError := service.GetUserByUsername(context.Background(), test.username)
			if !reflect.DeepEqual(apiError, test.expectedError) {
				t.Errorf("Expected error %v, got %v", test.expectedError, apiError)
			} else if test.expectedError == nil && result.Email != test.expectedEmail {
				t.Errorf("Expected username %v, got %v", test.expectedEmail, result.Email)
			}
		})
	}
}

func TestDefaultUserService_DeleteUser(t *testing.T) {
	service := DefaultUserService(t)
	tests := []struct {
		name           string
		id             uuid.UUID
		expectedToFail bool
	}{
		{
			name:           "Delete a user with existing id",
			id:             uuid.MustParse("a1b2c3d4-e5f6-7890-1234-567890abcdef"),
			expectedToFail: false,
		}, {
			name:           "Delete a user with non-existing id",
			id:             uuid.New(),
			expectedToFail: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			apiError := service.DeleteUser(context.Background(), test.id)
			if test.expectedToFail && apiError == nil {
				t.Errorf("Expected error, got nil")
			} else if !test.expectedToFail && apiError != nil {
				t.Errorf("Expected no error, got %v", apiError)
			}
		})
	}
}

func TestDefaultUserService_ForceLogoutUser(t *testing.T) {
	service := DefaultUserService(t)

	tests := []struct {
		name     string
		id       uuid.UUID
		expected *utils.APIError
	}{
		{
			name:     "Force logout a user with existing id",
			id:       uuid.MustParse("a1b2c3d4-e5f6-7890-1234-567890abcdef"),
			expected: nil,
		}, {
			name:     "Force logout a user with non-existing id",
			id:       uuid.New(),
			expected: utils.NewAPIError("No tokens founds linked to user.", fiber.StatusNotFound),
		},
	}

	for i, test := range tests {
		t.Run(fmt.Sprintf("test-%d", i), func(t *testing.T) {
			apiError := service.ForceLogoutUser(context.Background(), test.id)
			if !reflect.DeepEqual(apiError, test.expected) {
				t.Errorf("Expected error %v, got %v", test.expected, apiError)
			}
		})
	}
}

func TestDefaultUserService_UpdateUserEmail(t *testing.T) {
	service := DefaultUserService(t)
	tests := []struct {
		name     string
		email    string
		id       uuid.UUID
		expected *utils.APIError
	}{
		{
			name:     "Update a existing user",
			email:    "NewEmail@example.com",
			id:       uuid.MustParse("a1b2c3d4-e5f6-7890-1234-567890abcdef"),
			expected: nil,
		}, {
			name:     "Update a user with already existing username",
			email:    "jane_smith@example.com",
			id:       uuid.MustParse("a1b2c3d4-e5f6-7890-1234-567890abcdef"),
			expected: utils.NewAPIError("Email already in use.", fiber.StatusConflict),
		}, {
			name:     "Update a non-existing user",
			email:    "",
			id:       uuid.New(),
			expected: utils.UserNotFoundAPIError(),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			apiError := service.UpdateUserEmail(context.Background(), test.id, test.email)
			if !reflect.DeepEqual(apiError, test.expected) {
				t.Errorf("Expected error %v, got %v", test.expected, apiError)
			}
		})
	}
}

func TestDefaultUserService_UpdateUserUsername(t *testing.T) {
	service := DefaultUserService(t)
	tests := []struct {
		name     string
		username string
		id       uuid.UUID
		expected *utils.APIError
	}{
		{
			name:     "Update a existing user",
			username: "NewUsername123",
			id:       uuid.MustParse("a1b2c3d4-e5f6-7890-1234-567890abcdef"),
			expected: nil,
		}, {
			name:     "Update a user with already existing username",
			username: "alexw",
			id:       uuid.MustParse("a1b2c3d4-e5f6-7890-1234-567890abcdef"),
			expected: utils.NewAPIError("Username already in use.", fiber.StatusConflict),
		}, {
			name:     "Update a non-existing user",
			username: "",
			id:       uuid.New(),
			expected: utils.UserNotFoundAPIError(),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			apiError := service.UpdateUserUsername(context.Background(), test.id, test.username)
			if !reflect.DeepEqual(apiError, test.expected) {
				t.Errorf("Expected error %v, got %v", test.expected, apiError)
			}
		})
	}
}

func TestDefaultUserService_UpdateUserRole(t *testing.T) {
	service := DefaultUserService(t)
	tests := []struct {
		name     string
		id       uuid.UUID
		role     models.UserRole
		expected *utils.APIError
	}{
		{
			name:     "Update a existing user",
			id:       uuid.MustParse("a1b2c3d4-e5f6-7890-1234-567890abcdef"),
			role:     models.Admin,
			expected: nil,
		}, {
			name:     "Update a non-existing user",
			id:       uuid.New(),
			role:     models.Admin,
			expected: utils.UserNotFoundAPIError(),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			apiError := service.UpdateUserRole(context.Background(), test.id, test.role)
			if !reflect.DeepEqual(apiError, test.expected) {
				t.Errorf("Expected error %v, got %v", test.expected, apiError)
			}
		})
	}
}

func TestDefaultUserService_UpdateUserPassword(t *testing.T) {
	service := DefaultUserService(t)
	tests := []struct {
		name     string
		id       uuid.UUID
		password string
		expected *utils.APIError
	}{
		{
			name:     "Update a existing user",
			id:       uuid.MustParse("a1b2c3d4-e5f6-7890-1234-567890abcdef"),
			password: "NewPassword123",
			expected: nil,
		}, {
			name:     "Update a non-existing user",
			id:       uuid.New(),
			password: "",
			expected: utils.UserNotFoundAPIError(),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			apiError := service.UpdateUserPassword(context.Background(), test.id, test.password)
			if !reflect.DeepEqual(apiError, test.expected) {
				t.Errorf("Expected error %v, got %v", test.expected, apiError)
			}
		})
	}
}

func TestDefaultUserService_UpdateUserStatus(t *testing.T) {
	service := DefaultUserService(t)
	tests := []struct {
		name     string
		id       uuid.UUID
		status   bool
		expected *utils.APIError
	}{
		{
			name:     "Update a existing user",
			id:       uuid.MustParse("a1b2c3d4-e5f6-7890-1234-567890abcdef"),
			status:   true,
			expected: nil,
		}, {
			name:     "Update a non-existing user",
			id:       uuid.New(),
			status:   false,
			expected: utils.UserNotFoundAPIError(),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			apiError := service.UpdateUserActivationStatus(context.Background(), test.id, test.status)
			if !reflect.DeepEqual(apiError, test.expected) {
				t.Errorf("Expected error %v, got %v", test.expected, apiError)
			}
		})
	}
}
