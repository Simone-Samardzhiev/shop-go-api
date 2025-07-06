package services_test

import (
	"api/auth"
	"api/config"
	"api/models"
	"api/services"
	"api/testutils"
	"api/utils"
	"context"
	"fmt"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"reflect"
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
			name:           "Add client with duplicate email",
			payload:        models.NewRegisterClientPayload("newUser@gmail.com", "NewUsername1", "Strong_pass_1"),
			expectedStatus: fiber.StatusConflict,
		}, {
			name:           "Add client with duplicate username",
			payload:        models.NewRegisterClientPayload("newUser1@email.com", "NewUsername", "Strong_pass_1"),
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
					t.Errorf("Expected email %v, got %v", test.expectedEmails[i], result[i].Email)
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

			if test.expectedEmail == "" && !reflect.DeepEqual(err, utils.NewAPIError("User not found.", fiber.StatusNotFound)) {
				t.Errorf("Expected error %v, got %v", *utils.NewAPIError("User not found.", fiber.StatusNotFound), err)
				return
			} else if test.expectedEmail == "" && reflect.DeepEqual(err, utils.NewAPIError("User not found.", fiber.StatusNotFound)) {
				return
			}

			if result.Email != test.expectedEmail {
				t.Errorf("Expected email %v, got %v", test.expectedEmail, result.Email)
			}
		})
	}
}

func TestDefaultUserService_UpdateUser(t *testing.T) {
	service := DefaultUserService(t)

	tests := []struct {
		user     *models.UpdateUserPayload
		expected *utils.APIError
	}{
		{
			user:     models.NewUpdateUserPayload(uuid.MustParse("a1b2c3d4-e5f6-7890-1234-567890abcdef"), "exmple_email@email.com", "NewUsername", true, models.Client),
			expected: nil,
		}, {
			user:     models.NewUpdateUserPayload(uuid.MustParse("c3d4e5f6-a7b8-9012-3456-7890abcdef23"), "exmple_email@email.com", "NewUsername", false, models.Client),
			expected: utils.NewAPIError("User email or username already in use.", fiber.StatusConflict),
		}, {
			user:     models.NewUpdateUserPayload(uuid.MustParse("b2c3d4e5-f6a7-8901-2345-67890abcdef1"), "", "NewUsername", false, models.Client),
			expected: utils.NewAPIError("Invalid email.", fiber.StatusBadRequest),
		}, {
			user:     models.NewUpdateUserPayload(uuid.MustParse("b2c3d4e5-f6a7-8901-2345-67890abcdef1"), "example@email.com", "", true, models.Client),
			expected: utils.NewAPIError("Invalid username.", fiber.StatusBadRequest),
		}, {
			user:     models.NewUpdateUserPayload(uuid.MustParse("b2c3d4e5-f6a7-8901-2345-67890abcdef1"), "example@email.com", "NewUsername", true, ""),
			expected: utils.NewAPIError("Invalid user role.", fiber.StatusBadRequest),
		},
	}

	for i, test := range tests {
		t.Run(fmt.Sprintf("test-%d", i), func(t *testing.T) {
			apiError := service.UpdateUser(context.Background(), test.user)
			if !reflect.DeepEqual(apiError, test.expected) {
				t.Errorf("Expected error %v, got %v", test.expected, apiError)
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
