package services_test

import (
	"api/auth"
	"api/config"
	"api/models"
	"api/repositories"
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
	tokenRepo := repositories.NewMemoryTokenRepository(nil)
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
			payload:        models.NewLoginUserPayload("jane_s", "SecurePass2@"),
			expectedStatus: fiber.StatusOK,
		}, {
			name:           "Login with invalid credentials",
			payload:        models.NewLoginUserPayload("jane_s", "InvalidPassword"),
			expectedStatus: fiber.StatusUnauthorized,
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
	tokens, loginError := service.Login(context.Background(), models.NewLoginUserPayload("jane_s", "SecurePass2@"))
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
			result, err := service.GetUsersById(context.Background(), test.id)

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
