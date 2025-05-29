package services

import (
	"api/auth"
	"api/config"
	"api/models"
	"api/repositories"
	"api/utils"
	"context"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"testing"
)

// Setup returns DefaultUserService.
//
// The service is configured with repositories.MemoryUserRepository,
// repositories.MemoryTokenRepository and auth.JWTAuthenticator.
func Setup() *DefaultUserService {
	userRepository := repositories.NewMemoryUserRepository()
	tokenRepository := repositories.NewMemoryTokenRepository()
	authenticator := auth.NewJWTAuthenticator(config.AuthConfig{
		JWTSecret: "secret",
		Issuer:    "issuer",
	})
	return NewDefaultUserService(userRepository, tokenRepository, authenticator)
}

// TestDefaultUserServiceAddValidUser tests that adding valid clients works, and the second
// attempt to add the same client fails with the method AddClient of DefaultUserService.
func TestDefaultUserServiceAddValidUser(t *testing.T) {
	service := Setup()

	// The First attempt should succeed.
	err := service.AddClient(context.Background(), utils.ValidRegisterUserPayload())
	if err != nil {
		t.Errorf("AddClient returned error: %v", err)
	}

	// The second attempt should fail.
	err = service.AddClient(context.Background(), utils.ValidRegisterUserPayload())
	if err == nil {
		t.Errorf("AddClient returned no error when adding the same user.")
	}
}

// TestDefaultUserServiceAddInvalidUser test if adding an invalid client payload fails
// with the method AddClient of DefaultUserService.
func TestDefaultUserServiceAddInvalidUser(t *testing.T) {
	service := Setup()
	user := utils.InvalidRegisterUserPayload()

	// Adding the invalid user should result in an error.
	err := service.AddClient(context.Background(), user)
	if err == nil {
		t.Errorf("AddClient returned no error when adding invalid user.")
	}
}

// TestDefaultUserServiceAddLogin tests if after successful registration
// the user can log in with the method Login of DefaultUserService.
func TestDefaultUserServiceAddLogin(t *testing.T) {
	service := Setup()

	// Registering the user.
	err := service.AddClient(context.Background(), utils.ValidRegisterUserPayload())
	if err != nil {
		t.Errorf("AddClient returned error: %v", err)
	}

	// Logging as the same user.
	loginUser := utils.ValidLoginUserPayload()
	_, err = service.Login(context.Background(), loginUser)
	if err != nil {
		t.Errorf("Error logging in: %v", err)
	}
}

// TestDefaultUserServiceRefreshSession tests if after successful login,
// the user can refresh the session with the token with the method
// RefreshSession of DefaultUserService.
func TestDefaultUserServiceRefreshSession(t *testing.T) {
	service := Setup()

	// Register the client
	apiErr := service.AddClient(context.Background(), utils.ValidRegisterUserPayload())
	if apiErr != nil {
		t.Fatalf("Failed to register client: %v", apiErr)
	}

	// Login to get refresh token
	loginPayload := utils.ValidLoginUserPayload()
	tokenGroup, apiErr := service.Login(context.Background(), loginPayload)
	if apiErr != nil {
		t.Fatalf("Login failed: %v", apiErr.Message)
	}

	// Decode refresh token manually to get claims
	parsedToken, err := jwt.ParseWithClaims(tokenGroup.RefreshToken, &auth.Claims{}, func(token *jwt.Token) (any, error) {
		return []byte("secret"), nil
	})
	if err != nil {
		t.Fatalf("Failed to parse token: %v", err)
	}

	claims, ok := parsedToken.Claims.(*auth.Claims)
	if !ok || !parsedToken.Valid {
		t.Fatalf("Invalid claims")
	}

	// Call RefreshSession with parsed claims
	newTokenGroup, apiErr := service.RefreshSession(context.Background(), claims)
	if apiErr != nil {
		t.Fatalf("RefreshSession failed: %v", apiErr)
	}

	if newTokenGroup.AccessToken == "" || newTokenGroup.RefreshToken == "" {
		t.Errorf("Expected non-empty tokens")
	}
}

// TestDefaultUserServiceGetUsers test if getting users withing specific
// limit, page and role works expectedly with the method GetUsers of DefaultUserService.
func TestDefaultUserServiceGetUsers(t *testing.T) {
	userRepository, err := repositories.NewMemoryUserRepositoryWithUsers()
	if err != nil {
		t.Fatalf("Error creating memory user repository: %v", err)
	}

	tokenRepository := repositories.NewMemoryTokenRepository()
	authenticator := auth.NewJWTAuthenticator(config.AuthConfig{
		JWTSecret: "secret",
		Issuer:    "issuer",
	})

	role := models.Client
	service := NewDefaultUserService(userRepository, tokenRepository, authenticator)
	cases := []struct {
		limit          int
		page           int
		expectedSize   int
		role           *models.UserRole
		expectedEmails []string
	}{
		{
			limit:          4,
			page:           1,
			expectedSize:   4,
			role:           nil,
			expectedEmails: []string{"admin@example.com", "email1@example.com", "email2@example.com", "email3@example.com"},
		}, {
			limit:          4,
			page:           2,
			expectedSize:   4,
			role:           nil,
			expectedEmails: []string{"email4@example.com", "email5@example.com", "email6@example.com", "email7@example.com"},
		}, {
			limit:          4,
			page:           3,
			expectedSize:   2,
			role:           nil,
			expectedEmails: []string{"email8@example.com", "email9@example.com"},
		}, {
			limit:          4,
			page:           4,
			expectedSize:   0,
			role:           nil,
			expectedEmails: nil,
		}, {
			limit:          4,
			page:           1,
			role:           &role,
			expectedSize:   4,
			expectedEmails: []string{"email4@example.com", "email5@example.com", "email6@example.com", "email9@example.com"},
		},
	}

	for caseNum, c := range cases {
		t.Run(fmt.Sprintf("case-%d", caseNum), func(t *testing.T) {
			result, err := service.GetUsers(context.Background(), c.limit, c.page, c.role)
			if err != nil {
				t.Fatalf("Error getting users: %v", err)
			}
			if len(result) != c.expectedSize {
				t.Fatalf("Error getting users: %v, expected %v", len(result), c.expectedSize)
			}

			for i := 0; i < c.expectedSize; i++ {
				if result[i].Email != c.expectedEmails[i] {
					t.Fatalf("Error getting user email: %v, expected %v", result[i].Email, c.expectedEmails[i])
				}
			}
		})
	}

}
