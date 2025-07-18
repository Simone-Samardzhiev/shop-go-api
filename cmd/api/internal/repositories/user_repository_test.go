package repositories_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"shop/cmd/api/internal/models"
	"testing"
)

func TestMemoryUserRepository_AddUser(t *testing.T) {
	repo := memoryUserRepository(t)

	tests := []struct {
		name          string
		user          *models.User
		shouldSucceed bool
	}{
		{
			name:          "Add user",
			user:          models.NewUser(uuid.New(), "newUser@email.com", "NewUser", "ValidNewPassword_1234", models.Client),
			shouldSucceed: true,
		}, {
			name:          "Add user with duplicate email",
			user:          models.NewUser(uuid.New(), "newUser@email.com", "NewUser1", "ValidNewPassword_1234", models.Client),
			shouldSucceed: false,
		}, {
			name:          "Add user with duplicate username",
			user:          models.NewUser(uuid.New(), "newUser1@email.com", "NewUser", "ValidNewPassword_1234", models.Client),
			shouldSucceed: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := repo.AddUser(context.Background(), test.user)

			if test.shouldSucceed && err != nil {
				t.Errorf("Error adding user: %v", err)
			} else if !test.shouldSucceed && err == nil {
				t.Errorf("Expected an error!")
			}
		})
	}
}

func TestMemoryUserRepository_GetUsers(t *testing.T) {
	repo := memoryUserRepository(t)

	tests := []struct {
		page          int
		limit         int
		expectedEmail []string
	}{
		{
			page:          1,
			limit:         4,
			expectedEmail: []string{"user1@example.com", "jane_smith@example.com", "alex.wilson@example.com", "emma.davis@example.com"},
		}, {
			page:          2,
			limit:         4,
			expectedEmail: []string{"michael.brown@example.com", "olivia.jones@example.com", "william.garcia@example.com", "sophia.rodriguez@example.com"},
		}, {
			page:          3,
			limit:         4,
			expectedEmail: []string{"james.martinez@example.com", "isabella.hernandez@example.com", "benjamin.lopez@example.com", "mia.gonzalez@example.com"},
		},
	}

	for i, test := range tests {
		t.Run(fmt.Sprintf("test-%d", i), func(t *testing.T) {
			result, err := repo.GetUsers(context.Background(), test.limit, test.page)
			if err != nil {
				t.Errorf("Error getting users: %v", err)
			}

			if len(result) != len(test.expectedEmail) {
				t.Errorf("Expected %d users, got %d", len(test.expectedEmail), len(result))
			}

			for j := 0; i < len(result); i++ {
				if result[j].Email != test.expectedEmail[j] {
					t.Errorf("Expected email %v, got %v", test.expectedEmail[i], result[i].Email)
				}
			}
		})
	}
}

func TestMemoryUserRepository_GetUsersByRole(t *testing.T) {
	repo := memoryUserRepository(t)

	tests := []struct {
		role          models.UserRole
		page          int
		limit         int
		expectedEmail []string
	}{
		{
			role:          models.Admin,
			page:          1,
			limit:         5,
			expectedEmail: []string{"user1@example.com", "michael.brown@example.com", "james.martinez@example.com", "daniel.perez@example.com", "joseph.flores@example.com"},
		}, {
			role:          models.Admin,
			page:          2,
			limit:         5,
			expectedEmail: []string{},
		}, {
			role:          models.Client,
			page:          1,
			limit:         3,
			expectedEmail: []string{"jane_smith@example.com", "olivia.jones@example.com", "isabella.hernandez@example.com"},
		}, {
			role:          models.Client,
			page:          2,
			limit:         3,
			expectedEmail: []string{"chloe.sanchez@example.com", "gracie.rivera@example.com"},
		},
	}

	for i, test := range tests {
		t.Run(fmt.Sprintf("test-%d", i), func(t *testing.T) {
			result, err := repo.GetUsersByRole(context.Background(), test.limit, test.page, test.role)

			if err != nil {
				t.Errorf("Error getting users: %v", err)
			}

			if len(result) != len(test.expectedEmail) {
				t.Errorf("Expected %d users, got %d", len(test.expectedEmail), len(result))
			}

			for j := 0; i < len(result); i++ {
				if result[j].Email != test.expectedEmail[j] {
					t.Errorf("Expected email %v, got %v", test.expectedEmail[i], result[i].Email)
				}
			}
		})
	}
}

func TestMemoryUserRepository_GetUserByID(t *testing.T) {
	repo := memoryUserRepository(t)

	tests := []struct {
		name          string
		id            uuid.UUID
		expectedEmail string
		expectedError error
	}{
		{
			name:          "Presented id",
			id:            uuid.MustParse("a1b2c3d4-e5f6-7890-1234-567890abcdef"),
			expectedEmail: "user1@example.com",
			expectedError: nil,
		}, {
			name:          "Absent id",
			id:            uuid.New(),
			expectedEmail: "",
			expectedError: sql.ErrNoRows,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := repo.GetUserById(context.Background(), test.id)

			if errors.Is(err, test.expectedError) {
				return
			} else {
				t.Errorf("Expected error %v, got %v", test.expectedError, err)
			}

			if result.Email != test.expectedEmail {
				t.Errorf("Expected email %v, got %v", test.expectedEmail, result.Email)
			}
		})
	}
}

func TestMemoryUserRepository_GetUserByEmail(t *testing.T) {
	repo := memoryUserRepository(t)
	tests := []struct {
		name             string
		email            string
		expectedUsername string
		expectedError    error
	}{
		{
			name:             "Get user by existing email email",
			email:            "user1@example.com",
			expectedUsername: "john_doe",
			expectedError:    nil,
		}, {
			name:             "Get user by non-existing email",
			email:            "",
			expectedUsername: "",
			expectedError:    sql.ErrNoRows,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := repo.GetUserByEmail(context.Background(), test.email)
			if errors.Is(err, test.expectedError) {
				return
			} else {
				t.Errorf("Expected error %v, got %v", test.expectedError, err)
			}

			if result.Username != test.expectedUsername {
				t.Errorf("Expected username %v, got %v", test.expectedUsername, result.Username)
			}
		})
	}
}

func TestMemoryUserRepository_GetUserByUsername(t *testing.T) {
	repo := memoryUserRepository(t)

	tests := []struct {
		name          string
		username      string
		expectedEmail string
		expectedError error
	}{
		{
			name:          "Present username",
			username:      "john_doe",
			expectedEmail: "user1@example.com",
			expectedError: nil,
		}, {
			name:          "Absent username",
			username:      "john_doe1",
			expectedEmail: "",
			expectedError: sql.ErrNoRows,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			user, err := repo.GetUserByUsername(context.Background(), test.username)

			if errors.Is(err, test.expectedError) {
				return
			} else {
				t.Errorf("Expected error %v, got %v", test.expectedError, err)
			}

			if test.expectedEmail != user.Email {
				t.Errorf("Expected email %v, got %v", test.expectedEmail, user.Email)
			}
		})
	}
}

func TestMemoryUserRepository_DeleteUser(t *testing.T) {
	repo := memoryUserRepository(t)

	tests := []struct {
		name     string
		id       uuid.UUID
		expected bool
	}{
		{
			name:     "Delete existing user",
			id:       uuid.MustParse("a1b2c3d4-e5f6-7890-1234-567890abcdef"),
			expected: true,
		}, {
			name:     "Delete non-existing user",
			id:       uuid.New(),
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := repo.DeleteUser(context.Background(), test.id)
			if err != nil {
				t.Fatalf("Error deleting user: %v", err)
			}
			if result != test.expected {
				t.Errorf("Expected %t, got %t", test.expected, result)
			}
		})
	}
}

func TestMemoryUserRepository_CheckIfUserIsActive(t *testing.T) {
	repo := memoryUserRepository(t)
	tests := []struct {
		id       uuid.UUID
		expected bool
	}{
		{
			id:       uuid.MustParse("a1b2c3d4-e5f6-7890-1234-567890abcdef"),
			expected: true,
		}, {
			id:       uuid.MustParse("b2c3d4e5-f6a7-8901-2345-67890abcdef1"),
			expected: false,
		}, {
			id:       uuid.New(),
			expected: false,
		},
	}

	for i, test := range tests {
		t.Run(fmt.Sprintf("%d-test", i), func(t *testing.T) {
			result, err := repo.CheckIfUserIsActive(context.Background(), test.id)
			if err != nil {
				t.Fatalf("Error checking if user is active: %v", err)
			}
			if result != test.expected {
				t.Errorf("Expected %t, got %t", test.expected, result)
			}
		})
	}
}

func TestMemoryUserRepository_UpdateUserEmail(t *testing.T) {
	repo := memoryUserRepository(t)

	tests := []struct {
		name     string
		id       uuid.UUID
		email    string
		expected bool
	}{
		{
			name:     "Update existing user",
			id:       uuid.MustParse("a1b2c3d4-e5f6-7890-1234-567890abcdef"),
			email:    "NewEmail@email.com",
			expected: true,
		}, {
			name:     "Update non-existing user",
			id:       uuid.New(),
			email:    "",
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := repo.UpdateUserEmail(context.Background(), test.id, test.email)
			if err != nil {
				t.Fatalf("Error updating user: %v", err)
			}
			if result != test.expected {
				t.Errorf("Expected %t, got %t", test.expected, result)
			}
		})
	}
}

func TestMemoryUserRepository_UpdateUserUsername(t *testing.T) {
	repo := memoryUserRepository(t)
	tests := []struct {
		name     string
		id       uuid.UUID
		username string
		expected bool
	}{
		{
			name:     "Update existing user",
			id:       uuid.MustParse("a1b2c3d4-e5f6-7890-1234-567890abcdef"),
			username: "NewUsername",
			expected: true,
		}, {
			name:     "Update non-existing user",
			id:       uuid.New(),
			username: "",
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := repo.UpdateUserUsername(context.Background(), test.id, test.username)
			if err != nil {
				t.Fatalf("Error updating user: %v", err)
			}
			if result != test.expected {
				t.Errorf("Expected %t, got %t", test.expected, result)
			}
		})
	}
}

func TestMemoryUserRepository_UpdateUserRole(t *testing.T) {
	repo := memoryUserRepository(t)
	tests := []struct {
		name     string
		id       uuid.UUID
		role     string
		expected bool
	}{
		{
			name:     "Update existing user",
			id:       uuid.MustParse("a1b2c3d4-e5f6-7890-1234-567890abcdef"),
			role:     models.Admin,
			expected: true,
		}, {
			name:     "Update non-existing user",
			id:       uuid.New(),
			role:     models.Admin,
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := repo.UpdateUserRole(context.Background(), test.id, test.role)
			if err != nil {
				t.Fatalf("Error updating user: %v", err)
			}
			if result != test.expected {
				t.Errorf("Expected %t, got %t", test.expected, result)
			}
		})
	}
}

func TestPostgresUserRepository_AddUser(t *testing.T) {
	seedUserTable(t)
	t.Cleanup(cleanupUserTable)

	tests := []struct {
		name          string
		user          *models.User
		shouldSucceed bool
	}{
		{
			name:          "Add user",
			user:          models.NewUser(uuid.New(), "newUser@email.com", "NewUser", "ValidNewPassword_1234", models.Client),
			shouldSucceed: true,
		}, {
			name:          "Add user with duplicate email",
			user:          models.NewUser(uuid.New(), "newUser@email.com", "NewUser1", "ValidNewPassword_1234", models.Client),
			shouldSucceed: false,
		}, {
			name:          "Add user with duplicate username",
			user:          models.NewUser(uuid.New(), "newUser1@email.com", "NewUser", "ValidNewPassword_1234", models.Client),
			shouldSucceed: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := userPostgresRepository.AddUser(context.Background(), test.user)

			if test.shouldSucceed && err != nil {
				t.Errorf("Error adding user: %v", err)
			} else if !test.shouldSucceed && err == nil {
				t.Errorf("Expected an error!")
			}
		})
	}
}

func TestPostgresUserRepository_GetUsers(t *testing.T) {
	seedUserTable(t)
	t.Cleanup(cleanupUserTable)

	tests := []struct {
		page          int
		limit         int
		expectedEmail []string
	}{
		{
			page:          1,
			limit:         4,
			expectedEmail: []string{"user1@example.com", "jane_smith@example.com", "alex.wilson@example.com", "emma.davis@example.com"},
		}, {
			page:          2,
			limit:         4,
			expectedEmail: []string{"michael.brown@example.com", "olivia.jones@example.com", "william.garcia@example.com", "sophia.rodriguez@example.com"},
		}, {
			page:          3,
			limit:         4,
			expectedEmail: []string{"james.martinez@example.com", "isabella.hernandez@example.com", "benjamin.lopez@example.com", "mia.gonzalez@example.com"},
		},
	}

	for i, test := range tests {
		t.Run(fmt.Sprintf("test-%d", i), func(t *testing.T) {
			result, err := userPostgresRepository.GetUsers(context.Background(), test.limit, test.page)
			if err != nil {
				t.Errorf("Error getting users: %v", err)
			}

			if len(result) != len(test.expectedEmail) {
				t.Errorf("Expected %d users, got %d", len(test.expectedEmail), len(result))
			}

			for j := 0; i < len(result); i++ {
				if result[j].Email != test.expectedEmail[j] {
					t.Errorf("Expected email %v, got %v", test.expectedEmail[i], result[i].Email)
				}
			}
		})
	}
}

func TestPostgresUserRepository_GetUsersByRole(t *testing.T) {
	seedUserTable(t)
	t.Cleanup(cleanupUserTable)

	tests := []struct {
		role          models.UserRole
		page          int
		limit         int
		expectedEmail []string
	}{
		{
			role:          models.Admin,
			page:          1,
			limit:         5,
			expectedEmail: []string{"user1@example.com", "michael.brown@example.com", "james.martinez@example.com", "daniel.perez@example.com", "joseph.flores@example.com"},
		}, {
			role:          models.Admin,
			page:          2,
			limit:         5,
			expectedEmail: []string{},
		}, {
			role:          models.Client,
			page:          1,
			limit:         3,
			expectedEmail: []string{"jane_smith@example.com", "olivia.jones@example.com", "isabella.hernandez@example.com"},
		}, {
			role:          models.Client,
			page:          2,
			limit:         3,
			expectedEmail: []string{"chloe.sanchez@example.com", "gracie.rivera@example.com"},
		},
	}

	for i, test := range tests {
		t.Run(fmt.Sprintf("test-%d", i), func(t *testing.T) {
			result, err := userPostgresRepository.GetUsersByRole(context.Background(), test.limit, test.page, test.role)

			if err != nil {
				t.Errorf("Error getting users: %v", err)
			}

			if len(result) != len(test.expectedEmail) {
				t.Errorf("Expected %d users, got %d", len(test.expectedEmail), len(result))
			}

			for j := 0; i < len(result); i++ {
				if result[j].Email != test.expectedEmail[j] {
					t.Errorf("Expected email %v, got %v", test.expectedEmail[i], result[i].Email)
				}
			}
		})
	}
}

func TestPostgresUserRepository_GetUserByID(t *testing.T) {
	seedUserTable(t)
	t.Cleanup(cleanupUserTable)

	tests := []struct {
		name          string
		id            uuid.UUID
		expectedEmail string
		expectedError error
	}{
		{
			name:          "Presented id",
			id:            uuid.MustParse("a1b2c3d4-e5f6-7890-1234-567890abcdef"),
			expectedEmail: "user1@example.com",
			expectedError: nil,
		}, {
			name:          "Absent id",
			id:            uuid.New(),
			expectedEmail: "",
			expectedError: sql.ErrNoRows,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := userPostgresRepository.GetUserById(context.Background(), test.id)

			if errors.Is(err, test.expectedError) {
				return
			} else {
				t.Errorf("Expected error %v, got %v", test.expectedError, err)
			}

			if result.Email != test.expectedEmail {
				t.Errorf("Expected email %v, got %v", test.expectedEmail, result.Email)
			}
		})
	}
}

func TestPostgresUserRepository_GetUserByEmail(t *testing.T) {
	seedUserTable(t)
	t.Cleanup(cleanupUserTable)

	tests := []struct {
		name             string
		email            string
		expectedUsername string
		expectedError    error
	}{
		{
			name:             "Get user by existing email email",
			email:            "user1@example.com",
			expectedUsername: "john_doe",
			expectedError:    nil,
		}, {
			name:             "Get user by non-existing email",
			email:            "",
			expectedUsername: "",
			expectedError:    sql.ErrNoRows,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := userPostgresRepository.GetUserByEmail(context.Background(), test.email)
			if errors.Is(err, test.expectedError) {
				return
			} else {
				t.Errorf("Expected error %v, got %v", test.expectedError, err)
			}

			if result.Username != test.expectedUsername {
				t.Errorf("Expected username %v, got %v", test.expectedUsername, result.Username)
			}
		})
	}
}

func TestPostgresUserRepository_GetUserByUsername(t *testing.T) {
	seedUserTable(t)
	t.Cleanup(cleanupUserTable)

	tests := []struct {
		name          string
		username      string
		expectedEmail string
		expectedError error
	}{
		{
			name:          "Present username",
			username:      "john_doe",
			expectedEmail: "user1@example.com",
			expectedError: nil,
		}, {
			name:          "Absent username",
			username:      "john_doe1",
			expectedEmail: "",
			expectedError: sql.ErrNoRows,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			user, err := userPostgresRepository.GetUserByUsername(context.Background(), test.username)

			if errors.Is(err, test.expectedError) {
				return
			} else {
				t.Errorf("Expected error %v, got %v", test.expectedError, err)
			}

			if user.Email != test.expectedEmail {
				t.Errorf("Expected email %v, got %v", test.expectedEmail, user.Email)
			}
		})
	}
}

func TestPostgresUserRepository_DeleteUser(t *testing.T) {
	seedUserTable(t)
	t.Cleanup(cleanupUserTable)

	tests := []struct {
		name     string
		id       uuid.UUID
		expected bool
	}{
		{
			name:     "Delete existing user",
			id:       uuid.MustParse("a1b2c3d4-e5f6-7890-1234-567890abcdef"),
			expected: true,
		}, {
			name:     "Delete non-existing user",
			id:       uuid.New(),
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := userPostgresRepository.DeleteUser(context.Background(), test.id)
			if err != nil {
				t.Fatalf("Error deleting user: %v", err)
			}
			if result != test.expected {
				t.Errorf("Expected %t, got %t", test.expected, result)
			}
		})
	}
}

func TestPostgresUserRepository_CheckIfUserIsActive(t *testing.T) {
	seedUserTable(t)
	t.Cleanup(cleanupUserTable)

	tests := []struct {
		id       uuid.UUID
		expected bool
	}{
		{
			id:       uuid.MustParse("a1b2c3d4-e5f6-7890-1234-567890abcdef"),
			expected: true,
		}, {
			id:       uuid.MustParse("b2c3d4e5-f6a7-8901-2345-67890abcdef1"),
			expected: false,
		}, {
			id:       uuid.New(),
			expected: false,
		},
	}

	for i, test := range tests {
		t.Run(fmt.Sprintf("%d-test", i), func(t *testing.T) {
			result, err := userPostgresRepository.CheckIfUserIsActive(context.Background(), test.id)
			if err != nil {
				t.Fatalf("Error checking if user is active: %v", err)
			}
			if result != test.expected {
				t.Errorf("Expected %t, got %t", test.expected, result)
			}
		})
	}
}

func TestPostgresUserRepository_UpdateUserEmail(t *testing.T) {
	seedUserTable(t)
	t.Cleanup(cleanupUserTable)

	tests := []struct {
		name     string
		id       uuid.UUID
		email    string
		expected bool
	}{
		{
			name:     "Update existing user",
			id:       uuid.MustParse("a1b2c3d4-e5f6-7890-1234-567890abcdef"),
			email:    "NewEmail@email.com",
			expected: true,
		}, {
			name:     "Update non-existing user",
			id:       uuid.New(),
			email:    "",
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := userPostgresRepository.UpdateUserEmail(context.Background(), test.id, test.email)
			if err != nil {
				t.Fatalf("Error updating user: %v", err)
			}
			if result != test.expected {
				t.Errorf("Expected %t, got %t", test.expected, result)
			}
		})
	}
}

func TestPostgresUserRepository_UpdateUserUsername(t *testing.T) {
	seedUserTable(t)
	t.Cleanup(cleanupUserTable)

	tests := []struct {
		name     string
		id       uuid.UUID
		username string
		expected bool
	}{
		{
			name:     "Update existing user",
			id:       uuid.MustParse("a1b2c3d4-e5f6-7890-1234-567890abcdef"),
			username: "NewUsername",
			expected: true,
		}, {
			name:     "Update non-existing user",
			id:       uuid.New(),
			username: "",
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := userPostgresRepository.UpdateUserUsername(context.Background(), test.id, test.username)
			if err != nil {
				t.Fatalf("Error updating user: %v", err)
			}
			if result != test.expected {
				t.Errorf("Expected %t, got %t", test.expected, result)
			}
		})
	}
}

func TestPostgresUserRepository_UpdateUserRole(t *testing.T) {
	seedUserTable(t)
	t.Cleanup(cleanupUserTable)

	tests := []struct {
		name     string
		id       uuid.UUID
		role     string
		expected bool
	}{
		{
			name:     "Update existing user",
			id:       uuid.MustParse("a1b2c3d4-e5f6-7890-1234-567890abcdef"),
			role:     models.Admin,
			expected: true,
		}, {
			name:     "Update non-existing user",
			id:       uuid.New(),
			role:     models.Admin,
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := userPostgresRepository.UpdateUserRole(context.Background(), test.id, test.role)
			if err != nil {
				t.Fatalf("Error updating user: %v", err)
			}
			if result != test.expected {
				t.Errorf("Expected %t, got %t", test.expected, result)
			}
		})
	}
}
