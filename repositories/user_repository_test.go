package repositories_test

import (
	"api/models"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
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

func TestMemoryUserRepository_CheckEmailAndUsername(t *testing.T) {
	repo := memoryUserRepository(t)

	tests := []struct {
		name     string
		email    string
		username string
		expected bool
	}{
		{
			name:     "Valid email and username",
			email:    "NewUser@email.com",
			username: "NewUser",
			expected: false,
		}, {
			name:     "Invalid email and username",
			email:    "user1@example.com",
			username: "john_doe",
			expected: true,
		}, {
			name:     "Invalid email",
			email:    "user1@example.com",
			username: "NewUser",
			expected: true,
		}, {
			name:     "Invalid username",
			email:    "NewUser@email.com",
			username: "john_doe",
			expected: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := repo.CheckEmailAndUsername(context.Background(), test.email, test.username)

			if err != nil {
				t.Errorf("Error checking email and username: %v", err)
			}
			if result != test.expected {
				t.Errorf("Expected %t, got %t", test.expected, result)
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

func TestPostgresUserRepository_AddUser(t *testing.T) {
	seedUserDatabase(t)
	t.Cleanup(cleanupUserDatabase)

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

func TestPostgresUserRepository_CheckEmailAndUsername(t *testing.T) {
	seedUserDatabase(t)
	t.Cleanup(cleanupUserDatabase)

	tests := []struct {
		name     string
		email    string
		username string
		expected bool
	}{
		{
			name:     "Valid email and username",
			email:    "NewUser@email.com",
			username: "NewUser",
			expected: false,
		}, {
			name:     "Invalid email and username",
			email:    "user1@example.com",
			username: "john_doe",
			expected: true,
		}, {
			name:     "Invalid email",
			email:    "user1@example.com",
			username: "NewUser",
			expected: true,
		}, {
			name:     "Invalid username",
			email:    "NewUser@email.com",
			username: "john_doe",
			expected: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := userPostgresRepository.CheckEmailAndUsername(context.Background(), test.email, test.username)

			if err != nil {
				t.Errorf("Error checking email and username: %v", err)
			}
			if result != test.expected {
				t.Errorf("Expected %t, got %t", test.expected, result)
			}
		})
	}
}

func TestPostgresUserRepository_GetUserByUsername(t *testing.T) {
	seedUserDatabase(t)
	t.Cleanup(cleanupUserDatabase)

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

func TestPostgresUserRepository_GetUsers(t *testing.T) {
	seedUserDatabase(t)
	t.Cleanup(cleanupUserDatabase)

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
	seedUserDatabase(t)
	t.Cleanup(cleanupUserDatabase)

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
	seedUserDatabase(t)
	t.Cleanup(cleanupUserDatabase)

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
