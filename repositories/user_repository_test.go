package repositories

import (
	"api/auth"
	"api/models"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"log"
	"os"
	"testing"
)

var testDB *sql.DB
var postgresRepository *PostgresUserRepository

func TestMain(m *testing.M) {
	err := godotenv.Load("./../.env")
	if err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	databaseURL, exists := os.LookupEnv("TEST_DATABASE_URL")
	if !exists {
		log.Fatalf("TEST_DATABASE_URL environment variable is not set")
	}

	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		log.Fatalf("Error opening database connection: %v", err)
	}

	err = db.Ping()
	if err != nil {
		log.Fatalf("Error pinging database connection: %v", err)
	}

	testDB = db
	postgresRepository = NewPostgresUserRepository(db)
	m.Run()
	cleanUpDatabase()
}

// seedDatabase seeds the database with users read from testdata/users.json.
func seedDatabase() {
	file, err := os.Open("testdata/users.json")
	if err != nil {
		log.Fatalf("Error opening users.json file: %v", err)
	}
	defer func() {
		closeErr := file.Close()
		if closeErr != nil {
			log.Fatalf("Error closing users.json file: %v", err)
		}
	}()

	var users []models.User
	err = json.NewDecoder(file).Decode(&users)
	if err != nil {
		log.Fatalf("Error decoding users.json file: %v", err)
	}

	for _, user := range users {
		hash, hashErr := auth.HashPassword(user.Password)
		if hashErr != nil {
			log.Fatalf("Error hashing password: %v", hashErr)
		}
		user.Password = hash

		err = postgresRepository.AddUser(context.Background(), &user)
		if err != nil {
			log.Fatalf("Error seeding database: %v", err)
		}
	}
}

// cleanUpDatabase truncates table users in the database.
func cleanUpDatabase() {
	_, err := testDB.Exec("TRUNCATE TABLE users RESTART IDENTITY CASCADE")
	if err != nil {
		log.Fatalf("Error truncating users table: %v", err)
	}
}

func TestPostgresUserRepositoryAddUser(t *testing.T) {
	seedDatabase()
	t.Cleanup(cleanUpDatabase)

	hash, err := auth.HashPassword("Password!2")
	if err != nil {
		t.Fatalf("Error hashing password: %v", err)
	}

	tests := []struct {
		name          string
		user          *models.User
		expectedError bool
	}{
		{
			name:          "Add user",
			user:          models.NewUser(uuid.New(), "example@email.com", "Username", hash, models.Client),
			expectedError: false,
		}, {
			name:          "Add user with same email",
			user:          models.NewUser(uuid.New(), "example@email.com", "Username1", hash, models.Admin),
			expectedError: true,
		}, {
			name:          "Add user with same username",
			user:          models.NewUser(uuid.New(), "exmaple123@email.com", "Username", hash, models.Workshop),
			expectedError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repoErr := postgresRepository.AddUser(context.Background(), test.user)
			if repoErr != nil && !test.expectedError {
				t.Errorf("Error adding user: %v", err)
			} else if repoErr == nil && test.expectedError {
				t.Errorf("Error must be not nill")
			}
		})
	}
}

// TestPostgresUserRepositoryCheckEmailAndUsername tests that CheckEmailAndUsername method
// of PostgresUserRepository works expectedly.
func TestPostgresUserRepositoryCheckEmailAndUsername(t *testing.T) {
	seedDatabase()
	t.Cleanup(cleanUpDatabase)

	tests := []struct {
		name     string
		email    string
		username string
		expected bool
	}{
		{
			name:     "Check email and username",
			email:    "user1@example.com",
			username: "john_doe",
			expected: true,
		}, {
			name:     "Check email and username with only username matching",
			email:    "email",
			username: "john_doe",
			expected: true,
		}, {
			name:     "Check email and username with only email matching",
			email:    "user1@example.com",
			username: "username",
			expected: true,
		}, {
			name:     "Check email and username with no matching",
			email:    "email",
			username: "username",
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, repoErr := postgresRepository.CheckEmailAndUsername(context.Background(), test.email, test.username)
			if repoErr != nil {
				t.Errorf("Error checking email and username: %v", repoErr)
			}
			if result != test.expected {
				t.Errorf("Error checking email and username: %v, expected %v", result, test.expected)
			}
		})
	}
}

func TestPostgresUserRepositoryGetUserByUsername(t *testing.T) {
	seedDatabase()
	t.Cleanup(cleanUpDatabase)

	tests := []struct {
		name          string
		username      string
		expectedUser  *models.User
		expectedError error
	}{
		{
			name:     "Get user by username",
			username: "jane_s",
			expectedUser: models.NewUser(
				uuid.MustParse("b2c3d4e5-f6a7-8901-2345-67890abcdef1"),
				"jane_smith@example.com",
				"jane_s",
				"SecurePass2@",
				"client",
			),
			expectedError: nil,
		}, {
			name:          "Get user by invalid username",
			username:      "invalid_username",
			expectedUser:  &models.User{},
			expectedError: sql.ErrNoRows,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := postgresRepository.GetUserByUsername(context.Background(), test.username)
			if errors.Is(err, test.expectedError) {
				return
			} else {
				t.Errorf("Errors doesn't match: expected: %v, got: %v", test.expectedError, err)
			}

			if result.Id.String() != test.expectedUser.Id.String() {
				t.Errorf("Id doesn't match: expected: %v, got: %v", result.Id.String(), test.expectedUser.Id.String())
			} else if result.Email != test.expectedUser.Email {
				t.Errorf("Email doesn't match: expected: %v, got: %v", result.Email, test.expectedUser.Email)
			} else if result.Username != test.expectedUser.Username {
				t.Errorf("Username doesn't match: expected: %v, got: %v", result.Username, test.expectedUser.Username)
			} else if !auth.VerifyPassword(test.expectedUser.Password, result.Password) {
				t.Errorf("Password couldn't be verified")
			}
		})
	}
}

func TestPostgresUserRepositoryGetUsers(t *testing.T) {
	seedDatabase()
	t.Cleanup(cleanUpDatabase)

	cases := []struct {
		limit          int
		page           int
		expectedSize   int
		expectedEmails []string
	}{
		{
			limit:          4,
			page:           1,
			expectedSize:   4,
			expectedEmails: []string{"user1@example.com", "jane_smith@example.com", "alex.wilson@example.com", "emma.davis@example.com"},
		}, {
			limit:          4,
			page:           2,
			expectedSize:   4,
			expectedEmails: []string{"michael.brown@example.com", "olivia.jones@example.com", "william.garcia@example.com", "sophia.rodriguez@example.com"},
		}, {
			limit:          4,
			page:           5,
			expectedSize:   4,
			expectedEmails: []string{"joseph.flores@example.com", "gracie.rivera@example.com", "samuel.gomez@example.com", "lily.diaz@example.com"},
		}, {
			limit:          4,
			page:           6,
			expectedSize:   0,
			expectedEmails: nil,
		},
	}

	for i, test := range cases {
		t.Run(fmt.Sprintf("case-%d", i), func(t *testing.T) {
			result, err := postgresRepository.GetUsers(context.Background(), test.limit, test.page)
			if err != nil {
				t.Fatalf("Error getting users: %v", err)
			}
			if len(result) != test.expectedSize {
				t.Fatalf("Error getting users: %v, expected %v", len(result), test.expectedSize)
			}

			for i := 0; i < test.expectedSize; i++ {
				if result[i].Email != test.expectedEmails[i] {
					t.Fatalf("Error getting user email: expected: %s, got: %s", test.expectedEmails[i], result[i].Email)
				}
			}
		})

	}
}

func TestPostgresUserRepositoryGetUsersByRole(t *testing.T) {
	seedDatabase()
	t.Cleanup(cleanUpDatabase)

	cases := []struct {
		limit          int
		page           int
		role           models.UserRole
		expectedSize   int
		expectedEmails []string
	}{
		{
			limit:          4,
			page:           1,
			role:           models.Client,
			expectedSize:   4,
			expectedEmails: []string{"jane_smith@example.com", "olivia.jones@example.com", "isabella.hernandez@example.com", "chloe.sanchez@example.com"},
		}, {
			limit:          4,
			page:           2,
			role:           models.Client,
			expectedSize:   1,
			expectedEmails: []string{"gracie.rivera@example.com"},
		}, {
			limit:          4,
			page:           1,
			role:           models.Admin,
			expectedSize:   4,
			expectedEmails: []string{"user1@example.com", "michael.brown@example.com", "james.martinez@example.com", "daniel.perez@example.com"},
		},
	}

	for i, test := range cases {
		t.Run(fmt.Sprintf("case-%d", i), func(t *testing.T) {
			result, err := postgresRepository.GetUsersByRole(context.Background(), test.limit, test.page, test.role)
			if err != nil {
				t.Fatalf("Error getting users by role: %v", err)
			}
			if len(result) != test.expectedSize {
				t.Fatalf("Error getting users by role: %v, expected %v", len(result), test.expectedSize)
			}

			for i := 0; i < test.expectedSize; i++ {
				if result[i].Email != test.expectedEmails[i] {
					t.Fatalf("Error getting user email: expected: %s, got: %s", test.expectedEmails[i], result[i].Email)
				}
			}
		})
	}
}

func TestPostgresUserRepositoryGetUserById(t *testing.T) {
	seedDatabase()
	t.Cleanup(cleanUpDatabase)

	cases := []struct {
		id            uuid.UUID
		expectedEmail string
		expectedError error
	}{
		{
			id:            uuid.MustParse("a1b2c3d4-e5f6-7890-1234-567890abcdef"),
			expectedEmail: "user1@example.com",
			expectedError: nil,
		}, {
			id:            uuid.New(),
			expectedEmail: "",
			expectedError: sql.ErrNoRows,
		},
	}

	for i, test := range cases {
		t.Run(fmt.Sprintf("case-%d", i), func(t *testing.T) {
			result, err := postgresRepository.GetUserById(context.Background(), test.id)
			if errors.Is(err, test.expectedError) {
				return
			} else {
				t.Errorf("Errors doesn't match: expected: %v, got: %v", test.expectedError, err)
			}

			if result.Email != test.expectedEmail {
				t.Errorf("Email doesn't match: expected: %v, got: %v", test.expectedEmail, result.Email)
			}
		})
	}
}

func TestMemoryUserRepositoryAddUser(t *testing.T) {
	repo := NewMemoryUserRepository()

	hash, err := auth.HashPassword("Password!2")
	if err != nil {
		t.Fatalf("Error hashing password: %v", err)
	}

	tests := []struct {
		name          string
		user          *models.User
		expectedError bool
	}{
		{
			name:          "Add user",
			user:          models.NewUser(uuid.New(), "email", "username", hash, models.Client),
			expectedError: false,
		}, {
			name:          "Add user with same email",
			user:          models.NewUser(uuid.New(), "email", "NewUsername", hash, models.Client),
			expectedError: true,
		}, {
			name:          "Add user with same username",
			user:          models.NewUser(uuid.New(), "NewEmail", "username", hash, models.Client),
			expectedError: true,
		}, {
			name:          "Add user with new email and username",
			user:          models.NewUser(uuid.New(), "NewEmail", "NewUsername", hash, models.Admin),
			expectedError: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repoErr := repo.AddUser(context.Background(), test.user)
			if repoErr != nil && !test.expectedError {
				t.Errorf("Error adding user: %v", err)
			} else if repoErr == nil && test.expectedError {
				t.Errorf("Error must be not nill")
			}
		})
	}
}

func TestMemoryUserRepositoryCheckEmailAndUsername(t *testing.T) {
	repo := NewMemoryUserRepository()
	user := models.NewUser(uuid.New(), "email", "username", "password", models.Client)
	err := repo.AddUser(context.Background(), user)
	if err != nil {
		t.Errorf("Error adding user: %v", err)
	}

	tests := []struct {
		name     string
		email    string
		username string
		expected bool
	}{
		{
			name:     "Check email and username",
			email:    "email",
			username: "username",
			expected: true,
		}, {
			name:     "Check email and username with only username matching",
			email:    "email1",
			username: "username",
			expected: true,
		}, {
			name:     "Check email and username with only email matching",
			email:    "email",
			username: "username1",
			expected: true,
		}, {
			name:     "Check email and username with no matching",
			email:    "email1",
			username: "username1",
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, repoErr := repo.CheckEmailAndUsername(context.Background(), test.email, test.username)
			if repoErr != nil {
				t.Errorf("Error checking email and username: %v", err)
			}
			if result != test.expected {
				t.Errorf("Error checking email and username: %v, expected %v", result, test.expected)
			}
		})
	}
}

func TestMemoryUserRepositoryGetUserByUsername(t *testing.T) {
	repo := NewMemoryUserRepository()
	user := models.NewUser(uuid.New(), "email", "username", "password", models.Client)
	err := repo.AddUser(context.Background(), user)
	if err != nil {
		t.Errorf("Error adding user: %v", err)
	}

	result, err := repo.GetUserByUsername(context.Background(), "username")
	if err != nil {
		t.Errorf("Error getting user by username: %v", err)
	}
	if *result != *user {
		t.Errorf("Error getting user by username: %v, expected %v", user, result)
	}
}

func TestMemoryUserRepositoryGetUsers(t *testing.T) {
	repo, err := NewMemoryUserRepositoryWithUsers()
	if err != nil {
		t.Fatalf("Error creating memory user repository: %v", err)
	}

	cases := []struct {
		limit          int
		page           int
		expectedSize   int
		expectedEmails []string
	}{
		{
			limit:          4,
			page:           1,
			expectedSize:   4,
			expectedEmails: []string{"user1@example.com", "jane_smith@example.com", "alex.wilson@example.com", "emma.davis@example.com"},
		}, {
			limit:          4,
			page:           2,
			expectedSize:   4,
			expectedEmails: []string{"michael.brown@example.com", "olivia.jones@example.com", "william.garcia@example.com", "sophia.rodriguez@example.com"},
		}, {
			limit:          4,
			page:           5,
			expectedSize:   4,
			expectedEmails: []string{"joseph.flores@example.com", "gracie.rivera@example.com", "samuel.gomez@example.com", "lily.diaz@example.com"},
		}, {
			limit:          4,
			page:           6,
			expectedSize:   0,
			expectedEmails: nil,
		},
	}

	for i, test := range cases {
		t.Run(fmt.Sprintf("case-%d", i), func(t *testing.T) {
			result, repoErr := repo.GetUsers(context.Background(), test.limit, test.page)
			if repoErr != nil {
				t.Fatalf("Error getting users: %v", repoErr)
			}
			if len(result) != test.expectedSize {
				t.Fatalf("Error getting users: %v, expected %v", len(result), test.expectedSize)
			}

			for i := 0; i < test.expectedSize; i++ {
				if result[i].Email != test.expectedEmails[i] {
					t.Fatalf("Error getting user email: expected: %s, got: %s", test.expectedEmails[i], result[i].Email)
				}
			}
		})

	}
}

func TestMemoryUserRepositoryGetUsersByRole(t *testing.T) {
	repo, err := NewMemoryUserRepositoryWithUsers()

	if err != nil {
		t.Fatalf("Error creating memory user repository: %v", err)
	}

	cases := []struct {
		limit          int
		page           int
		role           models.UserRole
		expectedSize   int
		expectedEmails []string
	}{
		{
			limit:          4,
			page:           1,
			role:           models.Client,
			expectedSize:   4,
			expectedEmails: []string{"jane_smith@example.com", "olivia.jones@example.com", "isabella.hernandez@example.com", "chloe.sanchez@example.com"},
		}, {
			limit:          4,
			page:           2,
			role:           models.Client,
			expectedSize:   1,
			expectedEmails: []string{"gracie.rivera@example.com"},
		}, {
			limit:          4,
			page:           1,
			role:           models.Admin,
			expectedSize:   4,
			expectedEmails: []string{"user1@example.com", "michael.brown@example.com", "james.martinez@example.com", "daniel.perez@example.com"},
		},
	}

	for i, test := range cases {
		t.Run(fmt.Sprintf("case-%d", i), func(t *testing.T) {
			result, repoErr := repo.GetUsersByRole(context.Background(), test.limit, test.page, test.role)
			if repoErr != nil {
				t.Fatalf("Error getting users by role: %v", repoErr)
			}
			if len(result) != test.expectedSize {
				t.Fatalf("Error getting users by role: %v, expected %v", len(result), test.expectedSize)
			}

			for i := 0; i < test.expectedSize; i++ {
				if result[i].Email != test.expectedEmails[i] {
					t.Fatalf("Error getting user email: expected: %s, got: %s", test.expectedEmails[i], result[i].Email)
				}
			}
		})
	}
}

//func TestMemoryUserRepositoryGetUserById(t *testing.T) {
//	repo, err := NewMemoryUserRepositoryWithUsers()
//	if err != nil {
//		t.Fatalf("Error creating memory user repository: %v", err)
//	}
//
//	cases := []struct {
//		id            uuid.UUID
//		expectedEmail string
//		expectedError error
//	}
//}
