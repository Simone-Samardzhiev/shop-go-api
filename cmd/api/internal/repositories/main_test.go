package repositories_test

import (
	"database/sql"
	"github.com/joho/godotenv"
	"log"
	"os"
	"shop/cmd/api/internal/repositories"
	"shop/cmd/api/internal/testutils"
	"testing"
)

var (
	userPostgresRepository  *repositories.PostgresUserRepository
	tokenPostgresRepository *repositories.PostgresTokenRepository
	// db holds reference to the connection.
	db *sql.DB
)

// TestMain will load the .env.test file and create a connection to the test database.
func TestMain(m *testing.M) {
	err := godotenv.Load("./../.env.test")
	if err != nil {
		log.Fatalf("Error loading .env.test file")
	}

	connectionStr := os.Getenv("TEST_DATABASE_URL")
	if connectionStr == "" {
		log.Fatalf("DATABASE_URL is not set")
	}

	db, err = sql.Open("postgres", connectionStr)
	if err != nil {
		log.Fatalf("Error opening database connection: %v", err)
	}

	err = db.Ping()
	if err != nil {
		log.Fatalf("Error pinging database connection: %v", err)
	}

	userPostgresRepository = repositories.NewPostgresUserRepository(db)
	tokenPostgresRepository = repositories.NewPostgresTokenRepository(db)
	m.Run()
}

// memoryUserRepository will return repositories.MemoryUserRepository with loaded users
// or fail the test if loading users fails.
func memoryUserRepository(t *testing.T) *repositories.MemoryUserRepository {
	t.Helper()

	repo, err := testutils.NewMemoryUserRepositoryWithUsers()
	if err != nil {
		t.Fatalf("Error creating memory user repository: %v", err)
	}
	return repo
}

// memoryTokenRepository will return repositories.MemoryTokenRepository with loaded users
// or fail the test if loading fails.
func memoryTokenRepository(t *testing.T) *repositories.MemoryTokenRepository {
	t.Helper()

	repo, err := testutils.NewMemoryTokenRepositoryWithTokens()
	if err != nil {
		t.Fatalf("Error creating memory token repository: %v", err)
	}
	return repo
}

// seedUserDatabase will add users to the test database.
func seedUserDatabase(t *testing.T) {
	t.Helper()
	err := testutils.SeedUsersTable(db)
	if err != nil {
		t.Fatalf("Error seeding database: %v", err)
	}
}

// cleanupUserDatabase will truncate table users and reset the identity.
func cleanupUserDatabase() {
	err := testutils.CleanupDatabase([]string{"users"}, db)
	if err != nil {
		log.Fatalf("Error cleaning up database: %v", err)
	}
}

// seedTokenDatabase will add tokens to the test database.
//
// Note: The users must be added first, or the token adding will fail.
func seedTokenDatabase(t *testing.T) {
	t.Helper()
	err := testutils.SeedTokensTable(db)
	if err != nil {
		t.Fatalf("Error seeding database: %v", err)
	}
}

// cleanupTokenDatabase will truncate table tokens and reset the identity.
func cleanupTokenDatabase() {
	err := testutils.CleanupDatabase([]string{"tokens"}, db)
	if err != nil {
		log.Fatalf("Error cleaning up database: %v", err)
	}
}
