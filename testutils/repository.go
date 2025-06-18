package testutils

import (
	"api/auth"
	"api/models"
	"api/repositories"
	"database/sql"
	_ "embed"
	"encoding/json"
)

//go:embed testdata/users.json
var jsonUsers []byte

//go:embed testdata/tokens.json
var jsonTokens []byte

// getUsers decodes users from jsonUsers and returns them as slice.
//
// The function also hashes each user password before returning them.
func getUsers() ([]*models.User, error) {
	var users []*models.User
	err := json.Unmarshal(jsonUsers, &users)

	for _, user := range users {
		hash, hashErr := auth.HashPassword(user.Password)
		if hashErr != nil {
			return nil, hashErr
		}
		user.Password = hash
	}

	if err != nil {
		return nil, err
	}
	return users, nil
}

// NewMemoryUserRepositoryWithUsers creates a new instance of MemoryUserRepository.
//
// The function loads users from testdata/users.json.
func NewMemoryUserRepositoryWithUsers() (*repositories.MemoryUserRepository, error) {
	users, err := getUsers()
	if err != nil {
		return nil, err
	}
	return repositories.NewMemoryUserRepository(users), nil
}

// SeedUsersTable seeds users table with users loaded from testdata/users.json.
func SeedUsersTable(db *sql.DB) error {
	users, err := getUsers()
	if err != nil {
		return err
	}

	for _, user := range users {
		_, dbErr := db.Exec(
			`INSERT INTO users (id, email, username, password, user_role)
					VALUES ($1, $2, $3, $4, $5)`,
			user.Id,
			user.Email,
			user.Username,
			user.Password,
			user.Role,
		)
		if dbErr != nil {
			return dbErr
		}
	}

	return nil
}

// getTokens decodes tokens for jsonTokens and returns them as slice.
func getTokens() ([]*models.Token, error) {
	var tokens []*models.Token
	err := json.Unmarshal(jsonTokens, &tokens)
	if err != nil {
		return nil, err
	}
	return tokens, nil
}

// NewMemoryTokenRepositoryWithTokens creates a new instance of repositories.MemoryTokenRepository.
//
// The function also loads the tokens from testdata/tokens.json.
func NewMemoryTokenRepositoryWithTokens() (*repositories.MemoryTokenRepository, error) {
	tokens, err := getTokens()
	if err != nil {
		return nil, err
	}

	return repositories.NewMemoryTokenRepository(tokens), nil
}

// SeedTokensTable seeds tokens table with tokens loaded from testdata/tokens.json.
func SeedTokensTable(db *sql.DB) error {
	tokens, err := getTokens()
	if err != nil {
		return err
	}

	for _, token := range tokens {
		_, dbErr := db.Exec(
			`INSERT INTO tokens(id, user_id, exp) VALUES ($1, $2, $3)`,
			token.Id,
			token.UserId,
			token.ExpiresAt,
		)
		if dbErr != nil {
			return dbErr
		}
	}
	return nil
}

// CleanupDatabase will truncate and reset the identity for each table name passed.
//
// Note: Use with caution only on test databases.
func CleanupDatabase(tableNames []string, db *sql.DB) error {
	for _, tableName := range tableNames {
		_, err := db.Exec("TRUNCATE TABLE " + tableName + " RESTART IDENTITY CASCADE")

		if err != nil {
			return err
		}
	}
	return nil
}
