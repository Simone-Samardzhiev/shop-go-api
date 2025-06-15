package testutils

import (
	"api/auth"
	"api/models"
	"api/repositories"
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
)

//go:embed testdata/users.json
var jsonUsers []byte

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
func SeedUsersTable(repository repositories.UserRepository) error {
	users, err := getUsers()
	if err != nil {
		return err
	}

	for _, user := range users {
		repoErr := repository.AddUser(context.Background(), user)
		if repoErr != nil {
			return repoErr
		}
	}

	return nil
}

func CleanupDatabase(tableNames []string, db *sql.DB) error {
	for _, tableName := range tableNames {
		_, err := db.Exec("TRUNCATE TABLE $1 RESTART IDENTITY CASCADE", tableName)

		if err != nil {
			return err
		}
	}
	return nil
}
