package repositories

import (
	"api/models"
	"context"
	"testing"
)

func TestMemoryUserRepositoryAddUser(t *testing.T) {
	repo := NewMemoryUserRepository()
	user := &models.User{
		Email:    "user@example.com",
		Username: "user",
		Password: "password",
	}
	err := repo.AddUser(context.Background(), user)
	if err != nil {
		t.Errorf("Error adding user: %v", err)
	}
}

// TestMemoryUserRepositoryIdenticalUser used to test if adding user with same email
// or username gives an error.
func TestMemoryUserRepositoryIdenticalUser(t *testing.T) {
	repo := NewMemoryUserRepository()
	user := &models.User{
		Email:    "user@example.com",
		Username: "user",
		Password: "password",
	}
	err := repo.AddUser(context.Background(), user)
	if err != nil {
		t.Errorf("Error adding user: %v", err)
	}

	err = repo.AddUser(context.Background(), user)
	if err == nil {
		t.Errorf("Error must be not nill when adding user with same email or username")
	}
}
