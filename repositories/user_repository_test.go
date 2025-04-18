package repositories

import (
	"api/models"
	"context"
	"github.com/google/uuid"
	"testing"
)

func TestMemoryUserRepositoryAddUser(t *testing.T) {
	repo := NewMemoryUserRepository()
	user := models.NewUser(uuid.New(), "email", "username", "password", models.Client)
	err := repo.AddUser(context.Background(), user)
	if err != nil {
		t.Errorf("Error adding user: %v", err)
	}
}

// TestMemoryUserRepositoryIdenticalUser used to test if adding user with same email
// or username gives an error.
func TestMemoryUserRepositoryIdenticalUser(t *testing.T) {
	repo := NewMemoryUserRepository()
	user := models.NewUser(uuid.New(), "email", "username", "password", models.Client)
	err := repo.AddUser(context.Background(), user)
	if err != nil {
		t.Errorf("Error adding user: %v", err)
	}

	err = repo.AddUser(context.Background(), user)
	if err == nil {
		t.Errorf("Error must be not nill when adding user with same email or username")
	}
}

func TestMemoryUserRepositoryCheckEmailAndUsername(t *testing.T) {
	repo := NewMemoryUserRepository()
	user := models.NewUser(uuid.New(), "email", "username", "password", models.Client)
	err := repo.AddUser(context.Background(), user)
	if err != nil {
		t.Errorf("Error adding user: %v", err)
	}

	result, err := repo.CheckEmailAndUsername(context.Background(), "email", "")
	if err != nil {
		t.Errorf("Error checking email and username: %v", err)
	}
	if !result {
		t.Errorf("User added with email: %s, but not found with email: %s ", user.Email, "email")
	}

	result, err = repo.CheckEmailAndUsername(context.Background(), "", "username")
	if err != nil {
		t.Errorf("Error checking email and username: %v", err)
	}
	if !result {
		t.Errorf("User added with username: %s, but not found with username: %s ", user.Username, "username")
	}
}
