package repositories

import (
	"api/models"
	"context"
	"fmt"
	"github.com/google/uuid"
	"testing"
)

// TestMemoryUserRepositoryAddUser test if adding a user is successful.
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

// TestMemoryUserRepositoryCheckEmailAndUsername test if the method for checking if the email or the username exist
// works expectedly.
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

// TestMemoryUserRepositoryGetUserByUsername tests if fetching a user by email work expectedly.
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

// TestMemoryUserRepositoryGetUsers verifies that getting users by specie page and
func TestMemoryUserRepositoryGetUsers(t *testing.T) {
	repo := NewMemoryUserRepositoryWithUsers()

	cases := []struct {
		limit         int
		page          int
		expectedSize  int
		expectedEmail []string
	}{
		{
			limit:         4,
			page:          1,
			expectedSize:  4,
			expectedEmail: []string{"email1", "email2", "email3", "email4"},
		},
		{
			limit:         4,
			page:          2,
			expectedSize:  4,
			expectedEmail: []string{"email5", "email6", "email7", "email8"},
		},
		{
			limit:         4,
			page:          3,
			expectedSize:  2,
			expectedEmail: []string{"email9", "email10"},
		},
		{
			limit:         4,
			page:          4,
			expectedSize:  0,
			expectedEmail: nil,
		},
	}

	for caseNum, c := range cases {
		t.Run(fmt.Sprintf("case-%d", caseNum), func(t *testing.T) {
			result, err := repo.GetUsers(context.Background(), c.limit, c.page)
			if err != nil {
				t.Fatalf("Error getting users: %v", err)
			}
			if len(result) != c.expectedSize {
				t.Fatalf("Error getting users: %v, expected %v", len(result), c.expectedSize)
			}

			for i := 0; i < c.expectedSize; i++ {
				if result[i].Email != c.expectedEmail[i] {
					t.Fatalf("Error getting user email: %v, expected %v", result[i].Email, c.expectedEmail[i])
				}
			}
		})
	}
}

func TestMemoryUserRepositoryGetUsersByRole(t *testing.T) {
	repo := NewMemoryUserRepositoryWithUsers()

	cases := []struct {
		limit         int
		page          int
		role          models.UserRole
		expectedSize  int
		expectedEmail []string
	}{
		{
			limit:         4,
			page:          1,
			role:          models.Client,
			expectedSize:  4,
			expectedEmail: []string{"email1", "email5", "email6", "email7"},
		},
		{
			limit:         4,
			page:          2,
			role:          models.Client,
			expectedSize:  1,
			expectedEmail: []string{"email10"},
		},
	}

	for caseNum, c := range cases {
		t.Run(fmt.Sprintf("case-%d", caseNum), func(t *testing.T) {
			result, err := repo.GetUsersByRole(context.Background(), c.limit, c.page, c.role)
			if err != nil {
				t.Fatalf("Error getting users: %v", err)
			}
			if len(result) != c.expectedSize {
				t.Fatalf("Error getting users: %v, expected %v", len(result), c.expectedSize)
			}

			for i := 0; i < c.expectedSize; i++ {
				if result[i].Email != c.expectedEmail[i] {
					t.Fatalf("Error getting user email: %v, expected %v", result[i].Email, c.expectedEmail[i])
				}
			}
		})
	}
}
