package repositories

import (
	"api/models"
	"context"
	"fmt"
	"github.com/google/uuid"
	"testing"
)

// TestMemoryUserRepositoryAddUser tests if adding a user with the method AddUser of
// MemoryUserRepository works expectedly.
func TestMemoryUserRepositoryAddUser(t *testing.T) {
	repo := NewMemoryUserRepository()
	user := models.NewUser(uuid.New(), "email", "username", "password", models.Client)
	err := repo.AddUser(context.Background(), user)
	if err != nil {
		t.Errorf("Error adding user: %v", err)
	}
}

// TestMemoryUserRepositoryIdenticalUser tests if adding a user with the method AddUser of
// MemoryUserRepository returns an error.
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

// TestMemoryUserRepositoryCheckEmailAndUsername tests if checking user email and username with
// the method CheckEmailAndUsername of MemoryUserRepository work expectedly.
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

// TestMemoryUserRepositoryGetUserByUsername tests if fetching a user by username with
// the method GetUserByUsername of MemoryUserRepository works expectedly.
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

// TestMemoryUserRepositoryGetUsers tests if fetching users works expectedly with the method
// GetUsers of MemoryUserRepository.
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
			expectedEmails: []string{"admin@example.com", "email1@example.com", "email2@example.com", "email3@example.com"},
		},
		{
			limit:          4,
			page:           2,
			expectedSize:   4,
			expectedEmails: []string{"email4@example.com", "email5@example.com", "email6@example.com", "email7@example.com"},
		},
		{
			limit:          4,
			page:           3,
			expectedSize:   2,
			expectedEmails: []string{"email8@example.com", "email9@example.com"},
		},
		{
			limit:          4,
			page:           4,
			expectedSize:   0,
			expectedEmails: nil,
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
				if result[i].Email != c.expectedEmails[i] {
					t.Fatalf("Error getting user email: %v, expected %v", result[i].Email, c.expectedEmails[i])
				}
			}
		})
	}
}

// TestMemoryUserRepositoryGetUsersByRole tests if fetching users by role works expectedly with
// the method GetUsersByRole of MemoryUserRepository.
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
			expectedEmails: []string{"email4@example.com", "email5@example.com", "email6@example.com", "email9@example.com"},
		}, {
			limit:          1,
			page:           1,
			role:           models.Workshop,
			expectedSize:   1,
			expectedEmails: []string{"email1@example.com"},
		}, {
			limit:          1,
			page:           2,
			role:           models.Workshop,
			expectedSize:   1,
			expectedEmails: []string{"email7@example.com"},
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
				if result[i].Email != c.expectedEmails[i] {
					t.Fatalf("Error getting user email: %v, expected %v", result[i].Email, c.expectedEmails[i])
				}
			}
		})
	}
}
