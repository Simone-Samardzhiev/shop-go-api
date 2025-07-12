package repositories_test

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	"shop/cmd/api/internal/models"
	"testing"
	"time"
)

func TestMemoryTokenRepository_AddToken(t *testing.T) {
	repo := memoryTokenRepository(t)

	tokens := []*models.Token{
		{
			Id:        uuid.New(),
			UserId:    uuid.MustParse("a1b2c3d4-e5f6-7890-1234-567890abcdef"),
			ExpiresAt: time.Now().Add(time.Hour * 24),
		}, {
			Id:        uuid.New(),
			UserId:    uuid.MustParse("b2c3d4e5-f6a7-8901-2345-67890abcdef1"),
			ExpiresAt: time.Now().Add(time.Hour * 24),
		}, {
			Id:        uuid.New(),
			UserId:    uuid.MustParse("c3d4e5f6-a7b8-9012-3456-7890abcdef23"),
			ExpiresAt: time.Now().Add(time.Hour * 24),
		},
	}

	for i, token := range tokens {
		t.Run(fmt.Sprintf("test-%d", i), func(t *testing.T) {
			err := repo.AddToken(context.Background(), token)
			if err != nil {
				t.Errorf("Error adding token: %v", err)
			}
		})
	}
}

func TestMemoryTokenRepository_DeleteToken(t *testing.T) {
	repo := memoryTokenRepository(t)

	tests := []struct {
		name     string
		id       uuid.UUID
		expected bool
	}{
		{
			name:     "Existing id",
			id:       uuid.MustParse("e0a1c2b3-d4e5-4f6a-87b8-9c0d1e2f3a4b"),
			expected: true,
		}, {
			name:     "Absent id(1)",
			id:       uuid.MustParse("e0a1c2b3-d4e5-4f6a-87b8-9c0d1e2f3a4b"),
			expected: false,
		}, {
			name:     "Absent id(2)",
			id:       uuid.New(),
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := repo.DeleteToken(context.Background(), test.id)

			if err != nil {
				t.Errorf("Error deleting token: %v", err)
			}
			if result != test.expected {
				t.Errorf("Expected %t, got %t", test.expected, result)
			}
		})
	}
}

func TestMemoryTokenRepository_DeleteTokenByUserId(t *testing.T) {
	repo := memoryTokenRepository(t)

	tests := []struct {
		name     string
		userId   uuid.UUID
		expected bool
	}{
		{
			name:     "Existing user id",
			userId:   uuid.MustParse("a1b2c3d4-e5f6-7890-1234-567890abcdef"),
			expected: true,
		}, {
			name:     "Non-existing user id",
			userId:   uuid.New(),
			expected: false,
		},
	}

	for i, test := range tests {
		t.Run(fmt.Sprintf("test-%d", i), func(t *testing.T) {
			result, err := repo.DeleteTokensByUserId(context.Background(), test.userId)
			if err != nil {
				t.Fatalf("Error deleting token: %v", err)
			}
			if result != test.expected {
				t.Errorf("Expected %t, got %t", test.expected, result)
			}
		})
	}
}

func TestPostgresTokenRepository_AddToken(t *testing.T) {
	seedUserDatabase(t)
	seedTokenDatabase(t)
	t.Cleanup(cleanupTokenDatabase)
	t.Cleanup(cleanupUserDatabase)

	tokens := []*models.Token{
		{
			Id:        uuid.New(),
			UserId:    uuid.MustParse("a1b2c3d4-e5f6-7890-1234-567890abcdef"),
			ExpiresAt: time.Now().Add(time.Hour * 24),
		}, {
			Id:        uuid.New(),
			UserId:    uuid.MustParse("b2c3d4e5-f6a7-8901-2345-67890abcdef1"),
			ExpiresAt: time.Now().Add(time.Hour * 24),
		}, {
			Id:        uuid.New(),
			UserId:    uuid.MustParse("c3d4e5f6-a7b8-9012-3456-7890abcdef23"),
			ExpiresAt: time.Now().Add(time.Hour * 24),
		},
	}

	for i, token := range tokens {
		t.Run(fmt.Sprintf("test-%d", i), func(t *testing.T) {
			err := tokenPostgresRepository.AddToken(context.Background(), token)
			if err != nil {
				t.Errorf("Error adding token: %v", err)
			}
		})
	}
}

func TestPostgresTokenRepository_DeleteToken(t *testing.T) {
	seedUserDatabase(t)
	seedTokenDatabase(t)
	t.Cleanup(cleanupTokenDatabase)
	t.Cleanup(cleanupUserDatabase)

	tests := []struct {
		name     string
		id       uuid.UUID
		expected bool
	}{
		{
			name:     "Existing id",
			id:       uuid.MustParse("e0a1c2b3-d4e5-4f6a-87b8-9c0d1e2f3a4b"),
			expected: true,
		}, {
			name:     "Absent id(1)",
			id:       uuid.MustParse("e0a1c2b3-d4e5-4f6a-87b8-9c0d1e2f3a4b"),
			expected: false,
		}, {
			name:     "Absent id(2)",
			id:       uuid.New(),
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := tokenPostgresRepository.DeleteToken(context.Background(), test.id)

			if err != nil {
				t.Errorf("Error deleting token: %v", err)
			}
			if result != test.expected {
				t.Errorf("Expected %t, got %t", test.expected, result)
			}
		})
	}
}

func TestPostgresTokenRepository_DeleteTokenByUserId(t *testing.T) {
	seedUserDatabase(t)
	seedTokenDatabase(t)
	t.Cleanup(cleanupUserDatabase)
	t.Cleanup(cleanupTokenDatabase)

	tests := []struct {
		name     string
		userId   uuid.UUID
		expected bool
	}{
		{
			name:     "Existing user id",
			userId:   uuid.MustParse("a1b2c3d4-e5f6-7890-1234-567890abcdef"),
			expected: true,
		}, {
			name:     "Non-existing user id",
			userId:   uuid.New(),
			expected: false,
		},
	}

	for i, test := range tests {
		t.Run(fmt.Sprintf("test-%d", i), func(t *testing.T) {
			result, err := tokenPostgresRepository.DeleteTokensByUserId(context.Background(), test.userId)
			if err != nil {
				t.Fatalf("Error deleting token: %v", err)
			}
			if result != test.expected {
				t.Errorf("Expected %t, got %t", test.expected, result)
			}
		})
	}
}
