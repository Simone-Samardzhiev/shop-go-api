package repositories

import (
	"api/models"
	"context"
	"github.com/google/uuid"
	"testing"
	"time"
)

// TestMemoryTokenRepositoryAddToken checks if adding a new token works expectedly.
func TestMemoryTokenRepositoryAddToken(t *testing.T) {
	repo := NewMemoryTokenRepository()
	err := repo.AddToken(context.Background(), models.NewToken(uuid.New(), uuid.New(), time.Now().Add(time.Minute)))
	if err != nil {
		t.Errorf("Error adding token: %v", err)
	}
}

// TestMemoryTokenRepositoryDeleteToken verifies that deleting an existing token result in true
// and non existing in false.
func TestMemoryTokenRepositoryDeleteToken(t *testing.T) {
	repo := NewMemoryTokenRepository()
	tokenId := uuid.New()
	err := repo.AddToken(context.Background(), models.NewToken(tokenId, uuid.New(), time.Now().Add(time.Minute)))
	if err != nil {
		t.Fatalf("Error adding token: %v", err)
	}

	// Deleting the token with should return true.
	result, err := repo.DeleteToken(context.Background(), tokenId)
	if err != nil {
		t.Fatalf("Error deleting token: %v", err)
	}
	if !result {
		t.Fatalf("Expected result to be true")
	}

	// Deleting the token again should result in false.
	result, err = repo.DeleteToken(context.Background(), tokenId)
	if err != nil {
		t.Fatalf("Error deleting token: %v", err)
	}
	if result {
		t.Fatalf("Expected result to be true")
	}
}
