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
