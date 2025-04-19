package repositories

import (
	"api/models"
	"context"
	"database/sql"
)

// TokenRepository defines method for managing token data.
type TokenRepository interface {
	// AddToken stores a new token in the repository.
	//
	// Error is returned if the token fails to be added(e.g, database error)
	AddToken(ctx context.Context, token *models.Token) error
}

// MemoryTokenRepository implements TokenRepository with slice of tokens
//
// Mostly used to mock TokenRepository.
type MemoryTokenRepository struct {
	tokens []models.Token
}

func (r *MemoryTokenRepository) AddToken(_ context.Context, token *models.Token) error {
	r.tokens = append(r.tokens, *token)
	return nil
}

// NewMemoryTokenRepository return a new instance of MemoryTokenRepository.
func NewMemoryTokenRepository() *MemoryTokenRepository {
	return &MemoryTokenRepository{
		tokens: []models.Token{},
	}
}

// PostgresTokenRepository implements TokenRepository with postgres.
type PostgresTokenRepository struct {
	db *sql.DB
}

func (r *PostgresTokenRepository) AddToken(ctx context.Context, token *models.Token) error {
	_, err := r.db.ExecContext(
		ctx,
		`INSERT INTO tokens
		VALUES ($1, $2, $3)`,
		token.Id,
		token.UserId,
		token.ExpiresAt,
	)

	return err
}

// NewPostgresTokenRepository returns new instance of PostgresTokenRepository
func NewPostgresTokenRepository(db *sql.DB) *PostgresTokenRepository {
	return &PostgresTokenRepository{
		db: db,
	}
}
