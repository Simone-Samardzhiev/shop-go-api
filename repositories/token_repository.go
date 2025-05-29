package repositories

import (
	"api/models"
	"context"
	"database/sql"
	"github.com/google/uuid"
)

// TokenRepository defines method for managing token data.
type TokenRepository interface {
	// AddToken stores a new token in the repository.
	//
	// Error is returned if the token fails to be added(e.g, database error)
	AddToken(ctx context.Context, token *models.Token) error

	// DeleteToken deletes a token with a specific id.
	//
	// If the token was deleted, the result is true, otherwise if the token with this id doesn't,
	// the result is false
	//
	// Error is returned if the token failed to delete due to an error(e. g database error)
	DeleteToken(ctx context.Context, id uuid.UUID) (bool, error)
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

func (r *MemoryTokenRepository) DeleteToken(_ context.Context, id uuid.UUID) (bool, error) {
	i := -1

	for index, token := range r.tokens {
		if token.Id == id {
			i = index
			break
		}
	}

	if i == -1 {
		return false, nil
	}

	r.tokens[i] = r.tokens[len(r.tokens)-1]
	r.tokens = r.tokens[:len(r.tokens)-1]
	return true, nil
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
		`INSERT INTO tokens(id, user_id, exp)
		VALUES ($1, $2, $3)`,
		token.Id,
		token.UserId,
		token.ExpiresAt,
	)

	return err
}

func (r *PostgresTokenRepository) DeleteToken(ctx context.Context, id uuid.UUID) (bool, error) {
	result, err := r.db.ExecContext(
		ctx,
		`DELETE FROM
        tokens WHERE id = $1`,
		id,
	)
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return rows > 0, nil
}

// NewPostgresTokenRepository returns a new instance of PostgresTokenRepository
func NewPostgresTokenRepository(db *sql.DB) *PostgresTokenRepository {
	return &PostgresTokenRepository{
		db: db,
	}
}
