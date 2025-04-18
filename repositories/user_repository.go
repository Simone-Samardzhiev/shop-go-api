package repositories

import (
	"api/models"
	"context"
	"database/sql"
	"errors"
)

// UserRepository defines methods used to modify user data.
type UserRepository interface {
	// AddUser stores a new user in the repository.
	//
	// Returns an error if the user could not be added (e.g. duplicate entry or database error).
	AddUser(ctx context.Context, user *models.User) error
}

// MemoryUserRepository implements UserRepository with slice of users.
//
// Mostly used to mock UserRepository.
type MemoryUserRepository struct {
	users []models.User
}

// NewMemoryUserRepository creates new instance of MemoryUserRepository
func NewMemoryUserRepository() *MemoryUserRepository {
	return &MemoryUserRepository{users: make([]models.User, 0)}
}

func (r *MemoryUserRepository) AddUser(_ context.Context, user *models.User) error {
	for _, u := range r.users {
		if u.Email == user.Email || u.Username == user.Username {
			return errors.New("user email or password already exists")
		}
	}

	r.users = append(r.users, *user)
	return nil
}

// PostgresUserRepository implements UserRepository using postgres.
type PostgresUserRepository struct {
	db *sql.DB
}

func (r *PostgresUserRepository) AddUser(ctx context.Context, user *models.User) error {
	_, err := r.db.ExecContext(
		ctx,
		` INSERT INTO users (id, email, username, password, user_type) 
 		VALUES ($1, $2, $3, $4, $5)`,
		user.Id,
		user.Email,
		user.Username,
		user.Password,
		user.UserType,
	)

	return err
}

// NewPostgresUserRepository creates new instance of PostgresUserRepository
func NewPostgresUserRepository(db *sql.DB) *PostgresUserRepository {
	return &PostgresUserRepository{
		db: db,
	}
}
