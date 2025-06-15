package repositories

import (
	"api/models"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"os"
)

// UserRepository defines methods used to modify user data.
type UserRepository interface {
	// AddUser stores a new user in the repository.
	//
	// Returns an error if the user could not be added (e.g., duplicate entry or database error).
	AddUser(ctx context.Context, user *models.User) error

	// CheckEmailAndUsername checks if the email or the username are in use.
	//
	// Return true if they are in use or a database error.
	CheckEmailAndUsername(ctx context.Context, email string, username string) (bool, error)

	// GetUserByUsername gets a user by specified username.
	//
	// Returns an error if a user with the specified username doesn't exist or there was a database error.
	GetUserByUsername(ctx context.Context, username string) (*models.User, error)

	// GetUsers gets UserInfo from users.
	//
	// The limit specifies how many users are returned.
	// The page is used to specify which page to return.
	GetUsers(ctx context.Context, limit, page int) ([]*models.UserInfo, error)

	// GetUsersByRole gets UserInfo from users.
	//
	// The limit specifies how many users are returned.
	// The page is used to specify which page to return.
	// The role is used to filter users by specific role.
	GetUsersByRole(ctx context.Context, limit, page int, role models.UserRole) ([]*models.UserInfo, error)

	// GetUserById gets a user by specified id.
	//
	// Returns an error if a user with the specified id doesn't exist or there was a database error.
	GetUserById(ctx context.Context, id uuid.UUID) (*models.UserInfo, error)
}

// MemoryUserRepository implements UserRepository with a slice of users.
//
// Mostly used to mock UserRepository.
type MemoryUserRepository struct {
	users []*models.User
}

// NewMemoryUserRepository creates a new instance of MemoryUserRepository.
func NewMemoryUserRepository(user []*models.User) *MemoryUserRepository {
	if user == nil {
		user = make([]*models.User, 0)
	}
	return &MemoryUserRepository{users: user}
}

// NewMemoryUserRepositoryWithUsers creates a new instance of MemoryUserRepository.
//
// The function loads users from testdata/users.json.
//
// The password is the same for all (Password_123)
func NewMemoryUserRepositoryWithUsers() (*MemoryUserRepository, error) {
	file, err := os.Open("testdata/users.json")
	if err != nil {
		return nil, err
	}
	defer func() {
		closeErr := file.Close()
		if closeErr != nil {
			return
		}
	}()

	var users []*models.User
	err = json.NewDecoder(file).Decode(&users)
	if err != nil {
		return nil, err
	}

	repo := NewMemoryUserRepository()
	repo.users = users

	return repo, nil
}

func (r *MemoryUserRepository) AddUser(_ context.Context, user *models.User) error {
	for _, u := range r.users {
		if u.Email == user.Email || u.Username == user.Username {
			return errors.New("user email or password already exists")
		}
	}

	r.users = append(r.users, user)
	return nil
}

func (r *MemoryUserRepository) CheckEmailAndUsername(_ context.Context, email string, username string) (bool, error) {
	for _, u := range r.users {
		if u.Email == email || u.Username == username {
			return true, nil
		}
	}
	return false, nil
}

func (r *MemoryUserRepository) GetUserByUsername(_ context.Context, username string) (*models.User, error) {
	for _, u := range r.users {
		if u.Username == username {
			return u, nil
		}
	}
	return nil, sql.ErrNoRows
}

func (r *MemoryUserRepository) GetUsers(_ context.Context, limit, page int) ([]*models.UserInfo, error) {
	result := make([]*models.UserInfo, 0, limit)
	offset := (page - 1) * limit
	end := offset + limit
	if end > len(r.users) {
		end = len(r.users)
	}

	for i := offset; i < end; i++ {
		result = append(result, models.NewUserInfo(
			r.users[i].Id,
			r.users[i].Email,
			r.users[i].Username,
			r.users[i].Role,
		))
	}

	return result, nil
}

func (r *MemoryUserRepository) GetUsersByRole(_ context.Context, limit, page int, role models.UserRole) ([]*models.UserInfo, error) {
	filtered := make([]*models.UserInfo, 0)
	for _, u := range r.users {
		if u.Role == role {
			filtered = append(
				filtered,
				models.NewUserInfo(
					u.Id,
					u.Email,
					u.Username,
					u.Role,
				),
			)
		}
	}

	offset := (page - 1) * limit
	end := offset + limit
	if end > len(filtered) {
		end = len(filtered)
	}

	return filtered[offset:end], nil
}

func (r *MemoryUserRepository) GetUserById(_ context.Context, id uuid.UUID) (*models.UserInfo, error) {
	for _, u := range r.users {
		if u.Id == id {
			return models.NewUserInfo(u.Id, u.Email, u.Username, u.Role), nil
		}
	}
	return nil, sql.ErrNoRows
}

// PostgresUserRepository implements UserRepository using postgres.
type PostgresUserRepository struct {
	db *sql.DB
}

func (r *PostgresUserRepository) AddUser(ctx context.Context, user *models.User) error {
	_, err := r.db.ExecContext(
		ctx,
		` INSERT INTO users (id, email, username, password, user_role) 
 		VALUES ($1, $2, $3, $4, $5)`,
		user.Id,
		user.Email,
		user.Username,
		user.Password,
		user.Role,
	)

	return err
}

func (r *PostgresUserRepository) CheckEmailAndUsername(ctx context.Context, email string, username string) (bool, error) {
	row := r.db.QueryRowContext(
		ctx,
		`SELECT EXISTS( SELECT 1 FROM users WHERE email = $1 OR username = $2)`,
		email,
		username,
	)
	var exists bool
	err := row.Scan(&exists)
	return exists, err
}

func (r *PostgresUserRepository) GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	row := r.db.QueryRowContext(
		ctx,
		`SELECT id, email, username, password, user_role
		FROM users
		WHERE username = $1`,
		username,
	)

	var user models.User
	err := row.Scan(&user.Id, &user.Email, &user.Username, &user.Password, &user.Role)
	return &user, err
}

func (r *PostgresUserRepository) GetUsers(ctx context.Context, limit, page int) ([]*models.UserInfo, error) {
	result := make([]*models.UserInfo, 0, limit)
	offset := (page - 1) * limit

	rows, err := r.db.QueryContext(
		ctx,
		` SELECT id, email, username, user_role
 		FROM users
 		OFFSET $1
 		LIMIT $2
 		`,
		offset,
		limit,
	)

	defer func() {
		closeErr := rows.Close()
		if closeErr != nil {
			err = closeErr
		}
	}()

	if err != nil {
		return result, err
	}

	for rows.Next() {
		var info models.UserInfo
		err = rows.Scan(&info.Id, &info.Email, &info.Username, &info.Role)
		if err != nil {
			return result, err
		}
		result = append(result, &info)
	}

	return result, nil
}

func (r *PostgresUserRepository) GetUsersByRole(ctx context.Context, limit, page int, role models.UserRole) ([]*models.UserInfo, error) {
	result := make([]*models.UserInfo, 0, limit)
	offset := (page - 1) * limit

	rows, err := r.db.QueryContext(
		ctx,
		`SELECT id, email, username, user_role
		FROM users 
		WHERE user_role = $1 
		OFFSET $2 
		LIMIT $3`,
		role,
		offset,
		limit,
	)
	if err != nil {
		return result, err
	}

	defer func() {
		closeErr := rows.Close()
		if closeErr != nil {
			err = closeErr
		}
	}()

	for rows.Next() {
		var info models.UserInfo
		err = rows.Scan(&info.Id, &info.Email, &info.Username, &info.Role)
		if err != nil {
			return result, err
		}
		result = append(result, &info)
	}

	return result, nil
}

func (r *PostgresUserRepository) GetUserById(ctx context.Context, id uuid.UUID) (*models.UserInfo, error) {
	row := r.db.QueryRowContext(
		ctx,
		`SELECT id, email, username, user_role
		FROM users
		WHERE id = $1`,
		id,
	)

	var user models.UserInfo
	err := row.Scan(&user.Id, &user.Email, &user.Username, &user.Role)
	return &user, err
}

// NewPostgresUserRepository creates a new instance of PostgresUserRepository
func NewPostgresUserRepository(db *sql.DB) *PostgresUserRepository {
	return &PostgresUserRepository{
		db: db,
	}
}
