package repositories

import (
	"api/models"
	"context"
	"database/sql"
	"errors"
	"github.com/google/uuid"
	"github.com/lib/pq"
)

// UserRepository defines methods used to modify user data.
type UserRepository interface {
	// AddUser stores a new user in the repository.
	//
	// Returns an error if the user could not be added (e.g., duplicate entry or database error).
	AddUser(ctx context.Context, user *models.User) error

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

	// GetUserByEmail fetches a user with a specific email.
	//
	// Retunes an error if a user with the specified email doesn't exist or there was a database error.
	GetUserByEmail(ctx context.Context, email string) (*models.UserInfo, error)

	// GetUserByUsername gets a user by specified username.
	//
	// Returns an error if a user with the specified username doesn't exist or there was a database error.
	GetUserByUsername(ctx context.Context, username string) (*models.User, error)

	// UpdateUser updates user data.
	//
	// Returns true if the user was found and updated.
	UpdateUser(ctx context.Context, user *models.UpdateUserPayload) (bool, error)

	// DeleteUser deletes a user with a specific id.
	//
	// Returns true if the user was deleted or false if the user was not found.
	// Returns error if there was a database error.
	DeleteUser(ctx context.Context, id uuid.UUID) (bool, error)

	// CheckIfUserIsActive checks if a user with a specific id is active.
	//
	// Return true if the user is active.
	// Returns error if there was a database error.
	CheckIfUserIsActive(ctx context.Context, id uuid.UUID) (bool, error)

	// ChangePassword changes the password of a user with specific id.
	//
	// Returns true if the password was updated, or false if the use was not found.
	// Returns error if there was a database error.
	ChangePassword(ctx context.Context, id uuid.UUID, password string) (bool, error)
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

func (r *MemoryUserRepository) AddUser(_ context.Context, user *models.User) error {
	for _, u := range r.users {
		if u.Email == user.Email || u.Username == user.Username {
			return &pq.Error{
				Code: "23505",
			}
		}
	}

	r.users = append(r.users, user)
	return nil
}

func (r *MemoryUserRepository) GetUsers(_ context.Context, limit, page int) ([]*models.UserInfo, error) {
	result := make([]*models.UserInfo, 0, limit)
	offset := (page - 1) * limit
	end := offset + limit
	if offset >= len(r.users) {
		return result, nil
	}

	if end > len(r.users) {
		end = len(r.users)
	}

	for i := offset; i < end; i++ {
		result = append(result, models.NewUserInfo(
			r.users[i].Id,
			r.users[i].Email,
			r.users[i].Username,
			r.users[i].Role,
			r.users[i].Active,
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
					u.Active,
				),
			)
		}
	}

	offset := (page - 1) * limit
	if offset >= len(filtered) {
		return make([]*models.UserInfo, 0), nil
	}

	end := offset + limit
	if end > len(filtered) {
		end = len(filtered)
	}

	return filtered[offset:end], nil
}

func (r *MemoryUserRepository) GetUserById(_ context.Context, id uuid.UUID) (*models.UserInfo, error) {
	for _, u := range r.users {
		if u.Id == id {
			return models.NewUserInfo(u.Id, u.Email, u.Username, u.Role, u.Active), nil
		}
	}
	return nil, sql.ErrNoRows
}

func (r *MemoryUserRepository) GetUserByEmail(_ context.Context, email string) (*models.UserInfo, error) {
	for _, u := range r.users {
		if u.Email == email {
			return models.NewUserInfo(u.Id, u.Email, u.Username, u.Role, u.Active), nil
		}
	}

	return nil, sql.ErrNoRows
}

func (r *MemoryUserRepository) GetUserByUsername(_ context.Context, username string) (*models.User, error) {
	for _, u := range r.users {
		if u.Username == username {
			return u, nil
		}
	}
	return nil, sql.ErrNoRows
}

func (r *MemoryUserRepository) UpdateUser(_ context.Context, user *models.UpdateUserPayload) (bool, error) {
	indexToUpdate := -1
	for i, u := range r.users {
		if u.Id == user.Id {
			indexToUpdate = i
			break
		}
	}

	if indexToUpdate == -1 {
		return false, nil
	}

	for i, u := range r.users {
		if (u.Email == user.Email || u.Username == user.Username) && indexToUpdate != i {
			return false, &pq.Error{
				Code: "23505",
			}
		}
	}

	r.users[indexToUpdate].Email = user.Email
	r.users[indexToUpdate].Username = user.Username
	r.users[indexToUpdate].Role = user.Role
	r.users[indexToUpdate].Active = user.Active
	return true, nil
}

func (r *MemoryUserRepository) DeleteUser(_ context.Context, id uuid.UUID) (bool, error) {
	for i, u := range r.users {
		if u.Id == id {
			r.users = append(r.users[:i], r.users[i+1:]...)
			return true, nil
		}
	}

	return false, nil
}

func (r *MemoryUserRepository) CheckIfUserIsActive(_ context.Context, id uuid.UUID) (bool, error) {
	for _, u := range r.users {
		if u.Id == id {
			return u.Active, nil
		}
	}

	return false, nil
}

func (r *MemoryUserRepository) ChangePassword(_ context.Context, id uuid.UUID, password string) (bool, error) {
	for _, u := range r.users {
		if u.Id == id {
			u.Password = password
			return true, nil
		}
	}
	return false, nil
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

func (r *PostgresUserRepository) GetUsers(ctx context.Context, limit, page int) ([]*models.UserInfo, error) {
	result := make([]*models.UserInfo, 0, limit)
	offset := (page - 1) * limit

	rows, err := r.db.QueryContext(
		ctx,
		` SELECT id, email, username, user_role, active
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
		err = rows.Scan(&info.Id, &info.Email, &info.Username, &info.Role, &info.Active)
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
		`SELECT id, email, username, user_role, active
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
		err = rows.Scan(&info.Id, &info.Email, &info.Username, &info.Role, &info.Active)
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

func (r *PostgresUserRepository) GetUserByEmail(ctx context.Context, email string) (*models.UserInfo, error) {
	row := r.db.QueryRowContext(
		ctx,
		`SELECT id, email, username, user_role
		FROM users
		WHERE email = $1`,
		email,
	)

	var user models.UserInfo
	err := row.Scan(&user.Id, &user.Email, &user.Username, &user.Role)
	return &user, err
}

func (r *PostgresUserRepository) GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	row := r.db.QueryRowContext(
		ctx,
		`SELECT id, email, username, password, user_role, active
		FROM users
		WHERE username = $1`,
		username,
	)

	var user models.User
	err := row.Scan(&user.Id, &user.Email, &user.Username, &user.Password, &user.Role, &user.Active)
	return &user, err
}

func (r *PostgresUserRepository) UpdateUser(ctx context.Context, user *models.UpdateUserPayload) (bool, error) {
	result, err := r.db.ExecContext(
		ctx,
		`UPDATE users 
		SET email = $1, username = $2, user_role = $3, active = $4
		WHERE id = $5`,
		user.Email,
		user.Username,
		user.Role,
		user.Active,
		user.Id,
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

func (r *PostgresUserRepository) DeleteUser(ctx context.Context, id uuid.UUID) (bool, error) {
	result, err := r.db.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, id)
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return rows > 0, nil
}

func (r *PostgresUserRepository) CheckIfUserIsActive(ctx context.Context, id uuid.UUID) (bool, error) {
	row := r.db.QueryRowContext(
		ctx,
		`SELECT active
		FROM users
		WHERE id = $1`,
		id,
	)

	var active bool
	err := row.Scan(&active)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}

	return active, err
}

func (r *PostgresUserRepository) ChangePassword(ctx context.Context, id uuid.UUID, password string) (bool, error) {
	result, err := r.db.ExecContext(
		ctx,
		`UPDATE users 
		SET password = $1
		WHERE id = $2`,
		password,
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

// NewPostgresUserRepository creates a new instance of PostgresUserRepository
func NewPostgresUserRepository(db *sql.DB) *PostgresUserRepository {
	return &PostgresUserRepository{
		db: db,
	}
}
