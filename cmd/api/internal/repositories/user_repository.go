package repositories

import (
	"context"
	"database/sql"
	"errors"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"shop/cmd/api/internal/models"
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

	// DeleteUser deletes a user with a specific id.
	//
	// Returns true if the user was deleted or false if the user was not found.
	// Returns error if there was a database error.
	DeleteUser(ctx context.Context, id uuid.UUID) (bool, error)

	// CheckIfUserIsActive checks if a user with a specific id is active.
	//
	// Returns true if the user is active.
	// Returns error if there was a database error.
	CheckIfUserIsActive(ctx context.Context, id uuid.UUID) (bool, error)

	// UpdateUserEmail updates the email of a specific user by id.
	//
	// Returns true if the emails was updated.
	// Returns error if the update failed.
	UpdateUserEmail(ctx context.Context, id uuid.UUID, newEmail string) (bool, error)

	// UpdateUserUsername updates the username of a specific user by id.
	//
	// Returns true if the username was updated.
	// Returns error if the update failed.
	UpdateUserUsername(ctx context.Context, id uuid.UUID, newUsername string) (bool, error)

	// UpdateUserRole updates the role of a specific user by id.
	//
	// Returns true if the role was updated.
	// Returns error if the update failed.
	UpdateUserRole(ctx context.Context, id uuid.UUID, newRole models.UserRole) (bool, error)

	// UpdateUserPassword updates the role of a specific user by id.
	//
	// Returns true if the password was updated.
	// Returns error if the update failed.
	UpdateUserPassword(ctx context.Context, id uuid.UUID, newPassword string) (bool, error)

	// UpdateUserActivationStatus updates the activation status of a specific user by id.
	//
	// Returns true if the status was updated.
	// Returns error if the update failed.
	UpdateUserActivationStatus(ctx context.Context, id uuid.UUID, newStatus bool) (bool, error)
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

func (r *MemoryUserRepository) UpdateUserEmail(_ context.Context, id uuid.UUID, newEmail string) (bool, error) {
	indexToUpdate := -1
	for i, u := range r.users {
		if u.Id == id {
			indexToUpdate = i
			break
		}
	}

	if indexToUpdate == -1 {
		return false, nil
	}

	for i, u := range r.users {
		if u.Email == newEmail && indexToUpdate != i {
			return false, &pq.Error{Code: "23505"}
		}
	}

	r.users[indexToUpdate].Email = newEmail
	return true, nil
}

func (r *MemoryUserRepository) UpdateUserUsername(_ context.Context, id uuid.UUID, newUsername string) (bool, error) {
	indexToUpdate := -1
	for i, u := range r.users {
		if u.Id == id {
			indexToUpdate = i
			break
		}
	}

	if indexToUpdate == -1 {
		return false, nil
	}

	for i, u := range r.users {
		if u.Username == newUsername && indexToUpdate != i {
			return false, &pq.Error{Code: "23505"}
		}
	}

	r.users[indexToUpdate].Username = newUsername
	return true, nil
}

func (r *MemoryUserRepository) UpdateUserRole(_ context.Context, id uuid.UUID, newRole models.UserRole) (bool, error) {
	for _, u := range r.users {
		if u.Id == id {
			u.Role = newRole
			return true, nil
		}
	}

	return false, nil
}

func (r *MemoryUserRepository) UpdateUserPassword(_ context.Context, id uuid.UUID, newPassword string) (bool, error) {
	for _, u := range r.users {
		if u.Id == id {
			u.Password = newPassword
			return true, nil
		}
	}
	return false, nil
}

func (r *MemoryUserRepository) UpdateUserActivationStatus(_ context.Context, id uuid.UUID, newStatus bool) (bool, error) {
	for _, u := range r.users {
		if u.Id == id {
			u.Active = newStatus
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

func (r *PostgresUserRepository) UpdateUserEmail(ctx context.Context, id uuid.UUID, newEmail string) (bool, error) {
	result, err := r.db.ExecContext(
		ctx,
		`UPDATE users SET email = $1
             WHERE id = $2`,
		newEmail,
		id)

	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, err
	}

	return rows > 0, nil
}

func (r *PostgresUserRepository) UpdateUserUsername(ctx context.Context, id uuid.UUID, newUsername string) (bool, error) {
	result, err := r.db.ExecContext(
		ctx,
		`UPDATE users SET username = $1
             WHERE id = $2`,
		newUsername,
		id)

	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, err
	}

	return rows > 0, nil
}

func (r *PostgresUserRepository) UpdateUserRole(ctx context.Context, id uuid.UUID, newRole models.UserRole) (bool, error) {
	result, err := r.db.ExecContext(
		ctx,
		`UPDATE users SET user_role = $1
             WHERE id = $2`,
		newRole,
		id)

	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, err
	}

	return rows > 0, nil
}

func (r *PostgresUserRepository) UpdateUserPassword(ctx context.Context, id uuid.UUID, newPassword string) (bool, error) {
	result, err := r.db.ExecContext(
		ctx,
		`UPDATE users SET password = $1
             WHERE id = $2`,
		newPassword,
		id)

	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, err
	}

	return rows > 0, nil
}

func (r *PostgresUserRepository) UpdateUserActivationStatus(ctx context.Context, id uuid.UUID, newStatus bool) (bool, error) {
	result, err := r.db.ExecContext(
		ctx,
		`UPDATE users SET active = $1
             WHERE id = $2`,
		newStatus,
		id)

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
