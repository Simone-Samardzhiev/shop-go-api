package services

import (
	"context"
	"database/sql"
	"errors"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"shop/cmd/api/internal/auth"
	"shop/cmd/api/internal/models"
	"shop/cmd/api/internal/repositories"
	"shop/cmd/api/internal/utils"
	"time"
)

// UserService defines methods used to manage user business logic
type UserService interface {
	// AddClient used to save the user.
	//
	// Return utils.APIError if an error occurs otherwise nil.
	AddClient(ctx context.Context, payload *models.RegisterClientPayload) *utils.APIError

	// Login used to check login user by returning refresh and access token.
	//
	// The credentials are checked, and if the tokens are successfully created, they are returned.
	// Otherwise, utils.APIError is returned.
	Login(ctx context.Context, payload *models.LoginUserPayload) (*models.TokenGroup, *utils.APIError)

	// AddUser used to save the user.
	//
	// Return utils.APIError if an error occurs otherwise nil.
	AddUser(ctx context.Context, payload *models.RegisterUserPayload) *utils.APIError

	// RefreshSession used to refresh user token by refresh token.
	// If the refresh token is valid, the result is models.TokenGroup, otherwise
	// a utils.APIError is returned.
	RefreshSession(ctx context.Context, claims *auth.Claims) (*models.TokenGroup, *utils.APIError)

	// GetUsers used to get user information by admins.
	//
	// Support pagination with limit and page plus filtering by role that is optional.
	GetUsers(ctx context.Context, limit, page int, role *string) ([]*models.UserInfo, *utils.APIError)

	// GetUserById used to get specific user information by admins.
	//
	// Return the models.UserInfo if the user was found or utils.APIError if any error occurred.
	GetUserById(ctx context.Context, id uuid.UUID) (*models.UserInfo, *utils.APIError)

	// GetUserByEmail fetches a user's information by their email address.
	//
	// Return the models.UserInfo if the user was found or utils.APIError if any error occurred.
	GetUserByEmail(ctx context.Context, email string) (*models.UserInfo, *utils.APIError)

	// GetUserByUsername fetches a user's information by their username address.
	//
	// Return the models.UserInfo if the user was found or utils.APIError if any error occurred.
	GetUserByUsername(ctx context.Context, username string) (*models.UserInfo, *utils.APIError)

	// UpdateUser used to update user data by specific id.
	//
	// Return utils.APIError if the user was not found or if any error occurred.
	UpdateUser(ctx context.Context, user *models.UpdateUserPayload) *utils.APIError

	// DeleteUser used to delete a user by a specific id.
	//
	// Return utils.APIError if the user was not found or if any error occurred.
	DeleteUser(ctx context.Context, id uuid.UUID) *utils.APIError

	// ForceLogoutUser removes all refresh tokens that are linked to a specific user.
	//
	// Returns utils.APIError if the none tokens are found, or if any error occurred.
	ForceLogoutUser(ctx context.Context, id uuid.UUID) *utils.APIError

	// ChangeUserPassword changes the passwords of a user with specified id.
	//
	// Returns utils.APIError if the user was not found, or any error occurred.
	ChangeUserPassword(ctx context.Context, userId uuid.UUID, password string) *utils.APIError
}

// DefaultUserService is a default implementation of UserService.
type DefaultUserService struct {
	userRepository  repositories.UserRepository
	tokenRepository repositories.TokenRepository
	authenticator   *auth.JWTAuthenticator
}

func (s *DefaultUserService) AddClient(ctx context.Context, payload *models.RegisterClientPayload) *utils.APIError {
	if err := payload.Validate(); err != nil {
		return utils.NewAPIErrorFromError(err, fiber.StatusBadRequest)
	}

	hash, err := auth.HashPassword(payload.Password)
	if err != nil {
		return utils.InternalServerAPIError()
	}

	user := models.NewUser(uuid.New(), payload.Email, payload.Username, hash, models.Client)
	if err = s.userRepository.AddUser(ctx, user); err != nil {
		var pqErr *pq.Error
		ok := errors.As(err, &pqErr)
		if ok && pqErr.Code == "23505" {
			return utils.NewAPIError("User email or password are already in use.", fiber.StatusConflict)
		} else if !ok && err != nil {
			return utils.InternalServerAPIError()
		}
	}

	return nil
}

func (s *DefaultUserService) AddUser(ctx context.Context, payload *models.RegisterUserPayload) *utils.APIError {
	if err := payload.Validate(); err != nil {
		return utils.NewAPIErrorFromError(err, fiber.StatusBadRequest)
	}

	hash, err := auth.HashPassword(payload.Password)
	if err != nil {
		return utils.InternalServerAPIError()
	}

	user := models.NewUser(uuid.New(), payload.Email, payload.Username, hash, payload.UserRole)
	if err = s.userRepository.AddUser(ctx, user); err != nil {
		var pqErr *pq.Error
		ok := errors.As(err, &pqErr)
		if ok && pqErr.Code == "23505" {
			return utils.NewAPIError("User email or password are already in use.", fiber.StatusConflict)
		} else if !ok && err != nil {
			return utils.InternalServerAPIError()
		}
	}

	return nil
}

func (s *DefaultUserService) createTokenGroup(ctx context.Context, sub uuid.UUID, role models.UserRole) (*models.TokenGroup, *utils.APIError) {
	token := models.NewToken(uuid.New(), sub, time.Now().Add(time.Hour*24*20))
	if err := s.tokenRepository.AddToken(ctx, token); err != nil {
		return nil, utils.InternalServerAPIError()
	}

	accessToken, err := s.authenticator.CreateToken(sub, uuid.New(), role, auth.AccessToken, time.Now().Add(time.Minute*20))
	if err != nil {
		return nil, utils.InternalServerAPIError()
	}
	refreshToken, err := s.authenticator.CreateToken(sub, token.Id, role, auth.RefreshToken, time.Now().Add(time.Hour*24*20))
	if err != nil {
		return nil, utils.InternalServerAPIError()
	}

	return models.NewTokenGroup(refreshToken, accessToken), nil
}

func (s *DefaultUserService) Login(ctx context.Context, payload *models.LoginUserPayload) (*models.TokenGroup, *utils.APIError) {
	fetchedUser, err := s.userRepository.GetUserByUsername(ctx, payload.Username)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, utils.NewAPIError("Wrong credentials.", fiber.StatusUnauthorized)
	case err != nil:
		return nil, utils.InternalServerAPIError()
	}

	if !auth.VerifyPassword(payload.Password, fetchedUser.Password) {
		return nil, utils.NewAPIError("Wrong credentials.", fiber.StatusUnauthorized)
	}

	if !fetchedUser.Active {
		return nil, utils.NewAPIError("User is not active.", fiber.StatusForbidden)
	}

	return s.createTokenGroup(ctx, fetchedUser.Id, fetchedUser.Role)
}

func (s *DefaultUserService) RefreshSession(ctx context.Context, claims *auth.Claims) (*models.TokenGroup, *utils.APIError) {
	id, err := uuid.Parse(claims.ID)
	if err != nil {
		return nil, utils.NewAPIError("Invalid token id.", fiber.StatusUnauthorized)
	}
	result, err := s.tokenRepository.DeleteToken(ctx, id)
	if err != nil {
		return nil, utils.InternalServerAPIError()
	}
	if !result {
		return nil, utils.NewAPIError("Invalid token.", fiber.StatusUnauthorized)
	}

	sub, err := uuid.Parse(claims.Subject)
	if err != nil {
		return nil, utils.NewAPIError("Invalid token subject.", fiber.StatusUnauthorized)
	}

	isActive, err := s.userRepository.CheckIfUserIsActive(ctx, sub)
	if err != nil {
		return nil, utils.InternalServerAPIError()
	}

	if !isActive {
		return nil, utils.NewAPIError("User is not active.", fiber.StatusForbidden)
	}

	return s.createTokenGroup(ctx, sub, claims.Role)
}

func (s *DefaultUserService) GetUsers(ctx context.Context, limit, page int, role *string) ([]*models.UserInfo, *utils.APIError) {
	var results []*models.UserInfo
	var err error
	if role != nil {
		results, err = s.userRepository.GetUsersByRole(ctx, limit, page, *role)
	} else {
		results, err = s.userRepository.GetUsers(ctx, limit, page)
	}

	if err != nil {
		return nil, utils.InternalServerAPIError()
	}
	return results, nil
}

func (s *DefaultUserService) GetUserById(ctx context.Context, id uuid.UUID) (*models.UserInfo, *utils.APIError) {
	result, err := s.userRepository.GetUserById(ctx, id)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, utils.NewAPIError("User not found.", fiber.StatusNotFound)
	case err != nil:
		return nil, utils.InternalServerAPIError()
	default:
		return result, nil
	}
}

func (s *DefaultUserService) GetUserByEmail(ctx context.Context, email string) (*models.UserInfo, *utils.APIError) {
	result, err := s.userRepository.GetUserByEmail(ctx, email)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, utils.NewAPIError("User not found.", fiber.StatusNotFound)
	case err != nil:
		return nil, utils.InternalServerAPIError()
	default:
		return result, nil
	}
}

func (s *DefaultUserService) GetUserByUsername(ctx context.Context, username string) (*models.UserInfo, *utils.APIError) {
	result, err := s.userRepository.GetUserByUsername(ctx, username)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, utils.NewAPIError("User not found.", fiber.StatusNotFound)
	case err != nil:
		return nil, utils.InternalServerAPIError()
	default:
		return models.NewUserInfo(result.Id, result.Email, result.Username, result.Role, result.Active), nil
	}
}

func (s *DefaultUserService) UpdateUser(ctx context.Context, user *models.UpdateUserPayload) *utils.APIError {
	if err := user.Validate(); err != nil {
		return utils.NewAPIErrorFromError(err, fiber.StatusBadRequest)
	}

	result, err := s.userRepository.UpdateUser(ctx, user)
	var pqErr *pq.Error
	ok := errors.As(err, &pqErr)
	if ok && pqErr.Code == "23505" {
		return utils.NewAPIError("User email or username already in use.", fiber.StatusConflict)
	} else if !ok && err != nil {
		return utils.InternalServerAPIError()
	}
	if !result {
		return utils.NewAPIError("User not found.", fiber.StatusNotFound)
	}

	return nil
}

func (s *DefaultUserService) DeleteUser(ctx context.Context, id uuid.UUID) *utils.APIError {
	result, err := s.userRepository.DeleteUser(ctx, id)
	if err != nil {
		return utils.InternalServerAPIError()
	}
	if !result {
		return utils.NewAPIError("User not found.", fiber.StatusNotFound)
	}

	return nil
}

func (s *DefaultUserService) ForceLogoutUser(ctx context.Context, id uuid.UUID) *utils.APIError {
	result, err := s.tokenRepository.DeleteTokensByUserId(ctx, id)
	if err != nil {
		return utils.InternalServerAPIError()
	}
	if !result {
		return utils.NewAPIError("No tokens founds linked to user.", fiber.StatusNotFound)
	}

	return nil
}

func (s *DefaultUserService) ChangeUserPassword(ctx context.Context, userId uuid.UUID, password string) *utils.APIError {
	hash, err := auth.HashPassword(password)
	if err != nil {
		return utils.InternalServerAPIError()
	}

	result, err := s.userRepository.ChangePassword(ctx, userId, hash)
	if err != nil {
		return utils.InternalServerAPIError()
	}
	if !result {
		return utils.NewAPIError("User not found.", fiber.StatusNotFound)
	}

	return nil
}

// NewDefaultUserService return new instance of UserService.
func NewDefaultUserService(userRepository repositories.UserRepository, tokenRepository repositories.TokenRepository, authenticator *auth.JWTAuthenticator) *DefaultUserService {
	return &DefaultUserService{
		userRepository:  userRepository,
		tokenRepository: tokenRepository,
		authenticator:   authenticator,
	}
}
