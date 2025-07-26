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

	// GetUserByEmail fetches a user's information by their username address.
	//
	// Return the models.UserInfo if the user was found or utils.APIError if any error occurred.
	GetUserByEmail(ctx context.Context, email string) (*models.UserInfo, *utils.APIError)

	// GetUserByUsername fetches a user's information by their username address.
	//
	// Return the models.UserInfo if the user was found or utils.APIError if any error occurred.
	GetUserByUsername(ctx context.Context, username string) (*models.UserInfo, *utils.APIError)

	// DeleteUser used to delete a user by a specific id.
	//
	// Return utils.APIError if the user was not found or if any error occurred.
	DeleteUser(ctx context.Context, id uuid.UUID) *utils.APIError

	// ForceLogoutUser removes all refresh tokens that are linked to a specific user.
	//
	// Returns utils.APIError if the none tokens are found, or if any error occurred.
	ForceLogoutUser(ctx context.Context, id uuid.UUID) *utils.APIError

	// UpdateUserEmail updates the username of a user by the id.
	//
	// Returns utils.APIError if the username is already in use or the updating fails.
	UpdateUserEmail(ctx context.Context, id uuid.UUID, newEmail string) *utils.APIError

	// UpdateUserUsername updates the username of a user by the id.
	//
	// Returns utils.APIError if the username is already in use or the updating fails.
	UpdateUserUsername(ctx context.Context, id uuid.UUID, newUsername string) *utils.APIError

	// UpdateUserRole updates the role of a user by the id.
	//
	// Returns utils.APIError if the updating fails.
	UpdateUserRole(ctx context.Context, id uuid.UUID, newRole models.UserRole) *utils.APIError

	// UpdateUserPassword updates the password of a user by the id.
	//
	// Returns utils.APIError if the updating fails.
	UpdateUserPassword(ctx context.Context, id uuid.UUID, newPassword string) *utils.APIError

	// UpdateUserActivationStatus updates the activation status of a user by the id.
	//
	// Returns utils.APIError if the updating fails.
	UpdateUserActivationStatus(ctx context.Context, id uuid.UUID, newStatus bool) *utils.APIError

	// ChangeUserEmail updates the username of a user by the provided credentials.
	//
	// Returns utils.APIError if the credentials are incorrect or updating fails.
	ChangeUserEmail(ctx context.Context, payload *models.LoginUserPayload, newEmail string) *utils.APIError

	// ChangeUserUsername updates the username of a user by the provided credentials.
	//
	// Returns utils.APIError if the credentials are incorrect or updating fails.
	ChangeUserUsername(ctx context.Context, payload *models.LoginUserPayload, newUsername string) *utils.APIError

	// ChangeUserPassword updates the password of a user by the provided credentials.
	//
	// Returns utils.APIError if the credentials are incorrect or updating fails.
	ChangeUserPassword(ctx context.Context, payload *models.LoginUserPayload, newPassword string) *utils.APIError
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
			return utils.NewAPIError("User username or password are already in use.", fiber.StatusConflict)
		} else if !ok {
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
			return utils.NewAPIError("User username or password are already in use.", fiber.StatusConflict)
		} else if !ok {
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

func (s *DefaultUserService) validateUserLoginPayload(ctx context.Context, payload *models.LoginUserPayload) (*models.User, *utils.APIError) {
	fetchedUser, err := s.userRepository.GetUserByUsername(ctx, payload.Username)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, utils.WrongCredentialsAPIError()
	case err != nil:
		return nil, utils.InternalServerAPIError()
	}

	if !fetchedUser.Active {
		return nil, utils.NewAPIError("User is not active.", fiber.StatusForbidden)
	}

	if !auth.VerifyPassword(payload.Password, fetchedUser.Password) {
		return nil, utils.WrongCredentialsAPIError()
	}

	return fetchedUser, nil
}

func (s *DefaultUserService) Login(ctx context.Context, payload *models.LoginUserPayload) (*models.TokenGroup, *utils.APIError) {
	fetchedUser, apiError := s.validateUserLoginPayload(ctx, payload)
	if apiError != nil {
		return nil, apiError
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
		return nil, utils.UserNotFoundAPIError()
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
		return nil, utils.UserNotFoundAPIError()
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
		return nil, utils.UserNotFoundAPIError()
	case err != nil:
		return nil, utils.InternalServerAPIError()
	default:
		return models.NewUserInfo(result.Id, result.Email, result.Username, result.Role, result.Active), nil
	}
}

func (s *DefaultUserService) DeleteUser(ctx context.Context, id uuid.UUID) *utils.APIError {
	result, err := s.userRepository.DeleteUser(ctx, id)
	if err != nil {
		return utils.InternalServerAPIError()
	}
	if !result {
		return utils.UserNotFoundAPIError()
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

func (s *DefaultUserService) UpdateUserEmail(ctx context.Context, id uuid.UUID, newEmail string) *utils.APIError {
	result, err := s.userRepository.UpdateUserEmail(ctx, id, newEmail)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			return utils.NewAPIError("NewEmail already in use.", fiber.StatusConflict)
		} else {
			return utils.InternalServerAPIError()
		}
	}

	if !result {
		return utils.UserNotFoundAPIError()
	}
	return nil
}

func (s *DefaultUserService) UpdateUserUsername(ctx context.Context, id uuid.UUID, newUsername string) *utils.APIError {
	result, err := s.userRepository.UpdateUserUsername(ctx, id, newUsername)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			return utils.NewAPIError("NewUsername already in use.", fiber.StatusConflict)
		} else {
			return utils.InternalServerAPIError()
		}
	}

	if !result {
		return utils.UserNotFoundAPIError()
	}
	return nil
}

func (s *DefaultUserService) UpdateUserRole(ctx context.Context, id uuid.UUID, newRole models.UserRole) *utils.APIError {
	result, err := s.userRepository.UpdateUserRole(ctx, id, newRole)
	if err != nil {
		return utils.InternalServerAPIError()
	}
	if !result {
		return utils.UserNotFoundAPIError()
	}
	return nil
}

func (s *DefaultUserService) UpdateUserPassword(ctx context.Context, id uuid.UUID, newPassword string) *utils.APIError {
	hash, err := auth.HashPassword(newPassword)
	if err != nil {
		return utils.InternalServerAPIError()
	}
	result, err := s.userRepository.UpdateUserPassword(ctx, id, hash)
	if err != nil {
		return utils.InternalServerAPIError()
	}
	if !result {
		return utils.UserNotFoundAPIError()
	}

	return nil
}

func (s *DefaultUserService) UpdateUserActivationStatus(ctx context.Context, id uuid.UUID, newStatus bool) *utils.APIError {
	result, err := s.userRepository.UpdateUserActivationStatus(ctx, id, newStatus)
	if err != nil {
		return utils.InternalServerAPIError()
	}
	if !result {
		return utils.UserNotFoundAPIError()
	}
	return nil
}

func (s *DefaultUserService) ChangeUserEmail(ctx context.Context, payload *models.LoginUserPayload, newEmail string) *utils.APIError {
	fetchedUser, apiErr := s.validateUserLoginPayload(ctx, payload)
	if apiErr != nil {
		return apiErr
	}

	result, err := s.userRepository.UpdateUserEmail(ctx, fetchedUser.Id, newEmail)
	var pqErr *pq.Error
	if errors.As(err, &pqErr) && pqErr.Code == "23505" {
		return utils.NewAPIError("NewEmail already in use.", fiber.StatusConflict)
	} else if err != nil || !result {
		return utils.InternalServerAPIError()
	}

	return nil
}

func (s *DefaultUserService) ChangeUserUsername(ctx context.Context, payload *models.LoginUserPayload, newUsername string) *utils.APIError {
	fetchedUser, apiErr := s.validateUserLoginPayload(ctx, payload)
	if apiErr != nil {
		return apiErr
	}

	result, err := s.userRepository.UpdateUserUsername(ctx, fetchedUser.Id, newUsername)
	var pqErr *pq.Error
	if errors.As(err, &pqErr) && pqErr.Code == "23505" {
		return utils.NewAPIError("NewUsername already in use.", fiber.StatusConflict)
	} else if err != nil || !result {
		return utils.InternalServerAPIError()
	}

	return nil
}

func (s *DefaultUserService) ChangeUserPassword(ctx context.Context, payload *models.LoginUserPayload, newPassword string) *utils.APIError {
	hash, err := auth.HashPassword(newPassword)
	if err != nil {
		return utils.InternalServerAPIError()
	}

	fetchedUser, apiErr := s.validateUserLoginPayload(ctx, payload)
	if apiErr != nil {
		return apiErr
	}

	result, err := s.userRepository.UpdateUserPassword(ctx, fetchedUser.Id, hash)
	if err != nil || !result {
		return utils.InternalServerAPIError()
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
