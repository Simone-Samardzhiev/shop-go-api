package services

import (
	"api/auth"
	"api/models"
	"api/repositories"
	"api/utils"
	"context"
	"database/sql"
	"errors"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
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
	GetUserById(ctx context.Context, id uuid.UUID) (*models.UserInfo, *utils.APIError)

	// UpdateUser used to update user data by specific id.
	UpdateUser(ctx context.Context, user *models.User) *utils.APIError
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

	result, err := s.userRepository.CheckEmailAndUsername(ctx, payload.Email, payload.Username)
	if result {
		return utils.NewAPIError("User already exists", fiber.StatusConflict)
	}

	hash, err := auth.HashPassword(payload.Password)
	if err != nil {
		return utils.InternalServerAPIError()
	}

	user := models.NewUser(uuid.New(), payload.Email, payload.Username, hash, models.Client)
	if err = s.userRepository.AddUser(ctx, user); err != nil {
		return utils.InternalServerAPIError()
	}

	return nil
}

func (s *DefaultUserService) AddUser(ctx context.Context, payload *models.RegisterUserPayload) *utils.APIError {
	if err := payload.Validate(); err != nil {
		return utils.NewAPIErrorFromError(err, fiber.StatusBadRequest)
	}

	result, err := s.userRepository.CheckEmailAndUsername(ctx, payload.Email, payload.Username)
	if result {
		return utils.NewAPIError("User already exists.", fiber.StatusConflict)
	}

	hash, err := auth.HashPassword(payload.Password)
	if err != nil {
		return utils.InternalServerAPIError()
	}

	user := models.NewUser(uuid.New(), payload.Email, payload.Username, hash, payload.UserRole)
	if err = s.userRepository.AddUser(ctx, user); err != nil {
		return utils.InternalServerAPIError()
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
	if errors.Is(err, sql.ErrNoRows) {
		return nil, utils.NewAPIError("User not found.", fiber.StatusNotFound)
	} else if err != nil {
		return nil, utils.InternalServerAPIError()
	} else {
		return result, nil
	}
}

func (s *DefaultUserService) UpdateUser(ctx context.Context, user *models.User) *utils.APIError {
	if err := user.Validate(); err != nil {
		return utils.NewAPIErrorFromError(err, fiber.StatusBadRequest)
	}

	result, err := s.userRepository.CheckEmailAndUsername(ctx, user.Email, user.Username)
	if err != nil {
		return utils.NewAPIErrorFromError(err, fiber.StatusInternalServerError)
	}
	if result {
		return utils.NewAPIError("User email or username already exist.", fiber.StatusConflict)
	}

	result, err = s.userRepository.UpdateUser(ctx, user)
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
