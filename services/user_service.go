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

// UserService defines method used to manage user business logic
type UserService interface {
	// AddClient used to save the user.
	//
	// Return utils.APIError if error appears otherwise nil
	AddClient(ctx context.Context, payload *models.RegisterClientPayload) *utils.APIError

	// Login used to check login user by returning refresh and access token.
	//
	// The credentials are checked, and if the tokens are successfully created, they are returned.
	// Otherwise, a utils.APIError is returned.
	Login(ctx context.Context, payload *models.LoginUserPayload) (*models.TokenGroup, *utils.APIError)

	// AddUser used to save the user.
	//
	// Return utils.APIError if error appears otherwise nil
	AddUser(ctx context.Context, payload *models.RegisterUserPayload) *utils.APIError

	// RefreshSession used to refresh user token by refresh token.
	// If the refresh token is valid, the result is models.TokenGroup, otherwise
	// a utils.APIError is returned.
	RefreshSession(ctx context.Context, claims *auth.Claims) (*models.TokenGroup, *utils.APIError)
}

// DefaultUserService is a default implementation of UserService.
type DefaultUserService struct {
	userRepository  repositories.UserRepository
	tokenRepository repositories.TokenRepository
	authenticator   *auth.JWTAuthenticator
}

func (s *DefaultUserService) AddClient(ctx context.Context, payload *models.RegisterClientPayload) *utils.APIError {
	if !payload.Validate() {
		return utils.NewAPIError("Invalid User Payload", fiber.StatusBadRequest)
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
	if !payload.Validate() {
		return utils.NewAPIError("Invalid User Payload", fiber.StatusBadRequest)
	}

	result, err := s.userRepository.CheckEmailAndUsername(ctx, payload.Email, payload.Username)
	if result {
		return utils.NewAPIError("User already exists", fiber.StatusConflict)
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
		return nil, utils.NewAPIError("Wrong credentials", fiber.StatusUnauthorized)
	case err != nil:
		return nil, utils.InternalServerAPIError()
	}

	if !auth.VerifyPassword(payload.Password, fetchedUser.Password) {
		return nil, utils.NewAPIError("Wrong credentials", fiber.StatusUnauthorized)
	}

	return s.createTokenGroup(ctx, fetchedUser.Id, fetchedUser.UserRole)
}

func (s *DefaultUserService) RefreshSession(ctx context.Context, claims *auth.Claims) (*models.TokenGroup, *utils.APIError) {
	id, err := uuid.Parse(claims.ID)
	if err != nil {
		return nil, utils.NewAPIError("Invalid token id", fiber.StatusUnauthorized)
	}
	result, err := s.tokenRepository.DeleteToken(ctx, id)
	if err != nil {
		return nil, utils.InternalServerAPIError()
	}
	if !result {
		return nil, utils.NewAPIError("Invalid token", fiber.StatusUnauthorized)
	}

	sub, err := uuid.Parse(claims.Subject)
	if err != nil {
		return nil, utils.NewAPIError("Invalid token subject", fiber.StatusUnauthorized)
	}
	return s.createTokenGroup(ctx, sub, claims.Role)
}

// NewDefaultUserService return new instance of UserService.
func NewDefaultUserService(userRepository repositories.UserRepository, tokenRepository repositories.TokenRepository, authenticator *auth.JWTAuthenticator) *DefaultUserService {
	return &DefaultUserService{
		userRepository:  userRepository,
		tokenRepository: tokenRepository,
		authenticator:   authenticator,
	}
}
