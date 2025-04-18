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
}

// DefaultUserService is a default implementation of UserService.
type DefaultUserService struct {
	repo          repositories.UserRepository
	authenticator *auth.JWTAuthenticator
}

func (s *DefaultUserService) AddClient(ctx context.Context, payload *models.RegisterClientPayload) *utils.APIError {
	if !payload.Validate() {
		return utils.NewAPIError("Invalid User Payload", fiber.StatusBadRequest)
	}

	result, err := s.repo.CheckEmailAndUsername(ctx, payload.Email, payload.Username)
	if result {
		return utils.NewAPIError("User already exists", fiber.StatusConflict)
	}

	hash, err := auth.HashPassword(payload.Password)
	if err != nil {
		return utils.InternalServerAPIError()
	}

	user := models.NewUser(uuid.New(), payload.Email, payload.Username, hash, models.Client)
	err = s.repo.AddUser(ctx, user)
	if err != nil {
		return utils.InternalServerAPIError()
	}

	return nil
}

func (s *DefaultUserService) createTokenGroup(sub, id uuid.UUID, role models.UserType) (*models.TokenGroup, *utils.APIError) {
	accessToken, err := s.authenticator.CreateToken(sub, id, role, auth.AccessToken, time.Now().Add(time.Minute*20))
	if err != nil {
		return nil, utils.NewAPIError(err.Error(), fiber.StatusInternalServerError)
	}
	refreshToken, err := s.authenticator.CreateToken(sub, id, role, auth.RefreshToken, time.Now().Add(time.Hour*24*20))
	if err != nil {
		return nil, utils.NewAPIError(err.Error(), fiber.StatusInternalServerError)
	}

	return models.NewTokenGroup(refreshToken, accessToken), nil
}

func (s *DefaultUserService) Login(ctx context.Context, payload *models.LoginUserPayload) (*models.TokenGroup, *utils.APIError) {
	fetchedUser, err := s.repo.GetUserByUsername(ctx, payload.Username)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, utils.NewAPIError("Wrong credentials", fiber.StatusUnauthorized)
	case err != nil:
		return nil, utils.InternalServerAPIError()
	}

	if !auth.VerifyPassword(payload.Password, fetchedUser.Password) {
		return nil, utils.NewAPIError("Wrong credentials", fiber.StatusUnauthorized)
	}

	tokenId := uuid.New()
	return s.createTokenGroup(fetchedUser.Id, tokenId, fetchedUser.UserType)
}

// NewDefaultUserService return new instance of UserService.
func NewDefaultUserService(repo repositories.UserRepository, authenticator *auth.JWTAuthenticator) UserService {
	return &DefaultUserService{repo, authenticator}
}
