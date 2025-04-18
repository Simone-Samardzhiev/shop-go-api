package services

import (
	"api/auth"
	"api/models"
	"api/repositories"
	"api/utils"
	"context"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

// UserService defines method used to manage user business logic
type UserService interface {
	// AddUser used to save the user.
	//
	// Return utils.APIError if error appears otherwise nil
	AddUser(ctx context.Context, payload models.RegisterClientPayload) *utils.APIError
}

type DefaultUserService struct {
	repo repositories.UserRepository
}

func (s *DefaultUserService) AddUser(ctx context.Context, payload models.RegisterClientPayload) *utils.APIError {
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
