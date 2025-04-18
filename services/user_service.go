package services

import (
	"api/models"
	"api/repositories"
	"api/utils"
	"context"
	"github.com/gofiber/fiber/v2"
)

type UserService interface {
	AddUser(ctx context.Context, payload models.RegisterClientPayload) *utils.APIError
}

type DefaultUserService struct {
	repo repositories.UserRepository
}

func (s *DefaultUserService) AddUser(ctx context.Context, payload models.RegisterClientPayload) *utils.APIError {
	if !payload.Validate() {
		return utils.NewAPIError("Invalid User Payload", fiber.StatusBadRequest)
	}

}
