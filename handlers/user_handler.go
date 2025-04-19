package handlers

import (
	"api/models"
	"api/services"
	"github.com/gofiber/fiber/v2"
)

// UserHandler defines methods that return handler related ot users.
type UserHandler interface {
	// RegisterClient returns handler used by clients to register
	RegisterClient() fiber.Handler
	// Login returns handler used by all users to log in.
	Login() fiber.Handler
}

// DefaultUserHandler is default implementation of UserHandler.
type DefaultUserHandler struct {
	service services.UserService
}

func (h *DefaultUserHandler) RegisterClient() fiber.Handler {
	return func(c *fiber.Ctx) error {
		var payload *models.RegisterClientPayload
		err := c.BodyParser(&payload)
		if err != nil {
			return err
		}

		apiError := h.service.AddClient(c.Context(), payload)
		if apiError != nil {
			return c.Status(apiError.Status).JSON(apiError)
		}

		c.Status(fiber.StatusCreated)
		return nil
	}
}

func (h *DefaultUserHandler) Login() fiber.Handler {
	return func(c *fiber.Ctx) error {
		var payload *models.LoginUserPayload
		err := c.BodyParser(&payload)
		if err != nil {
			return err
		}

		tokens, apiError := h.service.Login(c.Context(), payload)
		if apiError != nil {
			return c.Status(apiError.Status).JSON(apiError)
		}
		return c.Status(fiber.StatusOK).JSON(tokens)
	}
}

// NewDefaultUserHandler return new instance of DefaultUserHandler.
func NewDefaultUserHandler(service services.UserService) *DefaultUserHandler {
	return &DefaultUserHandler{
		service: service,
	}
}
