package handlers

import (
	"api/auth"
	"api/models"
	"api/services"
	"api/utils"
	"github.com/gofiber/fiber/v2"
)

// UserHandler defines methods that return handler related ot users.
type UserHandler interface {
	// RegisterClient returns handler used by clients to register
	RegisterClient() fiber.Handler
	// Login returns handler used by all users to log in.
	Login() fiber.Handler
	// RegisterUser handler used by admins to add a new user.
	RegisterUser() fiber.Handler
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

func (h *DefaultUserHandler) RegisterUser() fiber.Handler {
	return func(c *fiber.Ctx) error {
		claims, ok := c.Locals("user").(*auth.Claims)
		if !ok {
			return c.Status(fiber.StatusInternalServerError).JSON(utils.InternalServerAPIError())
		}

		if claims.Role != models.Admin {
			return c.Status(fiber.StatusUnauthorized).JSON(utils.NewAPIError("Invalid role", fiber.StatusUnauthorized))
		}

		var payload *models.RegisterUserPayload
		err := c.BodyParser(&payload)
		if err != nil {
			return err
		}

		apiError := h.service.AddUser(c.Context(), payload)
		if apiError != nil {
			return c.Status(apiError.Status).JSON(apiError)
		}

		c.Status(fiber.StatusCreated)
		return nil
	}
}

// NewDefaultUserHandler return new instance of DefaultUserHandler.
func NewDefaultUserHandler(service services.UserService) *DefaultUserHandler {
	return &DefaultUserHandler{
		service: service,
	}
}
