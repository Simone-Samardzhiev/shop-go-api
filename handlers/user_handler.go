package handlers

import (
	"api/auth"
	"api/models"
	"api/services"
	"api/utils"
	"github.com/gofiber/fiber/v2"
	"strconv"
)

// UserHandler defines methods that return handler related ot users.
type UserHandler interface {
	// RegisterClient returns handler used by clients to register
	RegisterClient() fiber.Handler

	// RegisterUser handler used by admins to add a new user.
	RegisterUser() fiber.Handler

	// Login returns a handler used by all users to log in.
	Login() fiber.Handler

	// RefreshSession returns the handler used by all users
	// to refresh their session using the refresh token.
	RefreshSession() fiber.Handler

	// GetUsers returns handler used by admins to see user's information.
	GetUsers() fiber.Handler
}

// DefaultUserHandler is default implementation of UserHandler.
type DefaultUserHandler struct {
	service services.UserService
}

func (h *DefaultUserHandler) RegisterClient() fiber.Handler {
	return func(c *fiber.Ctx) error {
		var payload models.RegisterClientPayload
		err := c.BodyParser(&payload)
		if err != nil {
			return err
		}

		apiError := h.service.AddClient(c.Context(), &payload)
		if apiError != nil {
			return c.Status(apiError.Status).JSON(apiError)
		}

		c.Status(fiber.StatusCreated)
		return nil
	}
}

func (h *DefaultUserHandler) RegisterUser() fiber.Handler {
	return func(c *fiber.Ctx) error {
		claims, ok := c.Locals("user").(*auth.Claims)
		if !ok {
			return c.Status(fiber.StatusInternalServerError).JSON(utils.InternalServerAPIError())
		}

		if claims.Role != models.Admin || claims.TokenType != auth.AccessToken {
			return c.Status(fiber.StatusUnauthorized).JSON(utils.NewAPIError("Invalid role", fiber.StatusUnauthorized))
		}

		var payload models.RegisterUserPayload
		err := c.BodyParser(&payload)
		if err != nil {
			return err
		}

		apiError := h.service.AddUser(c.Context(), &payload)
		if apiError != nil {
			return c.Status(apiError.Status).JSON(apiError)
		}

		c.Status(fiber.StatusCreated)
		return nil
	}
}

func (h *DefaultUserHandler) Login() fiber.Handler {
	return func(c *fiber.Ctx) error {
		var payload models.LoginUserPayload
		err := c.BodyParser(&payload)
		if err != nil {
			return err
		}

		tokens, apiError := h.service.Login(c.Context(), &payload)
		if apiError != nil {
			return c.Status(apiError.Status).JSON(apiError)
		}
		return c.Status(fiber.StatusOK).JSON(tokens)
	}
}

func (h *DefaultUserHandler) RefreshSession() fiber.Handler {
	return func(c *fiber.Ctx) error {
		claims, ok := c.Locals("user").(*auth.Claims)
		if !ok {
			return c.Status(fiber.StatusInternalServerError).JSON(utils.InternalServerAPIError())
		}
		if claims.TokenType != auth.RefreshToken {
			return c.Status(fiber.StatusUnauthorized).JSON(utils.InvalidTokenAPIError())
		}

		tokens, apiError := h.service.RefreshSession(c.Context(), claims)
		if apiError != nil {
			return c.Status(apiError.Status).JSON(apiError)
		}
		return c.Status(fiber.StatusOK).JSON(tokens)
	}
}

func (h *DefaultUserHandler) GetUsers() fiber.Handler {
	return func(c *fiber.Ctx) error {
		claims, ok := c.Locals("user").(*auth.Claims)
		if !ok {
			return c.Status(fiber.StatusInternalServerError).JSON(utils.InternalServerAPIError())
		}
		if claims.Role != models.Admin || claims.TokenType != auth.AccessToken {
			return c.Status(fiber.StatusUnauthorized).JSON(utils.InvalidTokenAPIError())
		}

		limit := c.Query("limit")
		parsedLimit, err := strconv.Atoi(limit)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(utils.NewAPIError("Invalid limit", fiber.StatusBadGateway))
		}

		if parsedLimit > 100 {
			parsedLimit = 100
		}

		page := c.Query("page")
		parsedPage, err := strconv.Atoi(page)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(utils.NewAPIError("Invalid page", fiber.StatusBadRequest))
		}
		if parsedPage < 1 {
			parsedPage = 1
		}

		role := c.Query("role")
		var parsedRole *models.UserRole
		if role == "" {
			parsedRole = nil
		} else if !models.RolesMap[role] {
			return c.Status(fiber.StatusBadRequest).JSON(utils.NewAPIError("Invalid role", fiber.StatusBadRequest))
		}

		result, apiError := h.service.GetUsers(c.Context(), parsedLimit, parsedPage, parsedRole)
		if apiError != nil {
			return c.Status(apiError.Status).JSON(apiError)
		}

		return c.Status(fiber.StatusOK).JSON(result)
	}
}

// NewDefaultUserHandler return new instance of DefaultUserHandler.
func NewDefaultUserHandler(service services.UserService) *DefaultUserHandler {
	return &DefaultUserHandler{
		service: service,
	}
}
