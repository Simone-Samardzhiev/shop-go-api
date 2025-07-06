package handlers

import (
	"api/auth"
	"api/models"
	"api/services"
	"api/utils"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
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

	// GetUsers returns handler used by admins to see users' information.
	GetUsers() fiber.Handler

	// GetUserById returns handler used by admins to see specific user information.
	GetUserById() fiber.Handler

	// UpdateUser returns handler used by admins to update user data.
	UpdateUser() fiber.Handler

	// DeleteUser returns handle used by admins to delete user data.
	DeleteUser() fiber.Handler

	// ForceLogoutUser returns a handler user by admins to forcibly logout user
	// by removing all refresh tokens linked to the user.
	ForceLogoutUser() fiber.Handler
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

		if parsedLimit < 1 || parsedLimit > 50 {
			parsedLimit = 50
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
		} else {
			copyRole := role
			parsedRole = &copyRole
		}

		result, apiError := h.service.GetUsers(c.Context(), parsedLimit, parsedPage, parsedRole)
		if apiError != nil {
			return c.Status(apiError.Status).JSON(apiError)
		}

		return c.Status(fiber.StatusOK).JSON(result)
	}
}

func (h *DefaultUserHandler) GetUserById() fiber.Handler {
	return func(c *fiber.Ctx) error {
		claims, ok := c.Locals("user").(*auth.Claims)
		if !ok {
			return c.Status(fiber.StatusInternalServerError).JSON(utils.InternalServerAPIError())
		}
		if claims.Role != models.Admin || claims.TokenType != auth.AccessToken {
			return c.Status(fiber.StatusUnauthorized).JSON(utils.InvalidTokenAPIError())
		}

		id, err := uuid.Parse(c.Params("id"))
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(utils.NewAPIError("Invalid id", fiber.StatusBadRequest))
		}

		result, apiError := h.service.GetUserById(c.Context(), id)
		if apiError != nil {
			return c.Status(apiError.Status).JSON(apiError)
		}

		return c.Status(fiber.StatusOK).JSON(result)
	}
}

func (h *DefaultUserHandler) UpdateUser() fiber.Handler {
	return func(c *fiber.Ctx) error {
		claims, ok := c.Locals("user").(*auth.Claims)
		if !ok {
			return c.Status(fiber.StatusInternalServerError).JSON(utils.InternalServerAPIError())
		}
		if claims.Role != models.Admin || claims.TokenType != auth.AccessToken {
			return c.Status(fiber.StatusUnauthorized).JSON(utils.InvalidTokenAPIError())
		}

		var payload models.UpdateUserPayload
		err := c.BodyParser(&payload)
		if err != nil {
			return err
		}

		apiErr := h.service.UpdateUser(c.Context(), &payload)
		if apiErr != nil {
			return c.Status(apiErr.Status).JSON(apiErr)
		}

		c.Status(fiber.StatusOK)
		return nil
	}
}

func (h *DefaultUserHandler) DeleteUser() fiber.Handler {
	return func(c *fiber.Ctx) error {
		claims, ok := c.Locals("user").(*auth.Claims)
		if !ok {
			return c.Status(fiber.StatusInternalServerError).JSON(utils.InternalServerAPIError())
		}
		if claims.Role != models.Admin || claims.TokenType != auth.AccessToken {
			return c.Status(fiber.StatusUnauthorized).JSON(utils.InvalidTokenAPIError())
		}

		stringId := c.Params("id")
		id, err := uuid.Parse(stringId)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(utils.NewAPIError("Invalid id", fiber.StatusBadRequest))
		}

		apiError := h.service.DeleteUser(c.Context(), id)
		if apiError != nil {
			return c.Status(apiError.Status).JSON(apiError)
		}

		c.Status(fiber.StatusOK)
		return nil
	}
}

func (h *DefaultUserHandler) ForceLogoutUser() fiber.Handler {
	return func(c *fiber.Ctx) error {
		claims, ok := c.Locals("user").(*auth.Claims)
		if !ok {
			return c.Status(fiber.StatusInternalServerError).JSON(utils.InternalServerAPIError())
		}
		if claims.Role != models.Admin || claims.TokenType != auth.AccessToken {
			return c.Status(fiber.StatusUnauthorized).JSON(utils.InvalidTokenAPIError())
		}

		id := c.Params("id")
		parsedId, err := uuid.Parse(id)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(utils.NewAPIError("Invalid id", fiber.StatusBadRequest))
		}

		apiError := h.service.ForceLogoutUser(c.Context(), parsedId)
		if apiError != nil {
			return c.Status(apiError.Status).JSON(apiError)
		}

		c.Status(fiber.StatusOK)
		return nil
	}
}

// NewDefaultUserHandler return new instance of DefaultUserHandler.
func NewDefaultUserHandler(service services.UserService) *DefaultUserHandler {
	return &DefaultUserHandler{
		service: service,
	}
}
