package handlers

import (
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"shop/cmd/api/internal/auth"
	"shop/cmd/api/internal/models"
	"shop/cmd/api/internal/services"
	"shop/cmd/api/internal/utils"
	"shop/cmd/api/internal/validate"
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

	// GetUserById returns a handler used by admins to retrieve a user's information by their id.
	GetUserById() fiber.Handler

	// GetUserByEmail returns a handler used by admins to retrieve a user's information by their email address.
	GetUserByEmail() fiber.Handler

	// GetUserByUsername returns a handler used by admins to retrieve a user's information by their username address.
	GetUserByUsername() fiber.Handler

	// DeleteUser returns a handler used by admins to delete user data.
	DeleteUser() fiber.Handler

	// ForceLogoutUser returns a handler used by admins to forcibly logout user
	// by removing all refresh tokens linked to the user.
	ForceLogoutUser() fiber.Handler

	// UpdateUserEmail returns a handler used by admins to change the email of a user.
	UpdateUserEmail() fiber.Handler

	// UpdateUserUsername returns a handler used by admins to change the username of a user.
	UpdateUserUsername() fiber.Handler

	// UpdateUserRole returns a handler used by admins to change the role of a user.
	UpdateUserRole() fiber.Handler

	// UpdateUserPassword returns a handler used by admins to change the password of a user.
	UpdateUserPassword() fiber.Handler

	// UpdateUserActivationStatus returns a handler used by admins to change the activation status of a user.
	UpdateUserActivationStatus() fiber.Handler

	// ChangeEmail used by users to change their email.
	ChangeEmail() fiber.Handler

	// ChangeUsername used by users to change their username.
	ChangeUsername() fiber.Handler

	// ChangePassword used by users to change their password.
	ChangePassword() fiber.Handler
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

func (h *DefaultUserHandler) GetUserByEmail() fiber.Handler {
	return func(c *fiber.Ctx) error {
		claims, ok := c.Locals("user").(*auth.Claims)
		if !ok {
			return c.Status(fiber.StatusInternalServerError).JSON(utils.InternalServerAPIError())
		}
		if claims.Role != models.Admin || claims.TokenType != auth.AccessToken {
			return c.Status(fiber.StatusUnauthorized).JSON(utils.InvalidTokenAPIError())
		}

		email := c.Params("email")
		result, apiError := h.service.GetUserByEmail(c.Context(), email)
		if apiError != nil {
			return c.Status(apiError.Status).JSON(apiError)
		}
		return c.Status(fiber.StatusOK).JSON(result)
	}
}

func (h *DefaultUserHandler) GetUserByUsername() fiber.Handler {
	return func(c *fiber.Ctx) error {
		claims, ok := c.Locals("user").(*auth.Claims)
		if !ok {
			return c.Status(fiber.StatusInternalServerError).JSON(utils.InternalServerAPIError())
		}
		if claims.Role != models.Admin || claims.TokenType != auth.AccessToken {
			return c.Status(fiber.StatusUnauthorized).JSON(utils.InvalidTokenAPIError())
		}

		username := c.Params("username")
		result, apiError := h.service.GetUserByUsername(c.Context(), username)
		if apiError != nil {
			return c.Status(apiError.Status).JSON(apiError)
		}
		return c.Status(fiber.StatusOK).JSON(result)
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

func (h *DefaultUserHandler) UpdateUserEmail() fiber.Handler {
	return func(c *fiber.Ctx) error {
		claims, ok := c.Locals("user").(*auth.Claims)
		if !ok {
			return c.Status(fiber.StatusInternalServerError).JSON(utils.InternalServerAPIError())
		}
		if claims.Role != models.Admin || claims.TokenType != auth.AccessToken {
			return c.Status(fiber.StatusUnauthorized).JSON(utils.InvalidTokenAPIError())
		}

		var payload struct {
			Id    uuid.UUID `json:"id"`
			Email string    `json:"email"`
		}
		err := c.BodyParser(&payload)
		if err != nil {
			return err
		}

		validEmail := validate.Email(payload.Email)
		if !validEmail {
			return c.Status(fiber.StatusBadRequest).JSON(utils.NewAPIError("Invalid email", fiber.StatusBadRequest))
		}
		apiError := h.service.UpdateUserEmail(c.Context(), payload.Id, payload.Email)
		if apiError != nil {
			return c.Status(apiError.Status).JSON(apiError)
		}

		c.Status(fiber.StatusOK)
		return nil
	}
}

func (h *DefaultUserHandler) UpdateUserUsername() fiber.Handler {
	return func(c *fiber.Ctx) error {
		claims, ok := c.Locals("user").(*auth.Claims)
		if !ok {
			return c.Status(fiber.StatusInternalServerError).JSON(utils.InternalServerAPIError())
		}
		if claims.Role != models.Admin || claims.TokenType != auth.AccessToken {
			return c.Status(fiber.StatusUnauthorized).JSON(utils.InvalidTokenAPIError())
		}

		var payload struct {
			Id       uuid.UUID `json:"id"`
			Username string    `json:"username"`
		}
		err := c.BodyParser(&payload)
		if err != nil {
			return err
		}

		validUsername := validate.Username(payload.Username)
		if !validUsername {
			return c.Status(fiber.StatusBadRequest).JSON(utils.NewAPIError("Invalid username", fiber.StatusBadRequest))
		}

		apiError := h.service.UpdateUserUsername(c.Context(), payload.Id, payload.Username)
		if apiError != nil {
			return c.Status(apiError.Status).JSON(apiError)
		}

		c.Status(fiber.StatusOK)
		return nil
	}
}

func (h *DefaultUserHandler) UpdateUserRole() fiber.Handler {
	return func(c *fiber.Ctx) error {
		claims, ok := c.Locals("user").(*auth.Claims)
		if !ok {
			return c.Status(fiber.StatusInternalServerError).JSON(utils.InternalServerAPIError())
		}
		if claims.Role != models.Admin || claims.TokenType != auth.AccessToken {
			return c.Status(fiber.StatusUnauthorized).JSON(utils.InvalidTokenAPIError())
		}

		var payload struct {
			Id   uuid.UUID       `json:"id"`
			Role models.UserRole `json:"role"`
		}
		err := c.BodyParser(&payload)
		if err != nil {
			return err
		}
		if !models.RolesMap[payload.Role] {
			return c.Status(fiber.StatusBadRequest).JSON(utils.NewAPIError("Invalid role", fiber.StatusBadRequest))
		}
		apiError := h.service.UpdateUserRole(c.Context(), payload.Id, payload.Role)
		if apiError != nil {
			return c.Status(apiError.Status).JSON(apiError)
		}

		c.Status(fiber.StatusOK)
		return nil
	}
}

func (h *DefaultUserHandler) UpdateUserPassword() fiber.Handler {
	return func(c *fiber.Ctx) error {
		claims, ok := c.Locals("user").(*auth.Claims)
		if !ok {
			return c.Status(fiber.StatusInternalServerError).JSON(utils.InternalServerAPIError())
		}
		if claims.Role != models.Admin || claims.TokenType != auth.AccessToken {
			return c.Status(fiber.StatusUnauthorized).JSON(utils.InvalidTokenAPIError())
		}

		var payload struct {
			Id       uuid.UUID `json:"id"`
			Password string    `json:"password"`
		}
		err := c.BodyParser(&payload)
		if err != nil {
			return err
		}
		validPassword := validate.Password(payload.Password)
		if !validPassword {
			return c.Status(fiber.StatusBadRequest).JSON(utils.NewAPIError("Invalid password", fiber.StatusBadRequest))
		}

		apiError := h.service.UpdateUserPassword(c.Context(), payload.Id, payload.Password)
		if apiError != nil {
			return c.Status(apiError.Status).JSON(apiError)
		}

		c.Status(fiber.StatusOK)
		return nil
	}
}

func (h *DefaultUserHandler) UpdateUserActivationStatus() fiber.Handler {
	return func(c *fiber.Ctx) error {
		claims, ok := c.Locals("user").(*auth.Claims)
		if !ok {
			return c.Status(fiber.StatusInternalServerError).JSON(utils.InternalServerAPIError())
		}
		if claims.Role != models.Admin || claims.TokenType != auth.AccessToken {
			return c.Status(fiber.StatusUnauthorized).JSON(utils.InvalidTokenAPIError())
		}

		var payload struct {
			Id     uuid.UUID `json:"id"`
			Status bool      `json:"status"`
		}
		err := c.BodyParser(&payload)
		if err != nil {
			return err
		}

		apiError := h.service.UpdateUserActivationStatus(c.Context(), payload.Id, payload.Status)
		if apiError != nil {
			return c.Status(apiError.Status).JSON(apiError)
		}

		c.Status(fiber.StatusOK)
		return nil
	}
}

func (h *DefaultUserHandler) ChangeEmail() fiber.Handler {
	return func(c *fiber.Ctx) error {
		var payload struct {
			NewEmail string `json:"new_email"`
			models.LoginUserPayload
		}

		err := c.BodyParser(&payload)
		if err != nil {
			return err
		}

		if !validate.Email(payload.NewEmail) {
			return c.Status(fiber.StatusBadRequest).JSON(utils.NewAPIError("Invalid email.", fiber.StatusBadRequest))
		}

		apiError := h.service.ChangeUserEmail(c.Context(), &payload.LoginUserPayload, payload.NewEmail)
		if apiError != nil {
			return c.Status(apiError.Status).JSON(apiError)
		}

		c.Status(fiber.StatusOK)
		return nil
	}
}

func (h *DefaultUserHandler) ChangeUsername() fiber.Handler {
	return func(c *fiber.Ctx) error {
		var payload struct {
			NewUsername string `json:"new_username"`
			models.LoginUserPayload
		}

		err := c.BodyParser(&payload)
		if err != nil {
			return err
		}

		if !validate.Username(payload.NewUsername) {
			return c.Status(fiber.StatusBadRequest).JSON(utils.NewAPIError("Invalid username.", fiber.StatusBadRequest))
		}

		apiError := h.service.ChangeUserUsername(c.Context(), &payload.LoginUserPayload, payload.NewUsername)
		if apiError != nil {
			return c.Status(apiError.Status).JSON(apiError)
		}

		c.Status(fiber.StatusOK)
		return nil
	}
}

func (h *DefaultUserHandler) ChangePassword() fiber.Handler {
	return func(c *fiber.Ctx) error {
		var payload struct {
			NewPassword string `json:"new_password"`
			models.LoginUserPayload
		}
		err := c.BodyParser(&payload)
		if err != nil {
			return err
		}

		if !validate.Password(payload.NewPassword) {
			return c.Status(fiber.StatusBadRequest).JSON(utils.NewAPIError("Invalid password.", fiber.StatusBadRequest))
		}

		apiError := h.service.ChangeUserPassword(c.Context(), &payload.LoginUserPayload, payload.NewPassword)
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
