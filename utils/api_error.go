package utils

import (
	"github.com/gofiber/fiber/v2"
)

// APIError is the standard way of returning an error.
type APIError struct {
	Message string
	Status  int
}

// NewAPIError return instance of APIError
func NewAPIError(msg string, status int) *APIError {
	return &APIError{msg, status}
}

// InternalServerAPIError is the standard way of return a server error
func InternalServerAPIError() *APIError {
	return &APIError{"Internal Server Error", fiber.StatusInternalServerError}
}
