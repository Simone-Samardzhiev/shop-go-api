package utils

import (
	"github.com/gofiber/fiber/v2"
	"strings"
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

// NewAPIErrorFromError return instance of APIError from error.
//
// The constructor capitalizes the error message and adds punctuation.
func NewAPIErrorFromError(err error, status int) *APIError {
	message := err.Error()
	message = strings.ToUpper(string(message[0])) + message[1:]
	message = message + "."
	return &APIError{message, status}
}

// InternalServerAPIError is the standard way of return a server error.
func InternalServerAPIError() *APIError {
	return NewAPIError("Internal server error.", fiber.StatusInternalServerError)
}

// InvalidTokenAPIError is the standard way of return an invalid token error.
func InvalidTokenAPIError() *APIError {
	return &APIError{"Invalid token.", fiber.StatusUnauthorized}
}

// TooManyRequestsAPIError is the standard way of return in too many request send over time.
func TooManyRequestsAPIError() *APIError {
	return &APIError{"Too many requests.", fiber.StatusTooManyRequests}
}
