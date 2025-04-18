package utils

// APIError is the standard way of returning an error.
type APIError struct {
	Message string
	Status  int
}

// NewAPIError return instance of APIError
func NewAPIError(msg string, status int) *APIError {
	return &APIError{msg, status}
}
