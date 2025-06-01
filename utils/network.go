package utils

import (
	"api/models"
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/gofiber/fiber/v2"
	"net/http"
	"net/http/httptest"
)

// SendRegisterRequest sends an HTTP POST request to the "/register" endpoint with a valid registration payload.
//
// This function registers the provided handler with the fiber app and verifies the response meets expectations.
// Returns an error if marshaling the payload, making the request, or verifying the response fails.
func SendRegisterRequest(app *fiber.App, registerHandler fiber.Handler) error {
	data, err := json.Marshal(ValidRegisterClientPayload())
	if err != nil {
		return fmt.Errorf("failed to marshal register client payload: %v", err)
	}

	app.Post("/register", registerHandler)
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")

	res, err := app.Test(req, -1)
	if err != nil {
		return fmt.Errorf("request failed: %v", err)
	}
	if res.StatusCode != http.StatusCreated {
		return fmt.Errorf("invalid response code: %v expected 201", res.StatusCode)
	}

	return nil
}

// SendLoginRequest sends an HTTP POST request to the "/login" endpoint with a valid login payload.
//
// This function registers the provided handler with the fiber app and verifies the response meets expectations.
// Returns an error if marshaling the payload, making the request, or verifying the response fails.
func SendLoginRequest(app *fiber.App, loginHandler fiber.Handler) (*models.TokenGroup, error) {
	data, err := json.Marshal(ValidLoginUserPayload())
	if err != nil {
		return nil, fmt.Errorf("failed to marshal login user payload: %v", err)
	}

	app.Post("/login", loginHandler)
	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	res, err := app.Test(req, -1)
	if err != nil {
		return nil, fmt.Errorf("request failed: %v", err)
	}

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("invalid response code: %v expected 200", res.StatusCode)
	}

	var tokens models.TokenGroup
	err = json.NewDecoder(res.Body).Decode(&tokens)
	if err != nil {
		return nil, err
	}
	return &tokens, nil
}
