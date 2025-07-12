package testutils

import (
	"bytes"
	"encoding/json"
	"github.com/gofiber/fiber/v2"
	"io"
	"net/http"
	"net/http/httptest"
	"shop/cmd/api/internal/models"
)

// SendRequest sends a request to a path with a specific method and JSON body.
//
// If the body is nil, the header Content-Type won't be set to application/json.
func SendRequest(app *fiber.App, path, method, token string, body any) (*http.Response, error) {
	var reader io.Reader

	if body == nil {
		reader = nil
	} else {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(data)
	}

	var req *http.Request
	if reader != nil {
		req = httptest.NewRequest(method, path, reader)
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	return app.Test(req, -1)
}

// LoginAsAdmin send a login request with a valid admin payload in testdata/users.json.
func LoginAsAdmin(app *fiber.App, path string) (*models.TokenGroup, error) {
	res, err := SendRequest(app, path, "POST", "", models.NewLoginUserPayload("john_doe", "Password1!"))
	if err != nil {
		return nil, err
	}

	var tokens models.TokenGroup
	err = json.NewDecoder(res.Body).Decode(&tokens)
	if err != nil {
		return nil, err
	}
	return &tokens, nil
}
