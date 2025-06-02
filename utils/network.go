package utils

import (
	"api/models"
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/gofiber/fiber/v2"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// SendRequest sends an HTTP request to the specified path using the given method, token, and body.
//
// Returns the HTTP response and an error if any occurred during request creation or execution.
// If the body is nil, the request reader is set to nil and the `Content-Type` header will not be set.
func SendRequest(app *fiber.App, method, path, token string, body any) (*http.Response, error) {
	var reader io.Reader = nil
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("error marshaling request body: %w", err)
		}
		reader = bytes.NewReader(data)
	}

	req := httptest.NewRequest(method, path, reader)
	if reader != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	return app.Test(req, -1)
}

// SendRequestTest is a unit test helper function that sends an HTTP
// request to the provided path with the provided method, token and body.
//
// Uses SendRequest internally.
func SendRequestTest(t *testing.T, app *fiber.App, method, path, token string, body any) *http.Response {
	t.Helper()

	res, err := SendRequest(app, method, path, token, body)
	if err != nil {
		t.Fatalf("Error sending request: %v", err)
	}
	return res
}

// SendRequestBenchmark is a benchmark test helper function that sends an HTTP
// request to the provided path with the provided method, token and body.
//
// Uses SendRequest internally.
func SendRequestBenchmark(b *testing.B, app *fiber.App, method, path, token string, body any) *http.Response {
	res, err := SendRequest(app, method, path, token, body)
	if err != nil {
		b.Fatalf("Error sending request: %v", err)
	}
	return res
}

// SendLoginAsClientTest is a unit test helper function that sends a login request as a client.
//
// Uses SendRequest internally.
func SendLoginAsClientTest(t *testing.T, app *fiber.App, path string) *models.TokenGroup {
	t.Helper()

	res, err := SendRequest(app, "POST", path, "", ValidLoginClintPayload())
	if err != nil {
		t.Fatalf("Error sending request: %v", err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("Expected status code %v, got %v", http.StatusOK, res.StatusCode)
	}

	var tokenGroup models.TokenGroup
	err = json.NewDecoder(res.Body).Decode(&tokenGroup)
	if err != nil {
		t.Fatalf("Error decoding response body: %v", err)
	}
	return &tokenGroup
}

// SendLoginAsClientBenchmark is a benchmark helper function that sends a login request as a client.
//
// Uses SendRequest internally.
func SendLoginAsClientBenchmark(b *testing.B, app *fiber.App, path string) *models.TokenGroup {
	res, err := SendRequest(app, "POST", path, "", ValidLoginClintPayload())
	if err != nil {
		b.Fatalf("Error sending request: %v", err)
	}
	if res.StatusCode != http.StatusOK {
		b.Fatalf("Expected status code %v, got %v", http.StatusOK, res.StatusCode)
	}

	var tokenGroup models.TokenGroup
	err = json.NewDecoder(res.Body).Decode(&tokenGroup)
	if err != nil {
		b.Fatalf("Error decoding response body: %v", err)
	}
	return &tokenGroup
}

// SendLoginAsClientFuzz is a fuzz helper function that sends a login request as a client.
//
// Uses SendRequest internally.
func SendLoginAsClientFuzz(f *testing.F, app *fiber.App, path string) *models.TokenGroup {
	res, err := SendRequest(app, "POST", path, "", ValidLoginClintPayload())
	if err != nil {
		f.Fatalf("Error sending request: %v", err)
	}
	if res.StatusCode != http.StatusOK {
		f.Fatalf("Expected status code %v, got %v", http.StatusOK, res.StatusCode)
	}

	var tokenGroup models.TokenGroup
	err = json.NewDecoder(res.Body).Decode(&tokenGroup)
	if err != nil {
		f.Fatalf("Error decoding response body: %v", err)
	}
	return &tokenGroup
}

// SendLoginAsAdminTest is a unit test helper function that sends a login request as an admin.
//
// Uses SendRequest internally.
func SendLoginAsAdminTest(t *testing.T, app *fiber.App, path string) *models.TokenGroup {
	t.Helper()

	res, err := SendRequest(app, "POST", path, "", ValidAdminLoginPayload())
	if err != nil {
		t.Fatalf("Error sending request: %v", err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("Expected status code %v, got %v", http.StatusOK, res.StatusCode)
	}

	var tokenGroup models.TokenGroup
	err = json.NewDecoder(res.Body).Decode(&tokenGroup)
	if err != nil {
		t.Fatalf("Error decoding response body: %v", err)
	}
	return &tokenGroup
}

// SendLoginAsAdminBenchmark is a benchmark helper function that sends a login request as an admin.
//
// Uses SendRequest internally.
func SendLoginAsAdminBenchmark(b *testing.B, app *fiber.App, path string) *models.TokenGroup {
	res, err := SendRequest(app, "POST", path, "", ValidAdminLoginPayload())
	if err != nil {
		b.Fatalf("Error sending request: %v", err)
	}
	if res.StatusCode != http.StatusOK {
		b.Fatalf("Expected status code %v, got %v", http.StatusOK, res.StatusCode)
	}

	var tokenGroup models.TokenGroup
	err = json.NewDecoder(res.Body).Decode(&tokenGroup)
	if err != nil {
		b.Fatalf("Error decoding response body: %v", err)
	}
	return &tokenGroup
}

// SendLoginAsAdminFuzz is a fuzz helper function that sends a login request as an admin.
//
// Uses SendRequest internally.
func SendLoginAsAdminFuzz(f *testing.F, app *fiber.App, path string) *models.TokenGroup {
	f.Helper()

	res, err := SendRequest(app, "POST", path, "", ValidAdminLoginPayload())
	if err != nil {
		f.Fatalf("Error sending request: %v", err)
	}
	if res.StatusCode != http.StatusOK {
		f.Fatalf("Expected status code %v, got %v", http.StatusOK, res.StatusCode)
	}

	var tokenGroup models.TokenGroup
	err = json.NewDecoder(res.Body).Decode(&tokenGroup)
	if err != nil {
		f.Fatalf("Error decoding response body: %v", err)
	}
	return &tokenGroup
}
