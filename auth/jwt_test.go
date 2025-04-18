package auth

import (
	"api/config"
	"api/models"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"testing"
	"time"
)

func TestJWTAuthenticatorCreateToken(t *testing.T) {
	authenticator := &JWTAuthenticator{
		conf: config.AuthConfig{
			JWTSecret: "secret",
			Issuer:    "test",
		},
	}

	sub := uuid.New()
	id := uuid.New()
	role := models.Client
	tokenType := AccessToken
	exp := time.Now().Add(time.Hour)

	token, err := authenticator.CreateToken(sub, id, role, tokenType, exp)
	if err != nil {
		t.Errorf("Error creating token: %v", err)
	}

	parsedToken, err := jwt.ParseWithClaims(token, &Claims{}, func(token *jwt.Token) (any, error) {
		return []byte("secret"), nil
	})
	if err != nil {
		t.Errorf("Error parsing token: %v", err)
	}

	claims, ok := parsedToken.Claims.(*Claims)
	if !ok {
		t.Errorf("Error casting token claims")
	}

	if claims.TokenType != tokenType {
		t.Errorf("Token type mismatch")
	}
	if claims.Issuer != "test" {
		t.Errorf("Issuer mismatch")
	}
	if claims.Subject != sub.String() {
		t.Errorf("Subject mismatch")
	}
	if claims.ID != id.String() {
		t.Errorf("ID mismatch")
	}
}
