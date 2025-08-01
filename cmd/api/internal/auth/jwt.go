package auth

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"shop/cmd/api/internal/config"
	"shop/cmd/api/internal/models"
	"time"
)

// TokenType used to set the type of claims
type TokenType = int

const (
	// RefreshToken used to revalidate tokens.
	RefreshToken TokenType = iota
	// AccessToken used to get access to API.
	AccessToken
)

// Claims is a custom implementation of jwt.Claims
type Claims struct {
	TokenType TokenType       `json:"token_type"`
	Role      models.UserRole `json:"role"`
	jwt.RegisteredClaims
}

// JWTAuthenticator used to create JWT.
type JWTAuthenticator struct {
	conf config.AuthConfig
}

// CreateToken creates a new access token and signs it.
func (a *JWTAuthenticator) CreateToken(sub, id uuid.UUID, role models.UserRole, tokenType TokenType, exp time.Time) (string, error) {
	claims := Claims{
		TokenType: tokenType,
		Role:      role,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    a.conf.Issuer,
			Subject:   sub.String(),
			Audience:  []string{role},
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(exp),
			NotBefore: jwt.NewNumericDate(time.Now()),
			ID:        id.String(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(a.conf.JWTSecret))
	return signedToken, err
}

// NewJWTAuthenticator creates a new instance of JWTAuthenticator
func NewJWTAuthenticator(conf config.AuthConfig) *JWTAuthenticator {
	return &JWTAuthenticator{conf: conf}
}
