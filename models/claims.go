package models

import "github.com/golang-jwt/jwt/v5"

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
	TokenType TokenType `json:"token_type"`
	Role      UserType  `json:"role"`
	jwt.RegisteredClaims
}
