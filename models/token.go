package models

import (
	"github.com/google/uuid"
	"time"
)

// Token stores token data.
type Token struct {
	Id        uuid.UUID
	ExpiresAt time.Time
	UserId    uuid.UUID
}

// NewToken returns a new instance of Token
func NewToken(id, userId uuid.UUID, exp time.Time) *Token {
	return &Token{
		Id:        id,
		ExpiresAt: exp,
		UserId:    userId,
	}
}
