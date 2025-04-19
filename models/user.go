package models

import (
	"github.com/google/uuid"
	"net/mail"
	"strings"
	"unicode"
)

// RegisterClientPayload used by clients on registration.
type RegisterClientPayload struct {
	Email    string `json:"email"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// Validate will check if the payload of the client is valid.
func (payload *RegisterClientPayload) Validate() bool {
	if !payload.validateEmail() {
		return false
	}

	if len(payload.Username) < 8 {
		return false
	}

	if !payload.validatePassword() {
		return false
	}

	return true
}

func (payload *RegisterClientPayload) validateEmail() bool {
	addr, err := mail.ParseAddress(payload.Email)
	if err != nil {
		return false
	}

	parts := strings.Split(addr.Address, "@")
	if len(parts) != 2 {
		return false
	}

	local, domain := parts[0], parts[1]

	if local == "" || domain == "" {
		return false
	}

	if !strings.Contains(domain, ".") {
		return false
	}

	tldParts := strings.Split(domain, ".")
	tld := tldParts[len(tldParts)-1]
	if len(tld) < 2 {
		return false
	}

	return true
}

func (payload *RegisterClientPayload) validatePassword() bool {
	var (
		// Size is more than 8
		minSize = false
		// Contains upper char
		upper = false
		// Contains lower char
		lower = false
		// Contain number
		number = false
		// Contains special char
		special = false
	)

	if len(payload.Password) > 8 {
		minSize = true
	}

	for _, c := range payload.Password {
		switch {
		case unicode.IsUpper(c):
			upper = true
		case unicode.IsLower(c):
			lower = true
		case unicode.IsNumber(c):
			number = true
		case unicode.IsPunct(c) || unicode.IsSymbol(c):
			special = true
		}
	}

	return minSize && upper && lower && number && special
}

// RegisterUserPayload extends RegisterClientPayload by providing UserRole.
//
// The payload is used by an admin to register workers or in some cases clients.
type RegisterUserPayload struct {
	RegisterClientPayload
	UserType UserRole `json:"user_type"`
}

func (payload *RegisterUserPayload) Validate() bool {
	if !payload.validateEmail() {
		return false
	}

	if len(payload.UserType) < 8 {
		return false
	}

	if !payload.validatePassword() {
		return false
	}

	if payload.UserType != Admin && payload.UserType != Client && payload.UserType != Delivery && payload.UserType != Workshop {
		return false
	}

	return true
}

// NewRegisterClientPayload creates a new instance of RegisterClientPayload
func NewRegisterClientPayload(email string, username string, password string) *RegisterClientPayload {
	return &RegisterClientPayload{
		Email:    email,
		Username: username,
		Password: password,
	}
}

// LoginUserPayload used by user on login.
type LoginUserPayload struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// UserRole used to set the type of users
type UserRole = string

const (
	Admin    UserRole = "admin"
	Client   UserRole = "client"
	Delivery UserRole = "delivery"
	Workshop UserRole = "workshop"
)

// User holds registered used data.
type User struct {
	Id       uuid.UUID
	Email    string
	Username string
	Password string
	UserType UserRole
}

// NewUser create new instance of User
func NewUser(id uuid.UUID, email string, username string, password string, userType UserRole) *User {
	return &User{
		Id:       id,
		Email:    email,
		Username: username,
		Password: password,
		UserType: userType,
	}
}
