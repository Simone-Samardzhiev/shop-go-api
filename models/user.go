package models

import (
	"api/validate"
	"errors"
	"github.com/google/uuid"
)

// RegisterClientPayload used by clients on registration.
type RegisterClientPayload struct {
	Email    string `json:"email"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// Validate will check if the payload of the client is valid.
func (payload *RegisterClientPayload) Validate() error {
	if ok := validate.Email(payload.Email); !ok {
		return errors.New("invalid email")
	}

	if ok := validate.Password(payload.Password); !ok {
		return errors.New("invalid password")
	}

	if ok := validate.Username(payload.Username); !ok {
		return errors.New("invalid username")
	}

	return nil
}

// NewRegisterClientPayload creates a new instance of RegisterClientPayload
func NewRegisterClientPayload(email string, username string, password string) *RegisterClientPayload {
	return &RegisterClientPayload{
		Email:    email,
		Username: username,
		Password: password,
	}
}

// RegisterUserPayload extends RegisterClientPayload by providing UserRole.
//
// The payload is used by an admin to register workers or in some cases clients.
type RegisterUserPayload struct {
	RegisterClientPayload
	UserRole UserRole `json:"user_role"`
}

func (payload *RegisterUserPayload) Validate() error {
	if err := payload.RegisterClientPayload.Validate(); err != nil {
		return err
	}

	if !RolesMap[payload.UserRole] {
		return errors.New("invalid user role")
	}

	return nil
}

// NewRegisterUserPayload returns a new instance of RegisterUserPayload.
func NewRegisterUserPayload(email string, username string, password string, userRole UserRole) *RegisterUserPayload {
	return &RegisterUserPayload{
		RegisterClientPayload: RegisterClientPayload{
			Email:    email,
			Username: username,
			Password: password,
		},
		UserRole: userRole,
	}
}

// LoginUserPayload used by user on login.
type LoginUserPayload struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// NewLoginUserPayload returns a new instance of LoginUserPayload.
func NewLoginUserPayload(username string, password string) *LoginUserPayload {
	return &LoginUserPayload{
		Username: username,
		Password: password,
	}
}

// UserRole used to set the type of users.
type UserRole = string

const (
	Admin    UserRole = "admin"
	Client   UserRole = "client"
	Delivery UserRole = "delivery"
	Workshop UserRole = "workshop"
)

// RolesMap used to check users role.
var RolesMap = map[UserRole]bool{
	Admin:    true,
	Client:   true,
	Delivery: true,
	Workshop: true,
}

// User holds registered used data.
type User struct {
	Id       uuid.UUID `json:"id"`
	Email    string    `json:"email"`
	Username string    `json:"username"`
	Password string    `json:"password"`
	Active   bool      `json:"active"`
	Role     UserRole  `json:"role"`
}

// NewUser create new instance of User.
func NewUser(id uuid.UUID, email string, username string, password string, role UserRole) *User {
	return &User{
		Id:       id,
		Email:    email,
		Username: username,
		Password: password,
		Role:     role,
	}
}

// UserInfo holds used data without the password,
// used by admins to check user's data.
type UserInfo struct {
	Id       uuid.UUID `json:"id"`
	Email    string    `json:"email"`
	Username string    `json:"username"`
	Role     UserRole  `json:"role"`
	Active   bool      `json:"active"`
}

// NewUserInfo returns a new instance of UserInfo.
func NewUserInfo(id uuid.UUID, email, username string, role UserRole, active bool) *UserInfo {
	return &UserInfo{
		Id:       id,
		Email:    email,
		Username: username,
		Role:     role,
		Active:   active,
	}
}

// UpdateUserPayload used by admins to update user data.
type UpdateUserPayload struct {
	Id       uuid.UUID `json:"id"`
	Email    string    `json:"email"`
	Username string    `json:"username"`
	Active   bool      `json:"active"`
	Role     UserRole  `json:"role"`
}

func (payload *UpdateUserPayload) Validate() error {
	if ok := validate.Email(payload.Email); !ok {
		return errors.New("invalid email")
	}

	if ok := validate.Username(payload.Username); !ok {
		return errors.New("invalid username")
	}

	if ok := RolesMap[payload.Role]; !ok {
		return errors.New("invalid user role")
	}

	return nil
}

// NewUpdateUserPayload returns a new instance of UpdateUserPayload.
func NewUpdateUserPayload(id uuid.UUID, email string, username string, active bool, role UserRole) *UpdateUserPayload {
	return &UpdateUserPayload{
		Id:       id,
		Email:    email,
		Username: username,
		Active:   active,
		Role:     role,
	}
}
