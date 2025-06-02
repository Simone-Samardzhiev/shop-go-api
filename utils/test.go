package utils

import "api/models"

// ValidRegisterClientPayload returns valid models.RegisterClientPayload.
//  1. Email: email@example.com
//  2. Username: Username
//  3. Password: Password_123
func ValidRegisterClientPayload() *models.RegisterClientPayload {
	return &models.RegisterClientPayload{
		Email:    "email1@example.com",
		Username: "Username1",
		Password: "Password_123",
	}
}

// ValidLoginClintPayload returns valid models.LoginUserPayload.
//  1. Username: Username1
//  2. Password: Password_123
func ValidLoginClintPayload() *models.LoginUserPayload {
	return &models.LoginUserPayload{
		Username: "Username1",
		Password: "Password_123",
	}
}

// ValidAdminLoginPayload returns valid models.LoginUserPayload.
//  1. Username: AdminUsername
//  2. Password: Password_123
func ValidAdminLoginPayload() *models.LoginUserPayload {
	return &models.LoginUserPayload{
		Username: "AdminUsername",
		Password: "Password_123",
	}
}
