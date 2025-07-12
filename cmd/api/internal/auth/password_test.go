package auth

import "testing"

func TestHashPassword(t *testing.T) {
	password := "password"
	_, err := HashPassword(password)
	if err != nil {
		t.Errorf("Error hashing password: %v", err)
	}
}

func TestVerifyPassword(t *testing.T) {
	password := "password"
	hash, err := HashPassword(password)
	if err != nil {
		t.Errorf("Error hashing password: %v", err)
	}

	result := VerifyPassword(password, hash)
	if !result {
		t.Errorf("Password verification failed")
	}
}
