package validate

import (
	"github.com/asaskevich/govalidator"
	"unicode"
)

// Email checks if the email is valid.
func Email(email string) bool {
	return govalidator.IsEmail(email)
}

// Password checks if the password is valid.
//
// The function checks if the password contains:
//  1. At least 8 chars
//  2. Upper char
//  3. Lower char
//  4. Number
//  5. Special char
func Password(password string) bool {
	var (
		// Contains at least 8 chars
		minSize = false
		// Contains upper char
		upper = false
		// Contains lower char
		lower = false
		// Contains number
		number = false
		// Contains special char
		special = false
	)

	if len(password) > 8 {
		minSize = true
	}

	for _, c := range password {
		if c == ' ' {
			return false
		}

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

// Username checks if the username is valid.
//
// The function checks if the username contains:
//  1. At least 8 chars
//  2. At most 16 chars
//  3. No spaces
func Username(username string) bool {
	if (len(username) < 8) || (len(username) > 16) {
		return false
	}

	for _, c := range username {
		if c == ' ' {
			return false
		}
	}

	return true
}
