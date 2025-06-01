package models

import (
	"errors"
	"testing"
)

// TestRegisterClientPayloadValidate tests validation of different payloads.
func TestRegisterClientPayloadValidate(t *testing.T) {
	tests := []struct {
		Name     string
		Payload  RegisterClientPayload
		Expected error
	}{
		{
			Name:     "Valid payload",
			Payload:  *NewRegisterClientPayload("validemail@gmail.com", "validUsername", "ValidPassword_123"),
			Expected: nil,
		}, {
			Name:     "Invalid email(invalid domain)",
			Payload:  *NewRegisterClientPayload("invalid@gmail", "validUsername", "invalidPassword"),
			Expected: errors.New("invalid email"),
		}, {
			Name:     "Invalid email(invalid domain)",
			Payload:  *NewRegisterClientPayload("invalid@.com", "validUsername", "invalidPassword"),
			Expected: errors.New("invalid email"),
		}, {
			Name:     "Invalid email(invalid local part)",
			Payload:  *NewRegisterClientPayload("@gmail.com", "validUsername", "invalidPassword"),
			Expected: errors.New("invalid email"),
		}, {
			Name:     "Invalid username(to short)",
			Payload:  *NewRegisterClientPayload("validemail@gmail.com", "user", "Password_123"),
			Expected: errors.New("invalid username"),
		}, {
			Name:     "Invalid password(don't have special chars)",
			Payload:  *NewRegisterClientPayload("validemail@gmail.com", "validUsername", "IDontHaveSpecialChar1"),
			Expected: errors.New("invalid password"),
		}, {
			Name:     "Invalid password(don't have number)",
			Payload:  *NewRegisterClientPayload("validemail@gmail.com", "validUsername", "I_Dont_Have_Number"),
			Expected: errors.New("invalid password"),
		}, {
			Name:     "Invalid password(don't have upper case)",
			Payload:  *NewRegisterClientPayload("validemail@gmail.com", "validUsername", "i_dont_have_upper_case"),
			Expected: errors.New("invalid password"),
		}, {
			Name:     "Invalid password(don't have lower case)",
			Payload:  *NewRegisterClientPayload("validemail@gmail.com", "validUsername", "I_DONT_HAVE_LOWER_CASE"),
			Expected: errors.New("invalid password"),
		}, {
			Name:     "Invalid password(too short)",
			Payload:  *NewRegisterClientPayload("validemail@gmai.com", "validUsername", "Pas_1"),
			Expected: errors.New("invalid password"),
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			err := test.Payload.Validate()

			if test.Expected == nil && err != nil {
				t.Errorf("Expected no error, got %v", err)
			} else if test.Expected != nil && err == nil {
				t.Errorf("Expected error, got nil")
			} else if test.Expected != nil && err != nil && err.Error() != test.Expected.Error() {
				t.Errorf("Expected error %v, got %v", test.Expected, err)
			}
		})
	}
}

// BenchmarkRegisterClientPayloadValidate benchmarks the validation of a RegisterClientPayload.
func BenchmarkRegisterClientPayloadValidate(b *testing.B) {
	payload := NewRegisterClientPayload("validemail@gmail.com", "validUsername", "ValidPassword_123")

	for i := 0; i < b.N; i++ {
		_ = payload.Validate()
	}
}

// TestRegisterUserPayloadValidate tests validation of different payloads.
func TestRegisterUserPayloadValidate(t *testing.T) {
	tests := []struct {
		Name     string
		Payload  RegisterUserPayload
		Expected error
	}{
		{
			Name:     "Valid payload",
			Payload:  *NewRegisterUserPayload("validemail@gmail.com", "validUsername", "ValidPassword_123", Client),
			Expected: nil,
		}, {
			Name:     "Invalid email(invalid domain)",
			Payload:  *NewRegisterUserPayload("invalid@gmail", "validUsername", "invalidPassword", Workshop),
			Expected: errors.New("invalid email"),
		}, {
			Name:     "Invalid email(invalid domain)",
			Payload:  *NewRegisterUserPayload("invalid@.com", "validUsername", "invalidPassword", Delivery),
			Expected: errors.New("invalid email"),
		}, {
			Name:     "Invalid email(invalid local part)",
			Payload:  *NewRegisterUserPayload("@gmail.com", "validUsername", "invalidPassword", Client),
			Expected: errors.New("invalid email"),
		}, {
			Name:     "Invalid username(to short)",
			Payload:  *NewRegisterUserPayload("validemail@gmail.com", "user", "Password_123", Client),
			Expected: errors.New("invalid username"),
		}, {
			Name:     "Invalid password(don't have special chars)",
			Payload:  *NewRegisterUserPayload("validemail@gmail.com", "validUsername", "IDontHaveSpecialChar1", Client),
			Expected: errors.New("invalid password"),
		}, {
			Name:     "Invalid password(don't have number)",
			Payload:  *NewRegisterUserPayload("validemail@gmail.com", "validUsername", "I_Dont_Have_Number", Client),
			Expected: errors.New("invalid password"),
		}, {
			Name:     "Invalid password(don't have upper case)",
			Payload:  *NewRegisterUserPayload("validemail@gmail.com", "validUsername", "i_dont_have_upper_case", Delivery),
			Expected: errors.New("invalid password"),
		}, {
			Name:     "Invalid password(don't have lower case)",
			Payload:  *NewRegisterUserPayload("validemail@gmail.com", "validUsername", "I_DONT_HAVE_LOWER_CASE", Delivery),
			Expected: errors.New("invalid password"),
		}, {
			Name:     "Invalid password(too short)",
			Payload:  *NewRegisterUserPayload("validemail@gmai.com", "validUsername", "Pas_1", Workshop),
			Expected: errors.New("invalid password"),
		},
		{
			Name:     "Invalid role",
			Payload:  *NewRegisterUserPayload("validemail@gmai.com", "validUsername", "Password_123", "Invalid role"),
			Expected: errors.New("invalid user role"),
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			err := test.Payload.Validate()
			if test.Expected == nil && err != nil {
				t.Errorf("Expected no error, got %v", err)
			} else if test.Expected != nil && err == nil {
				t.Errorf("Expected error, got nil")
			} else if test.Expected != nil && err != nil && err.Error() != test.Expected.Error() {
				t.Errorf("Expected error %v, got %v", test.Expected, err)
			}
		})
	}
}

// BenchmarkRegisterUserPayloadValidate benchmarks the validation of a RegisterUserPayload.
func BenchmarkRegisterUserPayloadValidate(b *testing.B) {
	payload := NewRegisterUserPayload("validemail@gmail.com", "validUsername", "ValidPassword_123", Client)

	for i := 0; i < b.N; i++ {
		_ = payload.Validate()
	}
}
