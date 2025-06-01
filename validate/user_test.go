package validate

import "testing"

// TestEmail tests the Email function.
func TestEmail(t *testing.T) {
	tests := []struct {
		email    string
		expected bool
	}{
		{
			email:    "",
			expected: false,
		}, {
			email:    "example.com",
			expected: false,
		}, {
			email:    "email@examople.com",
			expected: true,
		}, {
			email:    "@example.com",
			expected: false,
		}, {
			email:    "email@example",
			expected: false,
		}, {
			email:    "email@example.",
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.email, func(t *testing.T) {
			result := Email(test.email)
			if result != test.expected {
				t.Errorf("Expected %t, got %t", test.expected, result)
			}
		})
	}
}

// BenchmarkEmail benchmarks the Email function.
func BenchmarkEmail(b *testing.B) {
	email := "someEmail@example.com"
	for i := 0; i < b.N; i++ {
		Email(email)
	}
}

// TestPassword tests the Password function.
func TestPassword(t *testing.T) {
	tests := []struct {
		password string
		expected bool
	}{
		{
			password: "",
			expected: false,
		}, {
			password: "password",
			expected: false,
		}, {
			password: "12345",
			expected: false,
		}, {
			password: "%$#%@^",
			expected: false,
		}, {
			password: "Password123",
			expected: false,
		}, {
			password: "Password!",
			expected: false,
		}, {
			password: "Password_ 123",
			expected: false,
		}, {
			password: "Password_123",
			expected: true,
		},
	}

	for _, test := range tests {
		t.Run(test.password, func(t *testing.T) {
			result := Password(test.password)
			if result != test.expected {
				t.Errorf("Expected %t, got %t", test.expected, result)
			}
		})
	}
}

// BenchmarkPassword benchmarks the Password function.
func BenchmarkPassword(b *testing.B) {
	password := "StringPassword_123456789!@$%^&*()_+=-"
	for i := 0; i < b.N; i++ {
		Password(password)
	}
}

// TestUsername tests the Username function.
func TestUsername(t *testing.T) {
	tests := []struct {
		username string
		expected bool
	}{
		{
			username: "",
			expected: false,
		}, {
			username: "username",
			expected: true,
		}, {
			username: "username 123",
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.username, func(t *testing.T) {
			result := Username(test.username)
			if result != test.expected {
				t.Errorf("Expected %t, got %t", test.expected, result)
			}
		})
	}
}

// BenchmarkUsername benchmarks the Username function.
func BenchmarkUsername(b *testing.B) {
	username := "StringUsername_123456789!@$%^&*()_+=-"
	for i := 0; i < b.N; i++ {
		Username(username)
	}
}
