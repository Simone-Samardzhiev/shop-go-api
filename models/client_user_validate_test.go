package models

import "testing"

func TestRegisterClientPayloadValidate(t *testing.T) {
	type TestCase struct {
		Id       int
		Name     string
		Payload  RegisterClientPayload
		Expected bool
	}

	testCases := []TestCase{
		TestCase{
			Id:       1,
			Name:     "Valid RegisterClientPayload",
			Payload:  *NewRegisterClientPayload("validemail@gmail.com", "validUsername", "validPassword"),
			Expected: true,
		}, {
			Id:       2,
			Name:     "Invalid RegisterClientPayload(email)",
			Payload:  *NewRegisterClientPayload("invalid@gmail", "validUsername", "invalidPassword"),
			Expected: false,
		}, {
			Id:       3,
			Name:     "Invalid RegisterClientPayload(email)",
			Payload:  *NewRegisterClientPayload("invalid@.com", "validUsername", "invalidPassword"),
			Expected: false,
		}, {
			Id:       4,
			Name:     "Invalid RegisterClientPayload(email)",
			Payload:  *NewRegisterClientPayload("@gmail.com", "validUsername", "invalidPassword"),
			Expected: false,
		}, {
			Id:       5,
			Name:     "Invalid RegisterClientPayload(username)",
			Payload:  *NewRegisterClientPayload("validemail@gmail.com", "user", "invalidPassword"),
			Expected: false,
		}, {
			Id:       6,
			Name:     "Invalid RegisterClientPayload(password)",
			Payload:  *NewRegisterClientPayload("validemail@gmail.com", "validUsername", "IDontHaveSpecialChar1"),
			Expected: false,
		}, {
			Id:       7,
			Name:     "Invalid RegisterClientPayload(password)",
			Payload:  *NewRegisterClientPayload("validemail@gmail.com", "validUsername", "I_Dont_Have_Number"),
			Expected: false,
		}, {
			Id:       8,
			Name:     "Invalid RegisterClientPayload(password)",
			Payload:  *NewRegisterClientPayload("validemail@gmail.com", "validUsername", "i_dont_have_upper_case"),
			Expected: false,
		}, {
			Id:       9,
			Name:     "Invalid RegisterClientPayload(password)",
			Payload:  *NewRegisterClientPayload("validemail@gmail.com", "validUsername", "I_DONT_HAVE_LOWER_CASE"),
			Expected: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Name, func(t *testing.T) {
			result := testCase.Payload.Validate()

			if result != testCase.Expected {
				t.Errorf("%d Name: %v \nExpected %t, got %t", testCase.Id, testCase.Name, testCase.Expected, result)
			}
		})
	}
}
