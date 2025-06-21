package testutils

import "strings"

// FilterToken filters JWT token to include valid runes and limit the size to 1024.
func FilterToken(token string) string {
	builder := strings.Builder{}
	for _, c := range token {
		if c >= 32 && c <= 126 {
			builder.WriteRune(c)
		}
	}

	result := builder.String()
	if len(result) > 1024 {
		return result[:1024]
	}
	return result
}

// FilterPathValue filter path values so they can be inserted safely in urls.
func FilterPathValue(path string) string {
	builder := strings.Builder{}

	for _, c := range path {
		if (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c == 45 || c == 46 || c == 95 || c == 126 {
			builder.WriteRune(c)
		}
	}

	result := builder.String()
	if len(result) > 1024 {
		return result[:1024]
	}
	return result
}
