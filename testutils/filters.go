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
