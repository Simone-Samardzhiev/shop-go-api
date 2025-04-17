package config

import "os"

// APIConfig holds API configuration
type APIConfig struct {
	/// ServerAddr holds the address of the API.
	ServerAddr string
	/// IsDebug used to check if the API is for production or development.
	IsDebug bool
}

// Config holds all configuration into one place
type Config struct {
	ApiConfig *APIConfig
}

// NewConfig creates Config instance by
// reading environment variables.
func NewConfig() *Config {
	return &Config{
		ApiConfig: &APIConfig{
			ServerAddr: getEnvVar("SERVER_ADDR", ":8080"),
			IsDebug:    getEnvVarBool("DEBUG", true),
		},
	}
}

// getEnvVar is used to read environment variables.
//
// If variable exist the values is returned otherwise the result is teh fallback.
func getEnvVar(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

// getEnvVarBool is specified version of getEnvVar special for bool variables.

// If the variable exist the value is returned by checking if the string equals true
// otherwise the fallback is returned.
func getEnvVarBool(key string, fallback bool) bool {
	if value, ok := os.LookupEnv(key); ok {
		return value == "true"
	}
	return fallback
}
