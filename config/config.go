package config

import "os"

// APIConfig holds API configuration
type APIConfig struct {
	/// ServerAddr holds the address of the API.
	ServerAddr string
}

// Config holds all configuration into one place
type Config struct {
	apiConfig *APIConfig
}

// NewConfig creates Config instance by
// reading environment variables.
func NewConfig() *Config {
	return &Config{
		apiConfig: &APIConfig{
			ServerAddr: getEnvVar("SERVER_ADDR", ":8080"),
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
