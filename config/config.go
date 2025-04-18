package config

import (
	"os"
	"strconv"
	"time"
)

// APIConfig holds API configuration
type APIConfig struct {
	/// ServerAddr holds the address of the API.
	ServerAddr string
	/// IsDebug used to check if the API is for production or development.
	IsDebug bool
}

// DatabaseConfig holds database configuration.
type DatabaseConfig struct {
	// URL used to connect to the database.
	URL string
	// MaxOpenConnections specifies the max open connection to the database.
	MaxOpenConnections int
	// MaxIdleConnections specifies the max open idle connections to the database.
	MaxIdleConnections int
	// MaxIdleTime specifies the time before idle connection is closed.
	MaxIdleTime time.Duration
	// MaxLifetime specifies the time a connection can be used.
	MaxLifetime time.Duration
}

// AuthConfig holds authentication configuration.
type AuthConfig struct {
	// JWTSecret used to sign the tokens.
	JWTSecret string
	// Issuer of the tokens.
	Issuer string
}

// Config holds all configuration into one place
type Config struct {
	ApiConfig *APIConfig
	DbConfig  *DatabaseConfig
}

// NewConfig creates Config instance by
// reading environment variables.
func NewConfig() *Config {
	return &Config{
		ApiConfig: &APIConfig{
			ServerAddr: getEnvVar("SERVER_ADDR", ":8080"),
			IsDebug:    getEnvVarBool("DEBUG", true),
		},
		DbConfig: &DatabaseConfig{
			URL:                getEnvVar("DATABASE_URL", ""),
			MaxOpenConnections: getEnvVarInt("MAX_OPEN_CONNECTIONS", 10),
			MaxIdleConnections: getEnvVarInt("MAX_IDLE_CONNECTIONS", 10),
			MaxLifetime:        getEnvVarDuration("MAX_LIFETIME", 5*time.Minute),
			MaxIdleTime:        getEnvVarDuration("MAX_IDLE_TIME", 5*time.Minute),
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

// getEnvVarBool is specialized version of getEnvVar for bool variables.
//
// If the variable exist the value is returned by checking if the string equals true
// otherwise the fallback is returned.
func getEnvVarBool(key string, fallback bool) bool {
	if value, ok := os.LookupEnv(key); ok {
		return value == "true"
	}
	return fallback
}

// getEnvVarInt is a specialized version of getEnvVar for int variables.
//
// If the variable exists, and it is a valid int the value is returned otherwise
// the fallback is returned
func getEnvVarInt(key string, fallback int) int {
	if value, ok := os.LookupEnv(key); ok {
		result, err := strconv.Atoi(value)
		if err != nil {
			return fallback
		}
		return result
	}
	return fallback
}

// getEnvVarDuration is specialized version of getEnvVar for time.Duration variables.
//
// If the variable exists, and it is a valid int the value is parsed into duration and returned
// otherwise the fallback is returned.
func getEnvVarDuration(key string, fallback time.Duration) time.Duration {
	if value, ok := os.LookupEnv(key); ok {
		result, err := strconv.Atoi(value)
		if err != nil {
			return fallback
		}
		return time.Duration(result) * time.Second
	}

	return fallback
}
