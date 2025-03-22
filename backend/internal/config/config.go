package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Config holds the application configuration
type Config struct {
	// Server configuration
	Port     int    `json:"port"`
	LogLevel string `json:"log_level"`

	// Security
	JWTSecret     string `json:"jwt_secret"`
	JWTExpiration int    `json:"jwt_expiration"` // in minutes

	// Temporary file storage
	TempDir string `json:"temp_dir"`
}

// DefaultConfig returns the default configuration
func DefaultConfig() *Config {
	return &Config{
		Port:          8080,
		LogLevel:      "info",
		JWTSecret:     "change-me-in-production",
		JWTExpiration: 60, // 1 hour by default
		TempDir:       os.TempDir(),
	}
}

// Load loads the configuration from environment variables or config file
func Load() (*Config, error) {
	config := DefaultConfig()

	// Try to load from config file
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		// Try default locations
		candidates := []string{
			"./config.json",
			"/etc/secretbay/config.json",
		}

		for _, candidate := range candidates {
			if _, err := os.Stat(candidate); err == nil {
				configPath = candidate
				break
			}
		}
	}

	if configPath != "" {
		if err := loadFromFile(config, configPath); err != nil {
			return nil, fmt.Errorf("failed to load config from file: %w", err)
		}
	}

	// Override with environment variables if present
	if port := os.Getenv("PORT"); port != "" {
		var err error
		_, err = fmt.Sscanf(port, "%d", &config.Port)
		if err != nil {
			return nil, fmt.Errorf("invalid PORT environment variable: %w", err)
		}
	}

	if logLevel := os.Getenv("LOG_LEVEL"); logLevel != "" {
		config.LogLevel = logLevel
	}

	if jwtSecret := os.Getenv("JWT_SECRET"); jwtSecret != "" {
		config.JWTSecret = jwtSecret
	}

	if jwtExp := os.Getenv("JWT_EXPIRATION"); jwtExp != "" {
		var err error
		_, err = fmt.Sscanf(jwtExp, "%d", &config.JWTExpiration)
		if err != nil {
			return nil, fmt.Errorf("invalid JWT_EXPIRATION environment variable: %w", err)
		}
	}

	if tempDir := os.Getenv("TEMP_DIR"); tempDir != "" {
		// Ensure the directory exists
		if err := os.MkdirAll(tempDir, 0750); err != nil {
			return nil, fmt.Errorf("failed to create temp directory: %w", err)
		}
		config.TempDir = tempDir
	} else {
		// Ensure the default temp directory exists and has a secretbay subdirectory
		secretbayTempDir := filepath.Join(config.TempDir, "secretbay")
		if err := os.MkdirAll(secretbayTempDir, 0750); err != nil {
			return nil, fmt.Errorf("failed to create secretbay temp directory: %w", err)
		}
		config.TempDir = secretbayTempDir
	}

	return config, nil
}

// loadFromFile loads configuration from a JSON file
func loadFromFile(config *Config, path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("could not open config file: %w", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(config); err != nil {
		return fmt.Errorf("could not decode config file: %w", err)
	}

	return nil
}
