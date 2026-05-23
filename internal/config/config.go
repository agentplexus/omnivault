package config

import (
	"encoding/json"
	"os"
	"time"
)

// Config represents the user configuration for OmniVault.
type Config struct {
	// AutoLockTimeout is the duration after which the vault auto-locks.
	// Use time.Duration format (e.g., "15m", "1h").
	AutoLockTimeout string `json:"auto_lock_timeout,omitempty"`

	// DefaultFormat is the default output format (text, json, yaml, shell).
	DefaultFormat string `json:"default_format,omitempty"`

	// DefaultTags are applied to all new secrets.
	DefaultTags map[string]string `json:"default_tags,omitempty"`

	// ExpiryWarningDays is the number of days before expiry to show warnings.
	ExpiryWarningDays int `json:"expiry_warning_days,omitempty"`
}

// DefaultConfig returns the default configuration.
func DefaultConfig() *Config {
	return &Config{
		AutoLockTimeout:   "15m",
		DefaultFormat:     "text",
		ExpiryWarningDays: 30,
	}
}

// LoadConfig loads the configuration from the config file.
// Returns default config if the file doesn't exist.
func LoadConfig() (*Config, error) {
	paths := GetPaths()
	return LoadConfigFromFile(paths.ConfigFile)
}

// LoadConfigFromFile loads the configuration from a specific file.
func LoadConfigFromFile(path string) (*Config, error) {
	cfg := DefaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, err
	}

	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Save writes the configuration to the config file.
func (c *Config) Save() error {
	paths := GetPaths()
	return c.SaveToFile(paths.ConfigFile)
}

// SaveToFile writes the configuration to a specific file.
func (c *Config) SaveToFile(path string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// GetAutoLockDuration parses and returns the auto-lock timeout duration.
func (c *Config) GetAutoLockDuration() time.Duration {
	if c.AutoLockTimeout == "" {
		return 15 * time.Minute
	}
	d, err := time.ParseDuration(c.AutoLockTimeout)
	if err != nil {
		return 15 * time.Minute
	}
	return d
}

// GetExpiryWarningDays returns the number of days for expiry warnings.
func (c *Config) GetExpiryWarningDays() int {
	if c.ExpiryWarningDays <= 0 {
		return 30
	}
	return c.ExpiryWarningDays
}
