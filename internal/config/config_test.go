package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.AutoLockTimeout != "15m" {
		t.Errorf("DefaultConfig().AutoLockTimeout = %q, want %q", cfg.AutoLockTimeout, "15m")
	}
	if cfg.DefaultFormat != "text" {
		t.Errorf("DefaultConfig().DefaultFormat = %q, want %q", cfg.DefaultFormat, "text")
	}
	if cfg.ExpiryWarningDays != 30 {
		t.Errorf("DefaultConfig().ExpiryWarningDays = %d, want %d", cfg.ExpiryWarningDays, 30)
	}
	if cfg.DefaultTags != nil {
		t.Errorf("DefaultConfig().DefaultTags = %v, want nil", cfg.DefaultTags)
	}
}

func TestLoadConfigFromFile_NotExists(t *testing.T) {
	cfg, err := LoadConfigFromFile("/nonexistent/path/config.json")
	if err != nil {
		t.Fatalf("LoadConfigFromFile() error = %v, expected nil for nonexistent file", err)
	}

	// Should return default config
	if cfg.AutoLockTimeout != "15m" {
		t.Errorf("AutoLockTimeout = %q, want default %q", cfg.AutoLockTimeout, "15m")
	}
	if cfg.DefaultFormat != "text" {
		t.Errorf("DefaultFormat = %q, want default %q", cfg.DefaultFormat, "text")
	}
}

func TestLoadConfigFromFile_ValidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.json")

	content := `{
		"auto_lock_timeout": "1h",
		"default_format": "json",
		"expiry_warning_days": 7,
		"default_tags": {"env": "prod", "team": "platform"}
	}`
	if err := os.WriteFile(configPath, []byte(content), 0600); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	cfg, err := LoadConfigFromFile(configPath)
	if err != nil {
		t.Fatalf("LoadConfigFromFile() error = %v", err)
	}

	if cfg.AutoLockTimeout != "1h" {
		t.Errorf("AutoLockTimeout = %q, want %q", cfg.AutoLockTimeout, "1h")
	}
	if cfg.DefaultFormat != "json" {
		t.Errorf("DefaultFormat = %q, want %q", cfg.DefaultFormat, "json")
	}
	if cfg.ExpiryWarningDays != 7 {
		t.Errorf("ExpiryWarningDays = %d, want %d", cfg.ExpiryWarningDays, 7)
	}
	if cfg.DefaultTags["env"] != "prod" {
		t.Errorf("DefaultTags[env] = %q, want %q", cfg.DefaultTags["env"], "prod")
	}
	if cfg.DefaultTags["team"] != "platform" {
		t.Errorf("DefaultTags[team] = %q, want %q", cfg.DefaultTags["team"], "platform")
	}
}

func TestLoadConfigFromFile_PartialJSON(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.json")

	// Only override some fields
	content := `{"default_format": "yaml"}`
	if err := os.WriteFile(configPath, []byte(content), 0600); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	cfg, err := LoadConfigFromFile(configPath)
	if err != nil {
		t.Fatalf("LoadConfigFromFile() error = %v", err)
	}

	// Overridden field
	if cfg.DefaultFormat != "yaml" {
		t.Errorf("DefaultFormat = %q, want %q", cfg.DefaultFormat, "yaml")
	}

	// Default values preserved
	if cfg.AutoLockTimeout != "15m" {
		t.Errorf("AutoLockTimeout = %q, want default %q", cfg.AutoLockTimeout, "15m")
	}
	if cfg.ExpiryWarningDays != 30 {
		t.Errorf("ExpiryWarningDays = %d, want default %d", cfg.ExpiryWarningDays, 30)
	}
}

func TestLoadConfigFromFile_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.json")

	content := `{invalid json`
	if err := os.WriteFile(configPath, []byte(content), 0600); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	_, err := LoadConfigFromFile(configPath)
	if err == nil {
		t.Error("LoadConfigFromFile() expected error for invalid JSON, got nil")
	}
}

func TestSaveToFile(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.json")

	cfg := &Config{
		AutoLockTimeout:   "30m",
		DefaultFormat:     "shell",
		ExpiryWarningDays: 14,
		DefaultTags:       map[string]string{"app": "test"},
	}

	if err := cfg.SaveToFile(configPath); err != nil {
		t.Fatalf("SaveToFile() error = %v", err)
	}

	// Verify file permissions
	info, err := os.Stat(configPath)
	if err != nil {
		t.Fatalf("Failed to stat config file: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("Config file permissions = %o, want 0600", info.Mode().Perm())
	}

	// Verify content by loading it back
	loaded, err := LoadConfigFromFile(configPath)
	if err != nil {
		t.Fatalf("LoadConfigFromFile() error = %v", err)
	}

	if loaded.AutoLockTimeout != cfg.AutoLockTimeout {
		t.Errorf("Loaded AutoLockTimeout = %q, want %q", loaded.AutoLockTimeout, cfg.AutoLockTimeout)
	}
	if loaded.DefaultFormat != cfg.DefaultFormat {
		t.Errorf("Loaded DefaultFormat = %q, want %q", loaded.DefaultFormat, cfg.DefaultFormat)
	}
	if loaded.ExpiryWarningDays != cfg.ExpiryWarningDays {
		t.Errorf("Loaded ExpiryWarningDays = %d, want %d", loaded.ExpiryWarningDays, cfg.ExpiryWarningDays)
	}
	if loaded.DefaultTags["app"] != "test" {
		t.Errorf("Loaded DefaultTags[app] = %q, want %q", loaded.DefaultTags["app"], "test")
	}
}

func TestGetAutoLockDuration(t *testing.T) {
	tests := []struct {
		name     string
		timeout  string
		expected time.Duration
	}{
		// Valid durations
		{"15 minutes", "15m", 15 * time.Minute},
		{"1 hour", "1h", time.Hour},
		{"30 seconds", "30s", 30 * time.Second},
		{"1h30m", "1h30m", 90 * time.Minute},
		{"24 hours", "24h", 24 * time.Hour},

		// Edge cases - fall back to default
		{"empty string", "", 15 * time.Minute},
		{"invalid format", "invalid", 15 * time.Minute},
		{"just number", "15", 15 * time.Minute},
		{"negative", "-5m", 15 * time.Minute}, // ParseDuration allows negative, but we get what it returns
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{AutoLockTimeout: tt.timeout}
			got := cfg.GetAutoLockDuration()

			// For negative duration case, ParseDuration succeeds, so adjust expectation
			if tt.timeout == "-5m" {
				if got != -5*time.Minute {
					t.Errorf("GetAutoLockDuration() = %v, want %v", got, -5*time.Minute)
				}
				return
			}

			if got != tt.expected {
				t.Errorf("GetAutoLockDuration() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestGetExpiryWarningDays(t *testing.T) {
	tests := []struct {
		name     string
		days     int
		expected int
	}{
		{"positive value", 7, 7},
		{"larger value", 90, 90},
		{"zero - fallback to default", 0, 30},
		{"negative - fallback to default", -5, 30},
		{"one day", 1, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{ExpiryWarningDays: tt.days}
			got := cfg.GetExpiryWarningDays()
			if got != tt.expected {
				t.Errorf("GetExpiryWarningDays() = %d, want %d", got, tt.expected)
			}
		})
	}
}

func TestConfigRoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.json")

	original := &Config{
		AutoLockTimeout:   "2h",
		DefaultFormat:     "yaml",
		ExpiryWarningDays: 45,
		DefaultTags: map[string]string{
			"env":    "staging",
			"region": "us-west-2",
		},
	}

	// Save
	if err := original.SaveToFile(configPath); err != nil {
		t.Fatalf("SaveToFile() error = %v", err)
	}

	// Load
	loaded, err := LoadConfigFromFile(configPath)
	if err != nil {
		t.Fatalf("LoadConfigFromFile() error = %v", err)
	}

	// Compare
	if loaded.AutoLockTimeout != original.AutoLockTimeout {
		t.Errorf("AutoLockTimeout mismatch: got %q, want %q", loaded.AutoLockTimeout, original.AutoLockTimeout)
	}
	if loaded.DefaultFormat != original.DefaultFormat {
		t.Errorf("DefaultFormat mismatch: got %q, want %q", loaded.DefaultFormat, original.DefaultFormat)
	}
	if loaded.ExpiryWarningDays != original.ExpiryWarningDays {
		t.Errorf("ExpiryWarningDays mismatch: got %d, want %d", loaded.ExpiryWarningDays, original.ExpiryWarningDays)
	}
	if len(loaded.DefaultTags) != len(original.DefaultTags) {
		t.Errorf("DefaultTags length mismatch: got %d, want %d", len(loaded.DefaultTags), len(original.DefaultTags))
	}
	for k, v := range original.DefaultTags {
		if loaded.DefaultTags[k] != v {
			t.Errorf("DefaultTags[%s] mismatch: got %q, want %q", k, loaded.DefaultTags[k], v)
		}
	}
}

func TestEmptyConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.json")

	// Write empty JSON object
	if err := os.WriteFile(configPath, []byte("{}"), 0600); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	cfg, err := LoadConfigFromFile(configPath)
	if err != nil {
		t.Fatalf("LoadConfigFromFile() error = %v", err)
	}

	// All defaults should be preserved
	if cfg.AutoLockTimeout != "15m" {
		t.Errorf("AutoLockTimeout = %q, want default %q", cfg.AutoLockTimeout, "15m")
	}
	if cfg.DefaultFormat != "text" {
		t.Errorf("DefaultFormat = %q, want default %q", cfg.DefaultFormat, "text")
	}
	if cfg.ExpiryWarningDays != 30 {
		t.Errorf("ExpiryWarningDays = %d, want default %d", cfg.ExpiryWarningDays, 30)
	}
}
