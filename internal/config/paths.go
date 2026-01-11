// Package config provides configuration and path management for OmniVault.
package config

import (
	"os"
	"path/filepath"
	"runtime"
)

// Paths contains all file system paths used by OmniVault.
type Paths struct {
	// ConfigDir is the base configuration directory.
	ConfigDir string

	// VaultFile is the encrypted vault data file.
	VaultFile string

	// MetaFile is the vault metadata file (salt, params).
	MetaFile string

	// SocketPath is the Unix socket path for the daemon (Unix only).
	SocketPath string

	// TCPAddr is the TCP address for the daemon (Windows only).
	TCPAddr string

	// PIDFile is the daemon PID file.
	PIDFile string

	// LogFile is the daemon log file.
	LogFile string
}

// GetPaths returns the appropriate paths for the current platform.
func GetPaths() *Paths {
	switch runtime.GOOS {
	case "windows":
		return windowsPaths()
	default:
		return unixPaths()
	}
}

// unixPaths returns paths for macOS and Linux.
func unixPaths() *Paths {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}

	configDir := filepath.Join(home, ".omnivault")

	return &Paths{
		ConfigDir:  configDir,
		VaultFile:  filepath.Join(configDir, "vault.enc"),
		MetaFile:   filepath.Join(configDir, "vault.meta"),
		SocketPath: filepath.Join(configDir, "omnivaultd.sock"),
		PIDFile:    filepath.Join(configDir, "omnivaultd.pid"),
		LogFile:    filepath.Join(configDir, "omnivaultd.log"),
	}
}

// windowsPaths returns paths for Windows.
func windowsPaths() *Paths {
	localAppData := os.Getenv("LOCALAPPDATA")
	if localAppData == "" {
		home, _ := os.UserHomeDir()
		localAppData = filepath.Join(home, "AppData", "Local")
	}

	configDir := filepath.Join(localAppData, "OmniVault")

	return &Paths{
		ConfigDir:  configDir,
		VaultFile:  filepath.Join(configDir, "vault.enc"),
		MetaFile:   filepath.Join(configDir, "vault.meta"),
		SocketPath: "", // Not used on Windows
		TCPAddr:    "127.0.0.1:19839",
		PIDFile:    filepath.Join(configDir, "omnivaultd.pid"),
		LogFile:    filepath.Join(configDir, "omnivaultd.log"),
	}
}

// EnsureConfigDir creates the configuration directory if it doesn't exist.
func (p *Paths) EnsureConfigDir() error {
	return os.MkdirAll(p.ConfigDir, 0700)
}

// VaultExists returns true if the vault file exists.
func (p *Paths) VaultExists() bool {
	_, err := os.Stat(p.VaultFile)
	return err == nil
}

// CleanupSocket removes the socket file if it exists.
func (p *Paths) CleanupSocket() error {
	if runtime.GOOS == "windows" {
		return nil // Named pipes don't need cleanup
	}
	return os.Remove(p.SocketPath)
}
