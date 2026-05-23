// Package output provides output formatting for the OmniVault CLI.
package output

import "strings"

// Format represents the output format type.
type Format int

const (
	// FormatText is the default human-readable format.
	FormatText Format = iota
	// FormatJSON outputs JSON.
	FormatJSON
	// FormatYAML outputs YAML.
	FormatYAML
	// FormatShell outputs shell-sourceable format.
	FormatShell
)

// String returns the string representation of the format.
func (f Format) String() string {
	switch f {
	case FormatJSON:
		return "json"
	case FormatYAML:
		return "yaml"
	case FormatShell:
		return "shell"
	default:
		return "text"
	}
}

// ParseFormat parses a format string into a Format.
// Returns FormatText for unrecognized formats.
func ParseFormat(s string) Format {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "json":
		return FormatJSON
	case "yaml", "yml":
		return FormatYAML
	case "shell", "sh", "bash":
		return FormatShell
	default:
		return FormatText
	}
}

// IsStructured returns true if the format outputs structured data (JSON/YAML).
func (f Format) IsStructured() bool {
	return f == FormatJSON || f == FormatYAML
}
