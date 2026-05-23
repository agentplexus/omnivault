package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/plexusone/omnivault/internal/config"
	"github.com/plexusone/omnivault/internal/daemon"
)

// OutputFormat represents the output format type.
type OutputFormat int

const (
	// FormatText is the default human-readable format.
	FormatText OutputFormat = iota
	// FormatJSON outputs JSON.
	FormatJSON
	// FormatYAML outputs YAML.
	FormatYAML
	// FormatShell outputs shell-sourceable format.
	FormatShell
)

// ParseFormat parses a format string into an OutputFormat.
func ParseFormat(s string) OutputFormat {
	switch strings.ToLower(s) {
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

// OutputWriter writes formatted output.
type OutputWriter struct {
	format OutputFormat
	w      io.Writer
}

// NewOutputWriter creates a new OutputWriter.
func NewOutputWriter(format OutputFormat) *OutputWriter {
	return &OutputWriter{
		format: format,
		w:      os.Stdout,
	}
}

// NewOutputWriterFromFlags creates an OutputWriter from parsed flags,
// using config defaults if no format specified.
func NewOutputWriterFromFlags(flags *ParsedFlags) *OutputWriter {
	format := flags.Get("format")
	if format == "" {
		// Load config for default format
		cfg, err := config.LoadConfig()
		if err == nil && cfg.DefaultFormat != "" {
			format = cfg.DefaultFormat
		}
	}
	return NewOutputWriter(ParseFormat(format))
}

// WriteSecret writes a secret in the configured format.
// If fieldName is non-empty, only that field is output.
func (o *OutputWriter) WriteSecret(secret *daemon.SecretResponse, fieldName string) error {
	// Field extraction mode
	if fieldName != "" {
		return o.writeFieldValue(secret, fieldName)
	}

	switch o.format {
	case FormatJSON:
		return o.writeJSON(secret)
	case FormatYAML:
		return o.writeYAML(secret)
	case FormatShell:
		return o.writeShellSecret(secret)
	default:
		return o.writeTextSecret(secret)
	}
}

// writeFieldValue outputs only a specific field value.
func (o *OutputWriter) writeFieldValue(secret *daemon.SecretResponse, fieldName string) error {
	var value string

	if fieldName == "value" || fieldName == "" {
		value = secret.Value
	} else if secret.Fields != nil {
		value = secret.Fields[fieldName]
	}

	switch o.format {
	case FormatJSON:
		return o.writeJSON(map[string]string{fieldName: value})
	case FormatYAML:
		return o.writeYAML(map[string]string{fieldName: value})
	case FormatShell:
		fmt.Fprintf(o.w, "export %s=%s\n", shellSafeKey(fieldName), shellQuote(value))
		return nil
	default:
		fmt.Fprintln(o.w, value)
		return nil
	}
}

// writeTextSecret writes a secret in human-readable text format.
func (o *OutputWriter) writeTextSecret(secret *daemon.SecretResponse) error {
	if secret.Value != "" {
		fmt.Fprintln(o.w, secret.Value)
	}

	if len(secret.Fields) > 0 {
		keys := sortedKeys(secret.Fields)
		for _, k := range keys {
			fmt.Fprintf(o.w, "%s: %s\n", k, secret.Fields[k])
		}
	}

	return nil
}

// writeShellSecret writes a secret as shell-sourceable export statements.
func (o *OutputWriter) writeShellSecret(secret *daemon.SecretResponse) error {
	// Use path as variable name prefix
	prefix := shellSafeKey(secret.Path)

	if secret.Value != "" {
		fmt.Fprintf(o.w, "export %s=%s\n", prefix, shellQuote(secret.Value))
	}

	if len(secret.Fields) > 0 {
		keys := sortedKeys(secret.Fields)
		for _, k := range keys {
			varName := prefix + "_" + shellSafeKey(k)
			fmt.Fprintf(o.w, "export %s=%s\n", varName, shellQuote(secret.Fields[k]))
		}
	}

	return nil
}

// WriteList writes a list response in the configured format.
func (o *OutputWriter) WriteList(resp *daemon.ListResponse, showMetadata bool) error {
	switch o.format {
	case FormatJSON:
		return o.writeJSON(resp)
	case FormatYAML:
		return o.writeYAML(resp)
	default:
		return o.writeTextList(resp, showMetadata)
	}
}

// writeTextList writes a list in human-readable text format.
func (o *OutputWriter) writeTextList(resp *daemon.ListResponse, showMetadata bool) error {
	if resp.Count == 0 {
		fmt.Fprintln(o.w, "No secrets found")
		return nil
	}

	for _, item := range resp.Secrets {
		typeIndicator := ""
		if item.HasValue && item.HasFields {
			typeIndicator = " (value+fields)"
		} else if item.HasFields {
			typeIndicator = " (fields)"
		}

		tagStr := ""
		if len(item.Tags) > 0 {
			if showMetadata && len(item.TagsMap) > 0 {
				// Show full key=value pairs
				var pairs []string
				for k, v := range item.TagsMap {
					pairs = append(pairs, fmt.Sprintf("%s=%s", k, v))
				}
				sort.Strings(pairs)
				tagStr = fmt.Sprintf(" [%s]", strings.Join(pairs, ", "))
			} else {
				tagStr = fmt.Sprintf(" [%s]", strings.Join(item.Tags, ", "))
			}
		}

		fmt.Fprintf(o.w, "%s%s%s\n", item.Path, typeIndicator, tagStr)

		if showMetadata {
			if !item.CreatedAt.IsZero() {
				fmt.Fprintf(o.w, "  Created: %s\n", item.CreatedAt.Format(time.RFC3339))
			}
			if !item.UpdatedAt.IsZero() {
				fmt.Fprintf(o.w, "  Updated: %s\n", item.UpdatedAt.Format(time.RFC3339))
			}
			if !item.ExpiresAt.IsZero() {
				fmt.Fprintf(o.w, "  Expires: %s\n", item.ExpiresAt.Format(time.RFC3339))
			}
		}
	}

	fmt.Fprintf(o.w, "\n%d secret(s)\n", resp.Count)
	return nil
}

// WriteStatus writes a status response in the configured format.
func (o *OutputWriter) WriteStatus(status *daemon.StatusResponse, daemonRunning bool) error {
	switch o.format {
	case FormatJSON:
		return o.writeJSON(status)
	case FormatYAML:
		return o.writeYAML(status)
	default:
		return o.writeTextStatus(status, daemonRunning)
	}
}

// writeTextStatus writes status in human-readable text format.
func (o *OutputWriter) writeTextStatus(status *daemon.StatusResponse, daemonRunning bool) error {
	if !daemonRunning {
		fmt.Fprintln(o.w, "Daemon: not running")
		return nil
	}

	fmt.Fprintln(o.w, "Daemon: running")
	fmt.Fprintf(o.w, "Uptime: %s\n", status.Uptime)

	if !status.VaultExists {
		fmt.Fprintln(o.w, "Vault: not initialized")
		return nil
	}

	if status.Locked {
		fmt.Fprintln(o.w, "Vault: locked")
	} else {
		fmt.Fprintln(o.w, "Vault: unlocked")
		fmt.Fprintf(o.w, "Secrets: %d\n", status.SecretCount)
		if !status.UnlockedAt.IsZero() {
			fmt.Fprintf(o.w, "Unlocked at: %s\n", status.UnlockedAt.Format("2006-01-02 15:04:05"))
		}
	}

	return nil
}

// writeJSON writes data as JSON.
func (o *OutputWriter) writeJSON(data any) error {
	enc := json.NewEncoder(o.w)
	enc.SetIndent("", "  ")
	return enc.Encode(data)
}

// writeYAML writes data as YAML.
func (o *OutputWriter) writeYAML(data any) error {
	enc := yaml.NewEncoder(o.w)
	enc.SetIndent(2)
	return enc.Encode(data)
}

// shellSafeKey converts a string to a safe shell variable name.
func shellSafeKey(s string) string {
	var result strings.Builder
	for i, r := range s {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || r == '_' {
			result.WriteRune(r)
		} else if r >= '0' && r <= '9' {
			if i == 0 {
				result.WriteRune('_')
			}
			result.WriteRune(r)
		} else {
			result.WriteRune('_')
		}
	}
	return strings.ToUpper(result.String())
}

// shellQuote quotes a string for safe shell use.
func shellQuote(s string) string {
	// Use single quotes and escape any single quotes in the string
	escaped := strings.ReplaceAll(s, "'", "'\"'\"'")
	return "'" + escaped + "'"
}

// sortedKeys returns the sorted keys of a map.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
