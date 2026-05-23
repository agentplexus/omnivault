package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/plexusone/omnivault/internal/daemon"
)

// Writer writes formatted output.
type Writer struct {
	format Format
	w      io.Writer
}

// NewWriter creates a new Writer with the specified format.
func NewWriter(format Format) *Writer {
	return &Writer{
		format: format,
		w:      os.Stdout,
	}
}

// NewWriterWithOutput creates a new Writer with a custom output destination.
func NewWriterWithOutput(format Format, w io.Writer) *Writer {
	return &Writer{
		format: format,
		w:      w,
	}
}

// Format returns the writer's format.
func (w *Writer) Format() Format {
	return w.format
}

// WriteSecret writes a secret in the configured format.
// If fieldName is non-empty, only that field is output.
func (w *Writer) WriteSecret(secret *daemon.SecretResponse, fieldName string) error {
	if fieldName != "" {
		return w.writeFieldValue(secret, fieldName)
	}

	switch w.format {
	case FormatJSON:
		return w.writeJSON(secret)
	case FormatYAML:
		return w.writeYAML(secret)
	case FormatShell:
		return w.writeShellSecret(secret)
	default:
		return w.writeTextSecret(secret)
	}
}

// writeFieldValue outputs only a specific field value.
func (w *Writer) writeFieldValue(secret *daemon.SecretResponse, fieldName string) error {
	var value string

	if fieldName == "value" || fieldName == "" {
		value = secret.Value
	} else if secret.Fields != nil {
		value = secret.Fields[fieldName]
	}

	switch w.format {
	case FormatJSON:
		return w.writeJSON(map[string]string{fieldName: value})
	case FormatYAML:
		return w.writeYAML(map[string]string{fieldName: value})
	case FormatShell:
		fmt.Fprintln(w.w, ShellExport(fieldName, value))
		return nil
	default:
		fmt.Fprintln(w.w, value)
		return nil
	}
}

// writeTextSecret writes a secret in human-readable text format.
func (w *Writer) writeTextSecret(secret *daemon.SecretResponse) error {
	if secret.Value != "" {
		fmt.Fprintln(w.w, secret.Value)
	}

	if len(secret.Fields) > 0 {
		keys := sortedKeys(secret.Fields)
		for _, k := range keys {
			fmt.Fprintf(w.w, "%s: %s\n", k, secret.Fields[k])
		}
	}

	return nil
}

// writeShellSecret writes a secret as shell-sourceable export statements.
func (w *Writer) writeShellSecret(secret *daemon.SecretResponse) error {
	prefix := ShellSafeKey(secret.Path)

	if secret.Value != "" {
		fmt.Fprintln(w.w, ShellExport(secret.Path, secret.Value))
	}

	if len(secret.Fields) > 0 {
		keys := sortedKeys(secret.Fields)
		for _, k := range keys {
			varName := prefix + "_" + ShellSafeKey(k)
			fmt.Fprintf(w.w, "export %s=%s\n", varName, ShellQuote(secret.Fields[k]))
		}
	}

	return nil
}

// WriteList writes a list response in the configured format.
func (w *Writer) WriteList(resp *daemon.ListResponse, showMetadata bool) error {
	switch w.format {
	case FormatJSON:
		return w.writeJSON(resp)
	case FormatYAML:
		return w.writeYAML(resp)
	default:
		return w.writeTextList(resp, showMetadata)
	}
}

// writeTextList writes a list in human-readable text format.
func (w *Writer) writeTextList(resp *daemon.ListResponse, showMetadata bool) error {
	if resp.Count == 0 {
		fmt.Fprintln(w.w, "No secrets found")
		return nil
	}

	for _, item := range resp.Secrets {
		line := FormatListItem(&item, showMetadata)
		fmt.Fprintln(w.w, line)

		if showMetadata {
			w.writeItemMetadata(&item)
		}
	}

	fmt.Fprintf(w.w, "\n%d secret(s)\n", resp.Count)
	return nil
}

// writeItemMetadata writes metadata lines for a list item.
func (w *Writer) writeItemMetadata(item *daemon.SecretListItem) {
	if !item.CreatedAt.IsZero() {
		fmt.Fprintf(w.w, "  Created: %s\n", item.CreatedAt.Format(time.RFC3339))
	}
	if !item.UpdatedAt.IsZero() {
		fmt.Fprintf(w.w, "  Updated: %s\n", item.UpdatedAt.Format(time.RFC3339))
	}
	if !item.ExpiresAt.IsZero() {
		fmt.Fprintf(w.w, "  Expires: %s\n", item.ExpiresAt.Format(time.RFC3339))
	}
}

// WriteStatus writes a status response in the configured format.
func (w *Writer) WriteStatus(status *daemon.StatusResponse, daemonRunning bool) error {
	switch w.format {
	case FormatJSON:
		if !daemonRunning {
			return w.writeJSON(map[string]any{"running": false})
		}
		return w.writeJSON(status)
	case FormatYAML:
		if !daemonRunning {
			return w.writeYAML(map[string]any{"running": false})
		}
		return w.writeYAML(status)
	default:
		return w.writeTextStatus(status, daemonRunning)
	}
}

// writeTextStatus writes status in human-readable text format.
func (w *Writer) writeTextStatus(status *daemon.StatusResponse, daemonRunning bool) error {
	if !daemonRunning {
		fmt.Fprintln(w.w, "Daemon: not running")
		return nil
	}

	fmt.Fprintln(w.w, "Daemon: running")
	fmt.Fprintf(w.w, "Uptime: %s\n", status.Uptime)

	if !status.VaultExists {
		fmt.Fprintln(w.w, "Vault: not initialized")
		return nil
	}

	if status.Locked {
		fmt.Fprintln(w.w, "Vault: locked")
	} else {
		fmt.Fprintln(w.w, "Vault: unlocked")
		fmt.Fprintf(w.w, "Secrets: %d\n", status.SecretCount)
		if !status.UnlockedAt.IsZero() {
			fmt.Fprintf(w.w, "Unlocked at: %s\n", status.UnlockedAt.Format("2006-01-02 15:04:05"))
		}
	}

	return nil
}

// WriteSearch writes a search response in the configured format.
func (w *Writer) WriteSearch(resp *daemon.SearchResponse) error {
	switch w.format {
	case FormatJSON:
		return w.writeJSON(resp)
	case FormatYAML:
		return w.writeYAML(resp)
	default:
		return w.writeTextSearch(resp)
	}
}

// writeTextSearch writes search results in text format.
func (w *Writer) writeTextSearch(resp *daemon.SearchResponse) error {
	if resp.Count == 0 {
		fmt.Fprintln(w.w, "No secrets found matching pattern")
		return nil
	}

	for _, path := range resp.Paths {
		fmt.Fprintln(w.w, path)
	}
	fmt.Fprintf(w.w, "\n%d secret(s) found\n", resp.Count)
	return nil
}

// writeJSON writes data as JSON.
func (w *Writer) writeJSON(data any) error {
	enc := json.NewEncoder(w.w)
	enc.SetIndent("", "  ")
	return enc.Encode(data)
}

// writeYAML writes data as YAML.
func (w *Writer) writeYAML(data any) error {
	enc := yaml.NewEncoder(w.w)
	enc.SetIndent(2)
	return enc.Encode(data)
}

// FormatListItem formats a secret list item as a string.
func FormatListItem(item *daemon.SecretListItem, showFullTags bool) string {
	var sb strings.Builder
	sb.WriteString(item.Path)

	// Type indicator
	if item.HasValue && item.HasFields {
		sb.WriteString(" (value+fields)")
	} else if item.HasFields {
		sb.WriteString(" (fields)")
	}

	// Tags
	if len(item.Tags) > 0 {
		if showFullTags && len(item.TagsMap) > 0 {
			var pairs []string
			for k, v := range item.TagsMap {
				pairs = append(pairs, fmt.Sprintf("%s=%s", k, v))
			}
			sort.Strings(pairs)
			sb.WriteString(" [")
			sb.WriteString(strings.Join(pairs, ", "))
			sb.WriteString("]")
		} else {
			sb.WriteString(" [")
			sb.WriteString(strings.Join(item.Tags, ", "))
			sb.WriteString("]")
		}
	}

	return sb.String()
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
