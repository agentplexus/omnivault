package main

import (
	"github.com/plexusone/omnivault/internal/config"
	"github.com/plexusone/omnivault/internal/daemon"
	"github.com/plexusone/omnivault/internal/output"
)

// OutputFormat is an alias to internal/output.Format for backwards compatibility.
type OutputFormat = output.Format

// Format constants for backwards compatibility.
const (
	FormatText  = output.FormatText
	FormatJSON  = output.FormatJSON
	FormatYAML  = output.FormatYAML
	FormatShell = output.FormatShell
)

// ParseFormat delegates to internal/output.ParseFormat.
func ParseFormat(s string) OutputFormat {
	return output.ParseFormat(s)
}

// OutputWriter wraps internal/output.Writer with cmd-specific functionality.
type OutputWriter struct {
	*output.Writer
}

// NewOutputWriter creates a new OutputWriter.
func NewOutputWriter(format OutputFormat) *OutputWriter {
	return &OutputWriter{
		Writer: output.NewWriter(format),
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
func (o *OutputWriter) WriteSecret(secret *daemon.SecretResponse, fieldName string) error {
	return o.Writer.WriteSecret(secret, fieldName)
}

// WriteList writes a list response in the configured format.
func (o *OutputWriter) WriteList(resp *daemon.ListResponse, showMetadata bool) error {
	return o.Writer.WriteList(resp, showMetadata)
}

// WriteStatus writes a status response in the configured format.
func (o *OutputWriter) WriteStatus(status *daemon.StatusResponse, daemonRunning bool) error {
	return o.Writer.WriteStatus(status, daemonRunning)
}

// WriteSearch writes a search response in the configured format.
func (o *OutputWriter) WriteSearch(resp *daemon.SearchResponse) error {
	return o.Writer.WriteSearch(resp)
}
