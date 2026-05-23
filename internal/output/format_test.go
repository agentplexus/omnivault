package output

import "testing"

func TestParseFormat(t *testing.T) {
	tests := []struct {
		input    string
		expected Format
	}{
		// JSON
		{"json", FormatJSON},
		{"JSON", FormatJSON},
		{"Json", FormatJSON},
		{"  json  ", FormatJSON},

		// YAML
		{"yaml", FormatYAML},
		{"YAML", FormatYAML},
		{"yml", FormatYAML},
		{"YML", FormatYAML},

		// Shell
		{"shell", FormatShell},
		{"SHELL", FormatShell},
		{"sh", FormatShell},
		{"bash", FormatShell},
		{"BASH", FormatShell},

		// Text (default)
		{"text", FormatText},
		{"TEXT", FormatText},
		{"", FormatText},
		{"unknown", FormatText},
		{"xml", FormatText},
		{"csv", FormatText},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := ParseFormat(tt.input)
			if got != tt.expected {
				t.Errorf("ParseFormat(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestFormatString(t *testing.T) {
	tests := []struct {
		format   Format
		expected string
	}{
		{FormatText, "text"},
		{FormatJSON, "json"},
		{FormatYAML, "yaml"},
		{FormatShell, "shell"},
		{Format(99), "text"}, // Unknown format defaults to text
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			got := tt.format.String()
			if got != tt.expected {
				t.Errorf("Format(%d).String() = %q, want %q", tt.format, got, tt.expected)
			}
		})
	}
}

func TestFormatIsStructured(t *testing.T) {
	tests := []struct {
		format   Format
		expected bool
	}{
		{FormatText, false},
		{FormatJSON, true},
		{FormatYAML, true},
		{FormatShell, false},
	}

	for _, tt := range tests {
		t.Run(tt.format.String(), func(t *testing.T) {
			got := tt.format.IsStructured()
			if got != tt.expected {
				t.Errorf("Format(%d).IsStructured() = %v, want %v", tt.format, got, tt.expected)
			}
		})
	}
}

func TestParseFormatRoundTrip(t *testing.T) {
	formats := []Format{FormatText, FormatJSON, FormatYAML, FormatShell}

	for _, f := range formats {
		t.Run(f.String(), func(t *testing.T) {
			parsed := ParseFormat(f.String())
			if parsed != f {
				t.Errorf("ParseFormat(%q) = %v, want %v", f.String(), parsed, f)
			}
		})
	}
}
