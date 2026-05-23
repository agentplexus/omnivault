package output

import "testing"

func TestShellSafeKey(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		// Basic cases
		{"", ""},
		{"foo", "FOO"},
		{"FOO", "FOO"},
		{"Foo", "FOO"},

		// With underscores
		{"foo_bar", "FOO_BAR"},
		{"_foo", "_FOO"},
		{"foo_", "FOO_"},

		// With numbers
		{"foo123", "FOO123"},
		{"foo1bar2", "FOO1BAR2"},
		{"123foo", "_123FOO"}, // Leading digit gets underscore prefix
		{"1", "_1"},           // Single digit
		{"123", "_123"},       // All digits

		// Special characters become underscores
		{"foo-bar", "FOO_BAR"},
		{"foo.bar", "FOO_BAR"},
		{"foo/bar", "FOO_BAR"},
		{"foo:bar", "FOO_BAR"},
		{"foo bar", "FOO_BAR"},
		{"foo@bar", "FOO_BAR"},

		// Multiple special characters
		{"foo--bar", "FOO__BAR"},
		{"a.b.c", "A_B_C"},
		{"path/to/secret", "PATH_TO_SECRET"},

		// Complex paths
		{"database/production/password", "DATABASE_PRODUCTION_PASSWORD"},
		{"api-keys/stripe", "API_KEYS_STRIPE"},
		{"env.prod.db", "ENV_PROD_DB"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := ShellSafeKey(tt.input)
			if got != tt.expected {
				t.Errorf("ShellSafeKey(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestShellQuote(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		// Basic cases
		{"", "''"},
		{"foo", "'foo'"},
		{"hello world", "'hello world'"},

		// With special shell characters (should be safely quoted)
		{"$HOME", "'$HOME'"},
		{"`whoami`", "'`whoami`'"},
		{"$(id)", "'$(id)'"},
		{"a && b", "'a && b'"},
		{"a || b", "'a || b'"},
		{"a; b", "'a; b'"},
		{"a | b", "'a | b'"},
		{"a > b", "'a > b'"},
		{"a < b", "'a < b'"},
		{"*", "'*'"},
		{"?", "'?'"},
		{"[abc]", "'[abc]'"},

		// With single quotes (need escaping)
		{"it's", "'it'\"'\"'s'"},
		{"'quoted'", "''\"'\"'quoted'\"'\"''"},
		{"a'b'c", "'a'\"'\"'b'\"'\"'c'"},

		// With double quotes (no special handling needed)
		{`"quoted"`, `'"quoted"'`},

		// With backslashes
		{`foo\bar`, `'foo\bar'`},
		{`\\`, `'\\'`},

		// Newlines and tabs
		{"line1\nline2", "'line1\nline2'"},
		{"col1\tcol2", "'col1\tcol2'"},

		// Unicode
		{"日本語", "'日本語'"},
		{"émoji 🎉", "'émoji 🎉'"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := ShellQuote(tt.input)
			if got != tt.expected {
				t.Errorf("ShellQuote(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestShellExport(t *testing.T) {
	tests := []struct {
		key      string
		value    string
		expected string
	}{
		// Basic cases
		{"foo", "bar", "export FOO='bar'"},
		{"database_password", "secret123", "export DATABASE_PASSWORD='secret123'"},

		// Path-like keys
		{"path/to/secret", "value", "export PATH_TO_SECRET='value'"},
		{"api-key", "abc123", "export API_KEY='abc123'"},

		// Values with special characters
		{"key", "value with spaces", "export KEY='value with spaces'"},
		{"key", "$HOME/path", "export KEY='$HOME/path'"},
		{"key", "it's quoted", "export KEY='it'\"'\"'s quoted'"},

		// Empty values
		{"key", "", "export KEY=''"},

		// Leading digits in key
		{"123key", "value", "export _123KEY='value'"},
	}

	for _, tt := range tests {
		name := tt.key + "=" + tt.value
		t.Run(name, func(t *testing.T) {
			got := ShellExport(tt.key, tt.value)
			if got != tt.expected {
				t.Errorf("ShellExport(%q, %q) = %q, want %q", tt.key, tt.value, got, tt.expected)
			}
		})
	}
}
