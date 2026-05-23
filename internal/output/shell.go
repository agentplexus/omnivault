package output

import "strings"

// ShellSafeKey converts a string to a safe shell variable name.
// - Replaces non-alphanumeric characters with underscores
// - Prepends underscore if string starts with a digit
// - Converts to uppercase
func ShellSafeKey(s string) string {
	if s == "" {
		return ""
	}

	var result strings.Builder
	result.Grow(len(s))

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

// ShellQuote quotes a string for safe shell use.
// Uses single quotes with proper escaping of embedded single quotes.
func ShellQuote(s string) string {
	// Use single quotes and escape any single quotes in the string
	// 'foo'bar' becomes 'foo'"'"'bar'
	escaped := strings.ReplaceAll(s, "'", "'\"'\"'")
	return "'" + escaped + "'"
}

// ShellExport formats a key-value pair as a shell export statement.
func ShellExport(key, value string) string {
	return "export " + ShellSafeKey(key) + "=" + ShellQuote(value)
}
