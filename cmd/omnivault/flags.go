package main

import (
	"strings"
)

// ParsedFlags holds parsed command-line flags and positional arguments.
type ParsedFlags struct {
	// Flags contains key-value flags (--key=value or --key value).
	Flags map[string]string

	// Bool contains boolean flags (--flag).
	Bool map[string]bool

	// Args contains positional arguments.
	Args []string
}

// Get returns a flag value, or empty string if not set.
func (p *ParsedFlags) Get(name string) string {
	return p.Flags[name]
}

// GetBool returns true if the boolean flag is set.
func (p *ParsedFlags) GetBool(name string) bool {
	return p.Bool[name]
}

// GetWithDefault returns a flag value, or the default if not set.
func (p *ParsedFlags) GetWithDefault(name, defaultVal string) string {
	if v, ok := p.Flags[name]; ok {
		return v
	}
	return defaultVal
}

// ParseFlags parses command-line arguments into flags and positional arguments.
// boolFlags is a list of flag names that should be treated as boolean (no value).
func ParseFlags(args []string, boolFlags []string) *ParsedFlags {
	p := &ParsedFlags{
		Flags: make(map[string]string),
		Bool:  make(map[string]bool),
		Args:  make([]string, 0),
	}

	// Build lookup for boolean flags
	isBoolFlag := make(map[string]bool)
	for _, name := range boolFlags {
		isBoolFlag[name] = true
	}

	i := 0
	for i < len(args) {
		arg := args[i]

		// Check for -- prefix
		if strings.HasPrefix(arg, "--") {
			name := strings.TrimPrefix(arg, "--")

			// Check for --name=value format
			if idx := strings.Index(name, "="); idx >= 0 {
				p.Flags[name[:idx]] = name[idx+1:]
				i++
				continue
			}

			// Check if this is a boolean flag
			if isBoolFlag[name] {
				p.Bool[name] = true
				i++
				continue
			}

			// Otherwise, expect next argument to be the value
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
				p.Flags[name] = args[i+1]
				i += 2
				continue
			}

			// Flag with no value - treat as empty string
			p.Flags[name] = ""
			i++
			continue
		}

		// Check for -x short flags
		if strings.HasPrefix(arg, "-") && len(arg) == 2 {
			name := strings.TrimPrefix(arg, "-")

			// Check if this is a boolean flag
			if isBoolFlag[name] {
				p.Bool[name] = true
				i++
				continue
			}

			// Otherwise, expect next argument to be the value
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				p.Flags[name] = args[i+1]
				i += 2
				continue
			}

			// Flag with no value
			p.Flags[name] = ""
			i++
			continue
		}

		// Positional argument
		p.Args = append(p.Args, arg)
		i++
	}

	return p
}
