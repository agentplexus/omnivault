package main

import (
	"reflect"
	"testing"
)

func TestParseFlags(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		boolFlags []string
		wantFlags map[string]string
		wantBool  map[string]bool
		wantArgs  []string
	}{
		{
			name:      "empty",
			args:      []string{},
			boolFlags: nil,
			wantFlags: map[string]string{},
			wantBool:  map[string]bool{},
			wantArgs:  []string{},
		},
		{
			name:      "positional only",
			args:      []string{"arg1", "arg2"},
			boolFlags: nil,
			wantFlags: map[string]string{},
			wantBool:  map[string]bool{},
			wantArgs:  []string{"arg1", "arg2"},
		},
		{
			name:      "flag with equals",
			args:      []string{"--format=json"},
			boolFlags: nil,
			wantFlags: map[string]string{"format": "json"},
			wantBool:  map[string]bool{},
			wantArgs:  []string{},
		},
		{
			name:      "flag with space",
			args:      []string{"--format", "json"},
			boolFlags: nil,
			wantFlags: map[string]string{"format": "json"},
			wantBool:  map[string]bool{},
			wantArgs:  []string{},
		},
		{
			name:      "boolean flag",
			args:      []string{"--metadata"},
			boolFlags: []string{"metadata"},
			wantFlags: map[string]string{},
			wantBool:  map[string]bool{"metadata": true},
			wantArgs:  []string{},
		},
		{
			name:      "mixed flags and args",
			args:      []string{"path/to/secret", "--format", "json", "--metadata"},
			boolFlags: []string{"metadata"},
			wantFlags: map[string]string{"format": "json"},
			wantBool:  map[string]bool{"metadata": true},
			wantArgs:  []string{"path/to/secret"},
		},
		{
			name:      "field extraction",
			args:      []string{"--field", "password", "database/creds"},
			boolFlags: nil,
			wantFlags: map[string]string{"field": "password"},
			wantBool:  map[string]bool{},
			wantArgs:  []string{"database/creds"},
		},
		{
			name:      "multiple flags",
			args:      []string{"--format=json", "--field=password", "path"},
			boolFlags: nil,
			wantFlags: map[string]string{"format": "json", "field": "password"},
			wantBool:  map[string]bool{},
			wantArgs:  []string{"path"},
		},
		{
			name:      "regex flag",
			args:      []string{"pattern", "--regex"},
			boolFlags: []string{"regex"},
			wantFlags: map[string]string{},
			wantBool:  map[string]bool{"regex": true},
			wantArgs:  []string{"pattern"},
		},
		{
			name:      "output file",
			args:      []string{"--output", "backup.json"},
			boolFlags: nil,
			wantFlags: map[string]string{"output": "backup.json"},
			wantBool:  map[string]bool{},
			wantArgs:  []string{},
		},
		{
			name:      "merge flag with file",
			args:      []string{"backup.json", "--merge"},
			boolFlags: []string{"merge"},
			wantFlags: map[string]string{},
			wantBool:  map[string]bool{"merge": true},
			wantArgs:  []string{"backup.json"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := ParseFlags(tt.args, tt.boolFlags)

			if !reflect.DeepEqual(p.Flags, tt.wantFlags) {
				t.Errorf("Flags = %v, want %v", p.Flags, tt.wantFlags)
			}

			if !reflect.DeepEqual(p.Bool, tt.wantBool) {
				t.Errorf("Bool = %v, want %v", p.Bool, tt.wantBool)
			}

			if !reflect.DeepEqual(p.Args, tt.wantArgs) {
				t.Errorf("Args = %v, want %v", p.Args, tt.wantArgs)
			}
		})
	}
}

func TestParsedFlagsGet(t *testing.T) {
	p := ParseFlags([]string{"--format=json", "--field", "password"}, nil)

	if got := p.Get("format"); got != "json" {
		t.Errorf("Get(format) = %q, want %q", got, "json")
	}

	if got := p.Get("field"); got != "password" {
		t.Errorf("Get(field) = %q, want %q", got, "password")
	}

	if got := p.Get("missing"); got != "" {
		t.Errorf("Get(missing) = %q, want %q", got, "")
	}
}

func TestParsedFlagsGetWithDefault(t *testing.T) {
	p := ParseFlags([]string{"--format=json"}, nil)

	if got := p.GetWithDefault("format", "text"); got != "json" {
		t.Errorf("GetWithDefault(format, text) = %q, want %q", got, "json")
	}

	if got := p.GetWithDefault("missing", "default"); got != "default" {
		t.Errorf("GetWithDefault(missing, default) = %q, want %q", got, "default")
	}
}

func TestParsedFlagsGetBool(t *testing.T) {
	p := ParseFlags([]string{"--metadata", "--regex"}, []string{"metadata", "regex", "merge"})

	if !p.GetBool("metadata") {
		t.Error("GetBool(metadata) = false, want true")
	}

	if !p.GetBool("regex") {
		t.Error("GetBool(regex) = false, want true")
	}

	if p.GetBool("merge") {
		t.Error("GetBool(merge) = true, want false")
	}
}
