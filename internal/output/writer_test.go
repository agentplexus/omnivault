package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/plexusone/omnivault/internal/daemon"
)

func TestNewWriter(t *testing.T) {
	w := NewWriter(FormatJSON)
	if w.Format() != FormatJSON {
		t.Errorf("NewWriter(FormatJSON).Format() = %v, want FormatJSON", w.Format())
	}
}

func TestNewWriterWithOutput(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriterWithOutput(FormatText, &buf)

	if w.Format() != FormatText {
		t.Errorf("Format() = %v, want FormatText", w.Format())
	}
}

func TestWriteSecret_Text(t *testing.T) {
	tests := []struct {
		name     string
		secret   *daemon.SecretResponse
		field    string
		expected string
	}{
		{
			name: "value only",
			secret: &daemon.SecretResponse{
				Path:  "test/secret",
				Value: "secret-value",
			},
			expected: "secret-value\n",
		},
		{
			name: "fields only",
			secret: &daemon.SecretResponse{
				Path: "test/secret",
				Fields: map[string]string{
					"username": "admin",
					"password": "secret",
				},
			},
			expected: "password: secret\nusername: admin\n",
		},
		{
			name: "value and fields",
			secret: &daemon.SecretResponse{
				Path:  "test/secret",
				Value: "main-value",
				Fields: map[string]string{
					"extra": "data",
				},
			},
			expected: "main-value\nextra: data\n",
		},
		{
			name: "specific field extraction",
			secret: &daemon.SecretResponse{
				Path: "test/secret",
				Fields: map[string]string{
					"username": "admin",
					"password": "secret",
				},
			},
			field:    "password",
			expected: "secret\n",
		},
		{
			name: "value field extraction",
			secret: &daemon.SecretResponse{
				Path:  "test/secret",
				Value: "the-value",
			},
			field:    "value",
			expected: "the-value\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := NewWriterWithOutput(FormatText, &buf)
			err := w.WriteSecret(tt.secret, tt.field)
			if err != nil {
				t.Fatalf("WriteSecret() error = %v", err)
			}
			if got := buf.String(); got != tt.expected {
				t.Errorf("WriteSecret() output = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestWriteSecret_JSON(t *testing.T) {
	secret := &daemon.SecretResponse{
		Path:  "test/secret",
		Value: "secret-value",
		Fields: map[string]string{
			"username": "admin",
		},
	}

	var buf bytes.Buffer
	w := NewWriterWithOutput(FormatJSON, &buf)
	err := w.WriteSecret(secret, "")
	if err != nil {
		t.Fatalf("WriteSecret() error = %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Invalid JSON output: %v", err)
	}

	if result["path"] != "test/secret" {
		t.Errorf("JSON path = %v, want test/secret", result["path"])
	}
	if result["value"] != "secret-value" {
		t.Errorf("JSON value = %v, want secret-value", result["value"])
	}
}

func TestWriteSecret_YAML(t *testing.T) {
	secret := &daemon.SecretResponse{
		Path:  "test/secret",
		Value: "secret-value",
	}

	var buf bytes.Buffer
	w := NewWriterWithOutput(FormatYAML, &buf)
	err := w.WriteSecret(secret, "")
	if err != nil {
		t.Fatalf("WriteSecret() error = %v", err)
	}

	var result map[string]any
	if err := yaml.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Invalid YAML output: %v", err)
	}

	if result["path"] != "test/secret" {
		t.Errorf("YAML path = %v, want test/secret", result["path"])
	}
}

func TestWriteSecret_Shell(t *testing.T) {
	tests := []struct {
		name     string
		secret   *daemon.SecretResponse
		contains []string
	}{
		{
			name: "value only",
			secret: &daemon.SecretResponse{
				Path:  "database/password",
				Value: "secret123",
			},
			contains: []string{"export DATABASE_PASSWORD='secret123'"},
		},
		{
			name: "fields",
			secret: &daemon.SecretResponse{
				Path: "api/credentials",
				Fields: map[string]string{
					"key":    "abc123",
					"secret": "xyz789",
				},
			},
			contains: []string{
				"export API_CREDENTIALS_KEY='abc123'",
				"export API_CREDENTIALS_SECRET='xyz789'",
			},
		},
		{
			name: "value with single quote",
			secret: &daemon.SecretResponse{
				Path:  "test/key",
				Value: "it's a secret",
			},
			contains: []string{"export TEST_KEY='it'\"'\"'s a secret'"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := NewWriterWithOutput(FormatShell, &buf)
			err := w.WriteSecret(tt.secret, "")
			if err != nil {
				t.Fatalf("WriteSecret() error = %v", err)
			}

			output := buf.String()
			for _, expected := range tt.contains {
				if !strings.Contains(output, expected) {
					t.Errorf("WriteSecret() output missing %q\ngot: %q", expected, output)
				}
			}
		})
	}
}

func TestWriteList_Text(t *testing.T) {
	resp := &daemon.ListResponse{
		Secrets: []daemon.SecretListItem{
			{Path: "secret/one", HasValue: true},
			{Path: "secret/two", HasFields: true},
		},
		Count: 2,
	}

	var buf bytes.Buffer
	w := NewWriterWithOutput(FormatText, &buf)
	err := w.WriteList(resp, false)
	if err != nil {
		t.Fatalf("WriteList() error = %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "secret/one") {
		t.Errorf("WriteList() output missing secret/one")
	}
	if !strings.Contains(output, "secret/two") {
		t.Errorf("WriteList() output missing secret/two")
	}
	if !strings.Contains(output, "2 secret(s)") {
		t.Errorf("WriteList() output missing count")
	}
}

func TestWriteList_Empty(t *testing.T) {
	resp := &daemon.ListResponse{
		Secrets: []daemon.SecretListItem{},
		Count:   0,
	}

	var buf bytes.Buffer
	w := NewWriterWithOutput(FormatText, &buf)
	err := w.WriteList(resp, false)
	if err != nil {
		t.Fatalf("WriteList() error = %v", err)
	}

	if !strings.Contains(buf.String(), "No secrets found") {
		t.Errorf("WriteList() should indicate no secrets found")
	}
}

func TestWriteList_WithMetadata(t *testing.T) {
	now := time.Now()
	resp := &daemon.ListResponse{
		Secrets: []daemon.SecretListItem{
			{
				Path:      "secret/one",
				HasValue:  true,
				CreatedAt: now,
				UpdatedAt: now,
			},
		},
		Count: 1,
	}

	var buf bytes.Buffer
	w := NewWriterWithOutput(FormatText, &buf)
	err := w.WriteList(resp, true)
	if err != nil {
		t.Fatalf("WriteList() error = %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Created:") {
		t.Errorf("WriteList() with metadata should show Created timestamp")
	}
	if !strings.Contains(output, "Updated:") {
		t.Errorf("WriteList() with metadata should show Updated timestamp")
	}
}

func TestWriteList_JSON(t *testing.T) {
	resp := &daemon.ListResponse{
		Secrets: []daemon.SecretListItem{
			{Path: "secret/one"},
		},
		Count: 1,
	}

	var buf bytes.Buffer
	w := NewWriterWithOutput(FormatJSON, &buf)
	err := w.WriteList(resp, false)
	if err != nil {
		t.Fatalf("WriteList() error = %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Invalid JSON output: %v", err)
	}

	if result["count"].(float64) != 1 {
		t.Errorf("JSON count = %v, want 1", result["count"])
	}
}

func TestWriteStatus_Text(t *testing.T) {
	tests := []struct {
		name          string
		status        *daemon.StatusResponse
		daemonRunning bool
		contains      []string
	}{
		{
			name:          "daemon not running",
			status:        nil,
			daemonRunning: false,
			contains:      []string{"Daemon: not running"},
		},
		{
			name: "vault not initialized",
			status: &daemon.StatusResponse{
				Uptime:      "1h0m0s",
				VaultExists: false,
			},
			daemonRunning: true,
			contains:      []string{"Daemon: running", "Vault: not initialized"},
		},
		{
			name: "vault locked",
			status: &daemon.StatusResponse{
				Uptime:      "1h0m0s",
				VaultExists: true,
				Locked:      true,
			},
			daemonRunning: true,
			contains:      []string{"Daemon: running", "Vault: locked"},
		},
		{
			name: "vault unlocked",
			status: &daemon.StatusResponse{
				Uptime:      "1h0m0s",
				VaultExists: true,
				Locked:      false,
				SecretCount: 5,
			},
			daemonRunning: true,
			contains:      []string{"Daemon: running", "Vault: unlocked", "Secrets: 5"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := NewWriterWithOutput(FormatText, &buf)
			err := w.WriteStatus(tt.status, tt.daemonRunning)
			if err != nil {
				t.Fatalf("WriteStatus() error = %v", err)
			}

			output := buf.String()
			for _, expected := range tt.contains {
				if !strings.Contains(output, expected) {
					t.Errorf("WriteStatus() output missing %q\ngot: %q", expected, output)
				}
			}
		})
	}
}

func TestWriteStatus_JSON(t *testing.T) {
	status := &daemon.StatusResponse{
		Uptime:      "1h0m0s",
		VaultExists: true,
		Locked:      false,
		SecretCount: 3,
	}

	var buf bytes.Buffer
	w := NewWriterWithOutput(FormatJSON, &buf)
	err := w.WriteStatus(status, true)
	if err != nil {
		t.Fatalf("WriteStatus() error = %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Invalid JSON output: %v", err)
	}

	if result["locked"] != false {
		t.Errorf("JSON locked = %v, want false", result["locked"])
	}
}

func TestWriteStatus_JSON_NotRunning(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriterWithOutput(FormatJSON, &buf)
	err := w.WriteStatus(nil, false)
	if err != nil {
		t.Fatalf("WriteStatus() error = %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Invalid JSON output: %v", err)
	}

	if result["running"] != false {
		t.Errorf("JSON running = %v, want false", result["running"])
	}
}

func TestWriteSearch_Text(t *testing.T) {
	resp := &daemon.SearchResponse{
		Paths: []string{"secret/foo", "secret/bar"},
		Count: 2,
	}

	var buf bytes.Buffer
	w := NewWriterWithOutput(FormatText, &buf)
	err := w.WriteSearch(resp)
	if err != nil {
		t.Fatalf("WriteSearch() error = %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "secret/foo") {
		t.Errorf("WriteSearch() output missing secret/foo")
	}
	if !strings.Contains(output, "secret/bar") {
		t.Errorf("WriteSearch() output missing secret/bar")
	}
	if !strings.Contains(output, "2 secret(s) found") {
		t.Errorf("WriteSearch() output missing count")
	}
}

func TestWriteSearch_Empty(t *testing.T) {
	resp := &daemon.SearchResponse{
		Paths: []string{},
		Count: 0,
	}

	var buf bytes.Buffer
	w := NewWriterWithOutput(FormatText, &buf)
	err := w.WriteSearch(resp)
	if err != nil {
		t.Fatalf("WriteSearch() error = %v", err)
	}

	if !strings.Contains(buf.String(), "No secrets found matching pattern") {
		t.Errorf("WriteSearch() should indicate no matches")
	}
}

func TestWriteSearch_JSON(t *testing.T) {
	resp := &daemon.SearchResponse{
		Paths: []string{"secret/foo"},
		Count: 1,
	}

	var buf bytes.Buffer
	w := NewWriterWithOutput(FormatJSON, &buf)
	err := w.WriteSearch(resp)
	if err != nil {
		t.Fatalf("WriteSearch() error = %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Invalid JSON output: %v", err)
	}

	if result["count"].(float64) != 1 {
		t.Errorf("JSON count = %v, want 1", result["count"])
	}
}

func TestFormatListItem(t *testing.T) {
	tests := []struct {
		name         string
		item         *daemon.SecretListItem
		showFullTags bool
		expected     string
	}{
		{
			name:     "simple path",
			item:     &daemon.SecretListItem{Path: "secret/path"},
			expected: "secret/path",
		},
		{
			name:     "value and fields",
			item:     &daemon.SecretListItem{Path: "secret/path", HasValue: true, HasFields: true},
			expected: "secret/path (value+fields)",
		},
		{
			name:     "fields only",
			item:     &daemon.SecretListItem{Path: "secret/path", HasFields: true},
			expected: "secret/path (fields)",
		},
		{
			name: "with tags",
			item: &daemon.SecretListItem{
				Path: "secret/path",
				Tags: []string{"env", "app"},
			},
			expected: "secret/path [env, app]",
		},
		{
			name: "with full tags",
			item: &daemon.SecretListItem{
				Path:    "secret/path",
				Tags:    []string{"env", "app"},
				TagsMap: map[string]string{"env": "prod", "app": "api"},
			},
			showFullTags: true,
			expected:     "secret/path [app=api, env=prod]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatListItem(tt.item, tt.showFullTags)
			if got != tt.expected {
				t.Errorf("FormatListItem() = %q, want %q", got, tt.expected)
			}
		})
	}
}
