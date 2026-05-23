package expiry

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestStatusString(t *testing.T) {
	tests := []struct {
		status   Status
		expected string
	}{
		{StatusOK, "ok"},
		{StatusWarning, "warning"},
		{StatusExpired, "expired"},
		{Status(99), "ok"}, // Unknown defaults to ok
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			got := tt.status.String()
			if got != tt.expected {
				t.Errorf("Status(%d).String() = %q, want %q", tt.status, got, tt.expected)
			}
		})
	}
}

func TestCheck(t *testing.T) {
	now := time.Date(2024, 6, 15, 12, 0, 0, 0, time.UTC)
	warningDays := 30

	tests := []struct {
		name           string
		expiresAt      time.Time
		expectedStatus Status
	}{
		{
			name:           "zero time - no expiry",
			expiresAt:      time.Time{},
			expectedStatus: StatusOK,
		},
		{
			name:           "expired yesterday",
			expiresAt:      now.AddDate(0, 0, -1),
			expectedStatus: StatusExpired,
		},
		{
			name:           "expired 1 hour ago",
			expiresAt:      now.Add(-time.Hour),
			expectedStatus: StatusExpired,
		},
		{
			name:           "expires in 5 days - within warning",
			expiresAt:      now.AddDate(0, 0, 5),
			expectedStatus: StatusWarning,
		},
		{
			name:           "expires in 29 days - within warning",
			expiresAt:      now.AddDate(0, 0, 29),
			expectedStatus: StatusWarning,
		},
		{
			name:           "expires in 30 days - exactly at threshold",
			expiresAt:      now.AddDate(0, 0, 30),
			expectedStatus: StatusWarning,
		},
		{
			name:           "expires in 31 days - outside warning",
			expiresAt:      now.AddDate(0, 0, 31),
			expectedStatus: StatusOK,
		},
		{
			name:           "expires in 1 year - far future",
			expiresAt:      now.AddDate(1, 0, 0),
			expectedStatus: StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Check(tt.expiresAt, warningDays, now)
			if result.Status != tt.expectedStatus {
				t.Errorf("Check() status = %v, want %v", result.Status, tt.expectedStatus)
			}

			// Verify ExpiresAt is set correctly (unless zero)
			if !tt.expiresAt.IsZero() && !result.ExpiresAt.Equal(tt.expiresAt) {
				t.Errorf("Check() expiresAt = %v, want %v", result.ExpiresAt, tt.expiresAt)
			}

			// Verify WarningDays is set
			if !tt.expiresAt.IsZero() && result.WarningDays != warningDays {
				t.Errorf("Check() warningDays = %d, want %d", result.WarningDays, warningDays)
			}
		})
	}
}

func TestCheck_TimeUntil(t *testing.T) {
	now := time.Date(2024, 6, 15, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name            string
		expiresAt       time.Time
		expectedTimeDir string // "positive", "negative", or "zero"
	}{
		{
			name:            "expired - negative time",
			expiresAt:       now.Add(-24 * time.Hour),
			expectedTimeDir: "negative",
		},
		{
			name:            "expiring soon - positive time",
			expiresAt:       now.Add(7 * 24 * time.Hour),
			expectedTimeDir: "positive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Check(tt.expiresAt, 30, now)

			switch tt.expectedTimeDir {
			case "positive":
				if result.TimeUntil <= 0 {
					t.Errorf("TimeUntil = %v, expected positive", result.TimeUntil)
				}
			case "negative":
				if result.TimeUntil >= 0 {
					t.Errorf("TimeUntil = %v, expected negative", result.TimeUntil)
				}
			}
		})
	}
}

func TestCheck_DifferentWarningDays(t *testing.T) {
	now := time.Date(2024, 6, 15, 12, 0, 0, 0, time.UTC)
	expiresIn10Days := now.AddDate(0, 0, 10)

	tests := []struct {
		name           string
		warningDays    int
		expectedStatus Status
	}{
		{"warning 7 days - outside", 7, StatusOK},
		{"warning 10 days - exactly at", 10, StatusWarning},
		{"warning 14 days - inside", 14, StatusWarning},
		{"warning 30 days - well inside", 30, StatusWarning},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Check(expiresIn10Days, tt.warningDays, now)
			if result.Status != tt.expectedStatus {
				t.Errorf("Check() with warningDays=%d status = %v, want %v",
					tt.warningDays, result.Status, tt.expectedStatus)
			}
		})
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		duration time.Duration
		expected string
	}{
		// Days
		{24 * time.Hour, "1 day"},
		{48 * time.Hour, "2 days"},
		{7 * 24 * time.Hour, "7 days"},
		{30 * 24 * time.Hour, "30 days"},

		// Hours
		{time.Hour, "1 hour"},
		{2 * time.Hour, "2 hours"},
		{23 * time.Hour, "23 hours"},

		// Minutes
		{time.Minute, "1 minute"},
		{2 * time.Minute, "2 minutes"},
		{59 * time.Minute, "59 minutes"},

		// Less than a minute
		{30 * time.Second, "less than a minute"},
		{0, "less than a minute"},

		// Negative values (absolute)
		{-24 * time.Hour, "1 day"},
		{-2 * time.Hour, "2 hours"},
		{-5 * time.Minute, "5 minutes"},

		// Combined (only shows largest unit for days)
		{25 * time.Hour, "1 day"}, // 1 day 1 hour, but shows 1 day
		{50 * time.Hour, "2 days"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			got := FormatDuration(tt.duration)
			if got != tt.expected {
				t.Errorf("FormatDuration(%v) = %q, want %q", tt.duration, got, tt.expected)
			}
		})
	}
}

func TestWriteWarning_Expired(t *testing.T) {
	now := time.Now()
	result := Result{
		Status:    StatusExpired,
		ExpiresAt: now.Add(-24 * time.Hour),
		TimeUntil: -24 * time.Hour,
	}

	var buf bytes.Buffer
	err := WriteWarning(&buf, "test/secret", result)

	if err == nil {
		t.Error("WriteWarning() expected error for expired secret")
	}

	output := buf.String()
	if !strings.Contains(output, "WARNING") {
		t.Errorf("WriteWarning() output missing WARNING: %q", output)
	}
	if !strings.Contains(output, "test/secret") {
		t.Errorf("WriteWarning() output missing path: %q", output)
	}
	if !strings.Contains(output, "expired") {
		t.Errorf("WriteWarning() output missing 'expired': %q", output)
	}
	if !strings.Contains(output, "1 day") {
		t.Errorf("WriteWarning() output missing duration: %q", output)
	}
}

func TestWriteWarning_Warning(t *testing.T) {
	expiresAt := time.Date(2024, 6, 20, 0, 0, 0, 0, time.UTC)
	result := Result{
		Status:    StatusWarning,
		ExpiresAt: expiresAt,
		TimeUntil: 5 * 24 * time.Hour,
	}

	var buf bytes.Buffer
	err := WriteWarning(&buf, "test/secret", result)

	if err != nil {
		t.Errorf("WriteWarning() unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "WARNING") {
		t.Errorf("WriteWarning() output missing WARNING: %q", output)
	}
	if !strings.Contains(output, "test/secret") {
		t.Errorf("WriteWarning() output missing path: %q", output)
	}
	if !strings.Contains(output, "expires in") {
		t.Errorf("WriteWarning() output missing 'expires in': %q", output)
	}
	if !strings.Contains(output, "5 days") {
		t.Errorf("WriteWarning() output missing duration: %q", output)
	}
	if !strings.Contains(output, "2024-06-20") {
		t.Errorf("WriteWarning() output missing date: %q", output)
	}
}

func TestWriteWarning_OK(t *testing.T) {
	result := Result{
		Status: StatusOK,
	}

	var buf bytes.Buffer
	err := WriteWarning(&buf, "test/secret", result)

	if err != nil {
		t.Errorf("WriteWarning() unexpected error: %v", err)
	}

	if buf.Len() != 0 {
		t.Errorf("WriteWarning() expected no output for StatusOK, got: %q", buf.String())
	}
}

func TestCheckNow(t *testing.T) {
	// Test with a future expiry
	future := time.Now().Add(365 * 24 * time.Hour)
	result := CheckNow(future, 30)

	if result.Status != StatusOK {
		t.Errorf("CheckNow() with far future expiry = %v, want StatusOK", result.Status)
	}

	// Test with a past expiry
	past := time.Now().Add(-24 * time.Hour)
	result = CheckNow(past, 30)

	if result.Status != StatusExpired {
		t.Errorf("CheckNow() with past expiry = %v, want StatusExpired", result.Status)
	}
}
