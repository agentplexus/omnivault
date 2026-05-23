// Package expiry provides expiry checking and warning functionality.
package expiry

import (
	"fmt"
	"io"
	"time"
)

// Status represents the expiry status of a secret.
type Status int

const (
	// StatusOK means the secret is not expiring soon.
	StatusOK Status = iota
	// StatusWarning means the secret is expiring within the warning threshold.
	StatusWarning
	// StatusExpired means the secret has already expired.
	StatusExpired
)

// String returns the string representation of the status.
func (s Status) String() string {
	switch s {
	case StatusWarning:
		return "warning"
	case StatusExpired:
		return "expired"
	default:
		return "ok"
	}
}

// Result contains the result of an expiry check.
type Result struct {
	Status      Status
	ExpiresAt   time.Time
	TimeUntil   time.Duration // Positive if expiring, negative if expired
	WarningDays int
}

// Check checks the expiry status of a time against a warning threshold.
// warningDays is the number of days before expiry to start warning.
// Returns StatusOK if expiresAt is zero.
func Check(expiresAt time.Time, warningDays int, now time.Time) Result {
	if expiresAt.IsZero() {
		return Result{Status: StatusOK}
	}

	timeUntil := expiresAt.Sub(now)

	if timeUntil <= 0 {
		return Result{
			Status:      StatusExpired,
			ExpiresAt:   expiresAt,
			TimeUntil:   timeUntil,
			WarningDays: warningDays,
		}
	}

	warningThreshold := time.Duration(warningDays) * 24 * time.Hour
	if timeUntil <= warningThreshold {
		return Result{
			Status:      StatusWarning,
			ExpiresAt:   expiresAt,
			TimeUntil:   timeUntil,
			WarningDays: warningDays,
		}
	}

	return Result{
		Status:      StatusOK,
		ExpiresAt:   expiresAt,
		TimeUntil:   timeUntil,
		WarningDays: warningDays,
	}
}

// CheckNow is a convenience function that calls Check with time.Now().
func CheckNow(expiresAt time.Time, warningDays int) Result {
	return Check(expiresAt, warningDays, time.Now())
}

// WriteWarning writes an expiry warning message to the writer.
// Returns nil if no warning is needed.
func WriteWarning(w io.Writer, path string, result Result) error {
	switch result.Status {
	case StatusExpired:
		fmt.Fprintf(w, "WARNING: Secret '%s' has expired (expired %s ago)\n",
			path, FormatDuration(-result.TimeUntil))
		return fmt.Errorf("secret expired")
	case StatusWarning:
		fmt.Fprintf(w, "WARNING: Secret '%s' expires in %s (on %s)\n",
			path, FormatDuration(result.TimeUntil), result.ExpiresAt.Format("2006-01-02"))
		return nil
	default:
		return nil
	}
}

// FormatDuration formats a duration in a human-readable way.
func FormatDuration(d time.Duration) string {
	if d < 0 {
		d = -d
	}

	days := int(d.Hours() / 24)
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60

	if days > 0 {
		if days == 1 {
			return "1 day"
		}
		return fmt.Sprintf("%d days", days)
	}

	if hours > 0 {
		if hours == 1 {
			return "1 hour"
		}
		return fmt.Sprintf("%d hours", hours)
	}

	if minutes > 0 {
		if minutes == 1 {
			return "1 minute"
		}
		return fmt.Sprintf("%d minutes", minutes)
	}

	return "less than a minute"
}
