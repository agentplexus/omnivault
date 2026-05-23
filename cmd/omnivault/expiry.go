package main

import (
	"fmt"
	"os"
	"time"

	"github.com/plexusone/omnivault/internal/config"
	"github.com/plexusone/omnivault/internal/daemon"
)

// checkExpiryWarning checks if a secret is expired or expiring soon
// and prints a warning to stderr.
func checkExpiryWarning(secret *daemon.SecretResponse) error {
	if secret.ExpiresAt.IsZero() {
		return nil
	}

	now := time.Now()
	expiresAt := secret.ExpiresAt

	// Check if already expired
	if expiresAt.Before(now) {
		fmt.Fprintf(os.Stderr, "WARNING: Secret '%s' has expired (expired %s ago)\n",
			secret.Path, formatDuration(now.Sub(expiresAt)))
		return fmt.Errorf("secret expired")
	}

	// Check if expiring soon
	cfg, err := config.LoadConfig()
	if err != nil {
		cfg = config.DefaultConfig()
	}

	warningDays := cfg.GetExpiryWarningDays()
	warningThreshold := time.Duration(warningDays) * 24 * time.Hour
	timeUntilExpiry := expiresAt.Sub(now)

	if timeUntilExpiry <= warningThreshold {
		fmt.Fprintf(os.Stderr, "WARNING: Secret '%s' expires in %s (on %s)\n",
			secret.Path, formatDuration(timeUntilExpiry), expiresAt.Format("2006-01-02"))
		return nil
	}

	return nil
}

// formatDuration formats a duration in a human-readable way.
func formatDuration(d time.Duration) string {
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
