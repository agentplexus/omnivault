package main

import (
	"os"

	"github.com/plexusone/omnivault/internal/config"
	"github.com/plexusone/omnivault/internal/daemon"
	"github.com/plexusone/omnivault/internal/expiry"
)

// checkExpiryWarning checks if a secret is expired or expiring soon
// and prints a warning to stderr.
func checkExpiryWarning(secret *daemon.SecretResponse) error {
	if secret.ExpiresAt.IsZero() {
		return nil
	}

	// Load config for warning threshold
	cfg, err := config.LoadConfig()
	if err != nil {
		cfg = config.DefaultConfig()
	}

	warningDays := cfg.GetExpiryWarningDays()
	result := expiry.CheckNow(secret.ExpiresAt, warningDays)

	return expiry.WriteWarning(os.Stderr, secret.Path, result)
}
