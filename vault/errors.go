package vault

import (
	"errors"
	"fmt"
)

// Standard errors that providers should return.
var (
	// ErrSecretNotFound is returned when a secret does not exist.
	ErrSecretNotFound = errors.New("secret not found")

	// ErrAccessDenied is returned when access to a secret is denied.
	ErrAccessDenied = errors.New("access denied")

	// ErrInvalidPath is returned when a secret path is invalid.
	ErrInvalidPath = errors.New("invalid path")

	// ErrReadOnly is returned when attempting to write to a read-only vault.
	ErrReadOnly = errors.New("vault is read-only")

	// ErrNotSupported is returned when an operation is not supported by the provider.
	ErrNotSupported = errors.New("operation not supported")

	// ErrConnectionFailed is returned when the vault connection fails.
	ErrConnectionFailed = errors.New("connection failed")

	// ErrAuthenticationFailed is returned when authentication fails.
	ErrAuthenticationFailed = errors.New("authentication failed")

	// ErrVersionNotFound is returned when a specific version of a secret is not found.
	ErrVersionNotFound = errors.New("version not found")

	// ErrAlreadyExists is returned when attempting to create a secret that already exists.
	ErrAlreadyExists = errors.New("secret already exists")

	// ErrClosed is returned when operating on a closed vault.
	ErrClosed = errors.New("vault is closed")
)

// VaultError is a structured error with additional context.
type VaultError struct {
	// Op is the operation that failed (e.g., "Get", "Set", "Delete").
	Op string

	// Path is the secret path involved in the error.
	Path string

	// Provider is the name of the provider that generated the error.
	Provider string

	// Err is the underlying error.
	Err error
}

// Error implements the error interface.
func (e *VaultError) Error() string {
	if e.Path != "" {
		return fmt.Sprintf("%s: %s %s: %v", e.Provider, e.Op, e.Path, e.Err)
	}
	return fmt.Sprintf("%s: %s: %v", e.Provider, e.Op, e.Err)
}

// Unwrap returns the underlying error.
func (e *VaultError) Unwrap() error {
	return e.Err
}

// Is reports whether the error matches the target.
func (e *VaultError) Is(target error) bool {
	return errors.Is(e.Err, target)
}

// NewVaultError creates a new VaultError.
func NewVaultError(op, path, provider string, err error) *VaultError {
	return &VaultError{
		Op:       op,
		Path:     path,
		Provider: provider,
		Err:      err,
	}
}
