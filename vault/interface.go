// Package vault defines the core interfaces for secret storage providers.
// External providers can implement these interfaces without depending on the
// main omnivault package, allowing them to be developed as separate Go modules.
//
// To create a custom provider, implement the Vault interface:
//
//	type MyProvider struct { /* ... */ }
//
//	func (p *MyProvider) Get(ctx context.Context, path string) (*Secret, error) { /* ... */ }
//	func (p *MyProvider) Set(ctx context.Context, path string, secret *Secret) error { /* ... */ }
//	func (p *MyProvider) Delete(ctx context.Context, path string) error { /* ... */ }
//	func (p *MyProvider) Exists(ctx context.Context, path string) (bool, error) { /* ... */ }
//	func (p *MyProvider) List(ctx context.Context, prefix string) ([]string, error) { /* ... */ }
//	func (p *MyProvider) Name() string { return "myprovider" }
//	func (p *MyProvider) Capabilities() Capabilities { /* ... */ }
//	func (p *MyProvider) Close() error { /* ... */ }
//
// Then inject it into the omnivault client:
//
//	client, _ := omnivault.NewClient(omnivault.Config{
//	    CustomVault: myProvider,
//	})
package vault

import "context"

// Vault is the primary interface that all secret storage providers must implement.
// This interface is designed to be minimal yet complete enough for most use cases.
type Vault interface {
	// Get retrieves a secret from the vault at the given path.
	// Returns ErrSecretNotFound if the secret does not exist.
	Get(ctx context.Context, path string) (*Secret, error)

	// Set stores a secret in the vault at the given path.
	// If the secret already exists, it will be overwritten.
	Set(ctx context.Context, path string, secret *Secret) error

	// Delete removes a secret from the vault at the given path.
	// Returns nil if the secret does not exist.
	Delete(ctx context.Context, path string) error

	// Exists checks if a secret exists at the given path.
	Exists(ctx context.Context, path string) (bool, error)

	// List returns all secret paths matching the given prefix.
	// Returns an empty slice if no secrets match.
	List(ctx context.Context, prefix string) ([]string, error)

	// Name returns the provider name (e.g., "onepassword", "aws-sm", "keychain").
	Name() string

	// Capabilities returns the capabilities supported by this provider.
	Capabilities() Capabilities

	// Close releases any resources held by the provider.
	Close() error
}

// ExtendedVault provides additional features beyond the basic Vault interface.
// Providers can optionally implement this interface for advanced functionality.
type ExtendedVault interface {
	Vault

	// GetVersion retrieves a specific version of a secret.
	GetVersion(ctx context.Context, path, version string) (*Secret, error)

	// ListVersions returns all versions of a secret.
	ListVersions(ctx context.Context, path string) ([]Version, error)

	// Rotate generates a new version of the secret and returns it.
	Rotate(ctx context.Context, path string) (*Secret, error)
}

// BatchVault provides batch operations for providers that support them.
type BatchVault interface {
	Vault

	// GetBatch retrieves multiple secrets in a single operation.
	GetBatch(ctx context.Context, paths []string) (map[string]*Secret, error)

	// SetBatch stores multiple secrets in a single operation.
	SetBatch(ctx context.Context, secrets map[string]*Secret) error

	// DeleteBatch removes multiple secrets in a single operation.
	DeleteBatch(ctx context.Context, paths []string) error
}

// Version represents a version of a secret.
type Version struct {
	ID        string
	CreatedAt *Timestamp
	Current   bool
}

// Capabilities indicates what features a provider supports.
// This allows clients to adapt their behavior based on provider capabilities.
type Capabilities struct {
	// Read indicates the provider supports reading secrets.
	Read bool `json:"read"`

	// Write indicates the provider supports writing secrets.
	Write bool `json:"write"`

	// Delete indicates the provider supports deleting secrets.
	Delete bool `json:"delete"`

	// List indicates the provider supports listing secrets.
	List bool `json:"list"`

	// Versioning indicates the provider supports secret versioning.
	Versioning bool `json:"versioning"`

	// Rotation indicates the provider supports secret rotation.
	Rotation bool `json:"rotation"`

	// Binary indicates the provider supports binary secrets.
	Binary bool `json:"binary"`

	// MultiField indicates the provider supports multi-field secrets.
	MultiField bool `json:"multiField"`

	// Batch indicates the provider supports batch operations.
	Batch bool `json:"batch"`

	// Watch indicates the provider supports watching for changes.
	Watch bool `json:"watch"`
}
