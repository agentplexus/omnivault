package omnivault

import (
	"fmt"
	"strings"
	"sync"

	"github.com/plexusone/omnivault/providers/env"
	"github.com/plexusone/omnivault/providers/file"
	"github.com/plexusone/omnivault/providers/memory"
	"github.com/plexusone/omnivault/vault"
)

// ProviderFactory is a function that creates a vault provider from a URI.
// The uri parameter is the full URI (e.g., "op://VaultName/item").
type ProviderFactory func(uri string) (vault.Vault, error)

// registry holds registered provider factories by scheme.
var (
	registryMu sync.RWMutex
	registry   = make(map[string]ProviderFactory)
)

func init() {
	// Register built-in providers
	RegisterProvider("memory", memoryFactory)
	RegisterProvider("file", fileFactory)
	RegisterProvider("env", envFactory)
}

// RegisterProvider registers a provider factory for a URI scheme.
// This allows external providers (like 1Password) to register themselves
// when imported, enabling VaultFromURI to create them automatically.
//
// Example:
//
//	// In omni-onepassword/omnivault/register.go
//	func init() {
//	    omnivault.RegisterProvider("op", func(uri string) (vault.Vault, error) {
//	        return New(Config{})
//	    })
//	}
func RegisterProvider(scheme string, factory ProviderFactory) {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry[scheme] = factory
}

// UnregisterProvider removes a provider factory for a URI scheme.
func UnregisterProvider(scheme string) {
	registryMu.Lock()
	defer registryMu.Unlock()
	delete(registry, scheme)
}

// RegisteredSchemes returns all registered URI schemes.
func RegisteredSchemes() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	schemes := make([]string, 0, len(registry))
	for scheme := range registry {
		schemes = append(schemes, scheme)
	}
	return schemes
}

// VaultFromURI creates a vault provider from a URI string.
// The URI scheme determines which provider is created.
//
// Built-in schemes:
//   - memory://           - In-memory (testing)
//   - file:///path/to/dir - File-based storage
//   - env://              - Environment variables (with optional prefix: env://PREFIX_)
//
// External providers can register additional schemes via RegisterProvider.
// For example, importing omni-onepassword adds support for:
//   - op://               - 1Password (requires OP_SERVICE_ACCOUNT_TOKEN)
//
// Example:
//
//	// Use built-in file provider
//	v, err := omnivault.VaultFromURI("file:///path/to/secrets")
//
//	// Use 1Password (after importing omni-onepassword)
//	import _ "github.com/plexusone/omni-onepassword/omnivault/register"
//	v, err := omnivault.VaultFromURI("op://MyVault")
func VaultFromURI(uri string) (vault.Vault, error) {
	ref := vault.SecretRef(uri)
	scheme := ref.Scheme()
	if scheme == "" {
		// Handle bare "memory" without ://
		if uri == "memory" {
			scheme = "memory"
		} else {
			return nil, fmt.Errorf("%w: missing scheme in URI: %s", ErrInvalidSecretRef, uri)
		}
	}

	registryMu.RLock()
	factory, ok := registry[scheme]
	registryMu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("%w: %s (available: %v)", ErrUnknownScheme, scheme, RegisteredSchemes())
	}

	return factory(uri)
}

// Built-in provider factories

func memoryFactory(uri string) (vault.Vault, error) {
	return memory.New(), nil
}

func fileFactory(uri string) (vault.Vault, error) {
	// Parse directory from URI: file:///path/to/dir
	dir := strings.TrimPrefix(uri, "file://")
	if dir == "" {
		dir = "."
	}
	return file.New(file.Config{
		Directory:  dir,
		JSONFormat: true,
		Extension:  ".json",
	})
}

func envFactory(uri string) (vault.Vault, error) {
	// Parse prefix from URI: env://PREFIX_
	prefix := strings.TrimPrefix(uri, "env://")
	return env.NewWithConfig(env.Config{
		Prefix:     prefix,
		AllowWrite: true,
	}), nil
}
