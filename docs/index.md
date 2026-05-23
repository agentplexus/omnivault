# OmniVault

OmniVault is a unified Go library for secret management across multiple providers. It provides a single interface for accessing secrets from password managers, cloud secret managers, enterprise vaults, and local storage.

## Features

- **Unified Interface** - Single API for all secret storage backends
- **Extensible Architecture** - Add custom providers as separate Go modules without modifying the core library
- **URI-Based Resolution** - Reference secrets using URIs like `op://vault/item/field` or `aws-sm://secret-name`
- **Built-in Providers** - Environment variables, file-based, and in-memory storage included
- **Zero External Dependencies** - Core library has no external dependencies beyond the standard library
- **CLI Tool** - Command-line interface with encrypted local storage and daemon architecture
- **Secure Local Storage** - AES-256-GCM encryption with Argon2id key derivation

## Two Ways to Use OmniVault

### As a Go Library

Import OmniVault into your Go application to access secrets from multiple providers:

```go
import "github.com/plexusone/omnivault"

client, _ := omnivault.NewClient(omnivault.Config{
    Provider: omnivault.ProviderEnv,
})

secret, _ := client.Get(ctx, "API_KEY")
fmt.Println(secret.Value)
```

[Get started with the library →](library/quickstart.md)

### As a CLI Tool

Use the `omnivault` command-line tool for secure local secret management:

```bash
omnivault daemon start
omnivault init
omnivault set database/password
omnivault get database/password
```

[Get started with the CLI →](cli/quickstart.md)

## CLI Highlights (v0.5.0)

The CLI includes powerful features for managing secrets:

=== "Output Formats"

    Get secrets in multiple formats:

    ```bash
    omnivault get api/key --format json
    omnivault get api/key --format yaml
    omnivault get api/key --format shell
    ```

=== "Field Extraction"

    Extract specific fields:

    ```bash
    omnivault get database/creds --field password
    ```

=== "Search"

    Find secrets by pattern:

    ```bash
    omnivault search "database/*"
    omnivault search ".*prod.*" --regex
    ```

=== "Import/Export"

    Backup and restore secrets:

    ```bash
    omnivault export --output backup.json
    omnivault import backup.json --merge
    ```

## Quick Links

| Section | Description |
|---------|-------------|
| [Installation](installation.md) | Install the library or CLI |
| [Library Quick Start](library/quickstart.md) | Get started with the Go library |
| [CLI Quick Start](cli/quickstart.md) | Get started with the CLI |
| [CLI Commands](cli/commands.md) | Complete command reference |
| [Configuration](cli/configuration.md) | Configure CLI behavior |
| [Providers](library/providers.md) | Available secret providers |
| [Security](cli/security.md) | CLI security model |
| [Changelog](changelog.md) | Release history |

## License

MIT License - see [LICENSE](https://github.com/plexusone/omnivault/blob/master/LICENSE) for details.
