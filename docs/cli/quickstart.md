# CLI Quick Start

This guide shows you how to use the `omnivault` command-line tool for secure local secret management.

## Installation

```bash
go install github.com/plexusone/omnivault/cmd/omnivault@latest
```

Verify the installation:

```bash
omnivault version
```

## Getting Started

### 1. Start the Daemon

The CLI requires a background daemon for secure operations:

```bash
omnivault daemon start
```

### 2. Initialize Your Vault

Create a new vault with a master password:

```bash
omnivault init
```

You'll be prompted to enter and confirm a master password (minimum 8 characters).

!!! warning "Remember Your Password"
    The master password is never stored. If you forget it, you cannot recover your secrets.

### 3. Store a Secret

```bash
# Prompted for value (hidden input)
omnivault set database/password

# Or provide value directly
omnivault set api/key sk-12345
```

### 4. Retrieve a Secret

```bash
omnivault get database/password
```

### 5. List Secrets

```bash
# List all secrets
omnivault list

# List secrets with a prefix
omnivault list database/
```

### 6. Delete a Secret

```bash
omnivault delete database/password
```

You'll be asked to confirm before deletion.

## Session Management

### Lock the Vault

Lock the vault to protect your secrets:

```bash
omnivault lock
```

### Unlock the Vault

Unlock to access secrets again:

```bash
omnivault unlock
```

### Check Status

View vault and daemon status:

```bash
omnivault status
```

Example output:

```
Daemon: running
Uptime: 2h30m15s
Vault: unlocked
Secrets: 5
Unlocked at: 2024-01-15 10:30:00
```

## Output Formats

Get secrets in different formats:

```bash
# Default text output
omnivault get database/credentials

# JSON output
omnivault get database/credentials --format json

# YAML output
omnivault get database/credentials --format yaml

# Shell-sourceable output
omnivault get aws/keys --format shell
```

Source secrets directly into your shell:

```bash
eval $(omnivault get aws/keys --format shell)
echo $AWS_KEYS_ACCESS_KEY
```

## Field Extraction

Extract specific fields from multi-field secrets:

```bash
# Get only the password field
omnivault get database/credentials --field password

# Use in scripts
DB_PASS=$(omnivault get database/credentials --field password)
```

## Search Secrets

Find secrets by pattern:

```bash
# Glob pattern
omnivault search "database/*"
omnivault search "*password*"

# Regex pattern
omnivault search ".*prod.*" --regex
```

## Backup and Restore

Export and import secrets for backup:

```bash
# Export all secrets
omnivault export --output backup.json

# Import secrets
omnivault import backup.json

# Import without overwriting existing
omnivault import backup.json --merge
```

## Change Password

Change your master password:

```bash
omnivault passwd
```

All secrets are automatically re-encrypted with the new password.

## Auto-Lock

The vault automatically locks after 15 minutes of inactivity. Each secret operation resets the timer. You can customize this in the [configuration file](configuration.md).

## Daemon Management

```bash
# Start daemon in background
omnivault daemon start

# Stop the daemon
omnivault daemon stop

# Check daemon status
omnivault daemon status

# Run in foreground (for debugging)
omnivault daemon run
```

## Typical Workflow

```bash
# First time setup
omnivault daemon start
omnivault init

# Daily usage
omnivault unlock
omnivault get my/secret
# ... work ...
omnivault lock

# Or let auto-lock handle it
```

## Next Steps

- [Commands Reference](commands.md) - All CLI commands
- [Configuration](configuration.md) - Customize CLI behavior
- [Daemon Architecture](daemon.md) - How the daemon works
- [Security Model](security.md) - Encryption and security details
