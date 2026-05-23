# CLI Commands Reference

Complete reference for all `omnivault` commands.

## Vault Commands

### init

Initialize a new vault with a master password.

```bash
omnivault init
```

- Prompts for master password (minimum 8 characters)
- Prompts to confirm password
- Creates encrypted vault at `~/.omnivault/`
- Vault is unlocked after initialization

!!! note "Requires Daemon"
    The daemon must be running before initialization.

### unlock

Unlock the vault with the master password.

```bash
omnivault unlock
```

- Prompts for master password
- Vault stays unlocked until locked or auto-lock timeout

### lock

Lock the vault immediately.

```bash
omnivault lock
```

- Clears encryption key from memory
- Secrets are inaccessible until unlocked

### status

Show vault and daemon status.

```bash
omnivault status [--format <format>]
```

**Flags:**

| Flag | Description |
|------|-------------|
| `--format` | Output format: `text` (default), `json`, `yaml` |

**Examples:**

```bash
# Default text output
omnivault status

# JSON output for scripting
omnivault status --format json
```

Example text output:

```
Daemon: running
Uptime: 1h23m45s
Vault: unlocked
Secrets: 12
Unlocked at: 2024-01-15 09:00:00
```

Status fields:

| Field | Description |
|-------|-------------|
| Daemon | `running` or `not running` |
| Uptime | Time since daemon started |
| Vault | `locked`, `unlocked`, or `not initialized` |
| Secrets | Number of stored secrets (when unlocked) |
| Unlocked at | Timestamp of last unlock |

### passwd

Change the vault master password.

```bash
omnivault passwd
```

- Prompts for current password
- Prompts for new password (minimum 8 characters)
- Prompts to confirm new password
- Re-encrypts all secrets with the new password

!!! warning "Vault Must Be Unlocked"
    The vault must be unlocked to change the password.

**Example:**

```bash
omnivault passwd
# Enter current password: ********
# Enter new password (min 8 chars): ********
# Confirm new password: ********
# Password changed successfully!
```

## Secret Commands

### get

Retrieve a secret value.

```bash
omnivault get <path> [--format <format>] [--field <name>]
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| `path` | Secret path (e.g., `database/password`) |

**Flags:**

| Flag | Description |
|------|-------------|
| `--format` | Output format: `text` (default), `json`, `yaml`, `shell` |
| `--field` | Extract a specific field from the secret |

**Examples:**

```bash
# Get secret value
omnivault get api/key

# JSON output
omnivault get database/credentials --format json

# YAML output
omnivault get database/credentials --format yaml

# Shell-sourceable output
omnivault get aws/keys --format shell
# Output:
# export AWS_KEYS='...'
# export AWS_KEYS_ACCESS_KEY='AKIA...'
# export AWS_KEYS_SECRET_KEY='...'

# Extract specific field
omnivault get database/credentials --field password

# Use in scripts
DB_PASS=$(omnivault get database/credentials --field password)
```

**Shell Format:**

The `shell` format outputs `export` statements that can be sourced directly:

```bash
# Source secrets into environment
eval $(omnivault get aws/keys --format shell)

# Or save to file and source
omnivault get aws/keys --format shell > /tmp/aws-env
source /tmp/aws-env
```

**Expiry Warnings:**

If a secret has an expiration date and is expired or expiring soon, a warning is printed to stderr:

```
WARNING: Secret 'api/token' expires in 5 days (on 2024-01-20)
```

### set

Store a secret.

```bash
omnivault set <path> [value]
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| `path` | Secret path (e.g., `database/password`) |
| `value` | Optional secret value |

If value is not provided, you'll be prompted to enter it (input is hidden).

**Examples:**

```bash
# Prompted input (recommended for sensitive values)
omnivault set database/password

# Direct value
omnivault set config/timeout 30

# Piped input
echo "my-secret" | omnivault set api/key
```

### list

List all secrets or filter by prefix.

```bash
omnivault list [prefix] [--format <format>] [--metadata]
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| `prefix` | Optional path prefix filter |

**Flags:**

| Flag | Description |
|------|-------------|
| `--format` | Output format: `text` (default), `json`, `yaml` |
| `--metadata` | Show detailed metadata (timestamps, full tags) |

**Examples:**

```bash
# List all secrets
omnivault list

# List secrets under database/
omnivault list database/

# JSON output for scripting
omnivault list --format json

# Show detailed metadata
omnivault list --metadata
```

**Default Output:**

```
database/password (value+fields)
database/username
api/key [production, v2]
config/timeout

4 secret(s)
```

**With `--metadata`:**

```
database/password (value+fields) [env=production, service=api]
  Created: 2024-01-01T10:30:00Z
  Updated: 2024-01-15T15:45:00Z
  Expires: 2024-06-01T00:00:00Z
database/username
  Created: 2024-01-01T10:30:00Z
  Updated: 2024-01-01T10:30:00Z

2 secret(s)
```

Indicators:

- `(value+fields)` - Secret has both value and fields
- `(fields)` - Secret has only fields
- `[tag1, tag2]` - Secret tags (keys only)
- `[key=value]` - Full tag pairs (with `--metadata`)

### delete

Delete a secret.

```bash
omnivault delete <path>
```

**Aliases:** `rm`

**Arguments:**

| Argument | Description |
|----------|-------------|
| `path` | Secret path to delete |

Prompts for confirmation before deletion.

**Examples:**

```bash
omnivault delete api/old-key
omnivault rm database/test
```

### search

Search for secrets by path pattern.

```bash
omnivault search <pattern> [--regex] [--format <format>]
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| `pattern` | Search pattern (glob or regex) |

**Flags:**

| Flag | Description |
|------|-------------|
| `--regex` | Use regex pattern instead of glob |
| `--format` | Output format: `text` (default), `json`, `yaml` |

**Examples:**

```bash
# Glob pattern (default)
omnivault search "database/*"
omnivault search "*password*"
omnivault search "api/v*"

# Regex pattern
omnivault search ".*prod.*" --regex
omnivault search "^api/v[0-9]+/" --regex
omnivault search "(database|cache)/.*password" --regex

# JSON output for scripting
omnivault search "database/*" --format json
```

**Output:**

```
database/prod/password
database/prod/username
database/dev/password

3 secret(s) found
```

## Import/Export Commands

### export

Export secrets as JSON.

```bash
omnivault export [prefix] [--output <file>]
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| `prefix` | Optional path prefix filter |

**Flags:**

| Flag | Description |
|------|-------------|
| `--output` | Output file (default: stdout) |

**Examples:**

```bash
# Export all secrets to stdout
omnivault export

# Export to file
omnivault export --output backup.json

# Export subset with prefix
omnivault export database/ --output database-backup.json

# Pipe to another command
omnivault export | jq '.secrets | length'
```

**Output Format:**

```json
{
  "secrets": [
    {
      "path": "database/password",
      "value": "secret123",
      "fields": {
        "username": "admin"
      },
      "tags": {
        "env": "production"
      }
    }
  ],
  "count": 1
}
```

!!! warning "Sensitive Data"
    The export contains plaintext secrets. Handle with care and delete backup files securely.

### import

Import secrets from JSON.

```bash
omnivault import [file] [--merge]
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| `file` | Input file (default: stdin) |

**Flags:**

| Flag | Description |
|------|-------------|
| `--merge` | Skip existing secrets instead of overwriting |

**Examples:**

```bash
# Import from file (overwrites existing)
omnivault import backup.json

# Import with merge (skip existing)
omnivault import backup.json --merge

# Import from stdin
cat secrets.json | omnivault import

# Pipe from export
omnivault export | omnivault import --merge
```

**Confirmation:**

Import always prompts for confirmation:

```
Import 5 secret(s)? (existing secrets will be overwritten) [y/N]: y
Imported: 5, Skipped: 0, Errors: 0
```

With `--merge`:

```
Import 5 secret(s)? (merge mode - existing secrets will be skipped) [y/N]: y
Imported: 2, Skipped: 3, Errors: 0
```

## Daemon Commands

### daemon start

Start the daemon in background.

```bash
omnivault daemon start
```

- Starts the daemon as a background process
- Creates Unix socket at `~/.omnivault/omnivaultd.sock`
- Writes PID to `~/.omnivault/omnivaultd.pid`

### daemon stop

Stop the daemon.

```bash
omnivault daemon stop
```

- Locks the vault before stopping
- Removes socket and PID files

### daemon status

Show daemon status.

```bash
omnivault daemon status
```

### daemon run

Run the daemon in foreground.

```bash
omnivault daemon run
```

Useful for debugging. Press Ctrl+C to stop.

## Other Commands

### version

Show version information.

```bash
omnivault version
```

### help

Show help information.

```bash
omnivault help
omnivault -h
omnivault --help
```

## Output Formats

Commands that support `--format` accept the following values:

| Format | Description |
|--------|-------------|
| `text` | Human-readable format (default) |
| `json` | JSON output |
| `yaml` | YAML output |
| `shell` | Shell-sourceable `export` statements (get only) |

The default format can be set in the [configuration file](configuration.md).

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success |
| 1 | Error (message printed to stderr) |

## Environment Variables

Currently, the CLI does not use environment variables for configuration. Use the [configuration file](configuration.md) instead.
