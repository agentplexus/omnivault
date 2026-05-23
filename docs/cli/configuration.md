# Configuration

OmniVault supports user configuration via a JSON configuration file.

## Configuration File

The configuration file is located at:

| Platform | Path |
|----------|------|
| macOS/Linux | `~/.omnivault/config.json` |
| Windows | `%LOCALAPPDATA%\OmniVault\config.json` |

## Creating the Configuration

Create the configuration file manually:

```bash
mkdir -p ~/.omnivault
cat > ~/.omnivault/config.json << 'EOF'
{
  "auto_lock_timeout": "15m",
  "default_format": "text",
  "expiry_warning_days": 30
}
EOF
```

## Configuration Options

### auto_lock_timeout

Duration before the vault auto-locks due to inactivity.

| Type | Default |
|------|---------|
| string (duration) | `"15m"` |

**Format:** Go duration string (e.g., `"5m"`, `"1h"`, `"30m"`, `"2h30m"`)

**Examples:**

```json
{
  "auto_lock_timeout": "30m"
}
```

```json
{
  "auto_lock_timeout": "1h"
}
```

!!! note "Activity Reset"
    Each secret operation (get, set, list, delete, search) resets the auto-lock timer.

### default_format

Default output format for commands that support `--format`.

| Type | Default |
|------|---------|
| string | `"text"` |

**Valid Values:** `"text"`, `"json"`, `"yaml"`

**Example:**

```json
{
  "default_format": "json"
}
```

This affects:

- `omnivault get` (also supports `"shell"`)
- `omnivault list`
- `omnivault status`
- `omnivault search`

!!! tip "Override with Flag"
    The `--format` flag always overrides the default.

### expiry_warning_days

Number of days before expiration to show warnings when retrieving secrets.

| Type | Default |
|------|---------|
| integer | `30` |

**Example:**

```json
{
  "expiry_warning_days": 14
}
```

When you `get` a secret that expires within this many days, a warning is printed to stderr:

```
WARNING: Secret 'api/token' expires in 5 days (on 2024-01-20)
```

Set to `0` to only warn about already-expired secrets.

### default_tags

Tags automatically applied to all new secrets.

| Type | Default |
|------|---------|
| object | `null` |

**Example:**

```json
{
  "default_tags": {
    "managed_by": "omnivault",
    "environment": "development"
  }
}
```

These tags are merged with any tags specified when creating a secret.

## Complete Example

```json
{
  "auto_lock_timeout": "30m",
  "default_format": "json",
  "expiry_warning_days": 14,
  "default_tags": {
    "managed_by": "omnivault"
  }
}
```

## Configuration Precedence

1. Command-line flags (highest priority)
2. Configuration file
3. Built-in defaults (lowest priority)

## Validating Configuration

The configuration file is read on each command. Invalid JSON will cause an error:

```bash
omnivault status
# Error: failed to load config: invalid character...
```

Validate your configuration:

```bash
cat ~/.omnivault/config.json | python3 -m json.tool
```

## File Permissions

The configuration file should have restricted permissions:

```bash
chmod 600 ~/.omnivault/config.json
```

While the configuration itself doesn't contain secrets, restricting access follows the principle of least privilege.

## Reloading Configuration

Configuration is loaded fresh on each command invocation. No restart is required after changes.

## Configuration vs. Vault Settings

| Setting | Stored In | Scope |
|---------|-----------|-------|
| Auto-lock timeout | Config file | User preference |
| Default format | Config file | User preference |
| Expiry warnings | Config file | User preference |
| Master password | Vault (encrypted) | Security |
| Secrets | Vault (encrypted) | Data |

The configuration file controls CLI behavior. The vault stores encrypted secrets and security parameters.
