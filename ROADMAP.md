# OmniVault Roadmap

## Overview

OmniVault is a unified Go library for secret management. This roadmap covers the evolution from a library to a complete local secret management solution with daemon and CLI.

## Current State: Library ✅ Complete

- [x] Core `vault.Vault` interface
- [x] Built-in providers (env, file, memory)
- [x] URI-based resolver
- [x] External provider module architecture
- [x] omnivault-aws provider module
- [x] omnivault-keyring provider module

## Phase 1: Encrypted Local Store

Add encrypted file-based storage for secure local secrets.

- [ ] `internal/store/crypto.go` - AES-256-GCM encryption, Argon2id key derivation
- [ ] `internal/store/encrypted.go` - Encrypted file store implementing `vault.Vault`
- [ ] Master password protection
- [ ] Configurable auto-lock timeout

## Phase 2: Daemon (omnivaultd)

Background service for secure secret access.

- [ ] `internal/config/paths.go` - Platform-specific paths (~/.omnivault/)
- [ ] `internal/daemon/protocol.go` - IPC protocol definitions
- [ ] `internal/daemon/server.go` - HTTP server over Unix socket
- [ ] `internal/daemon/handlers.go` - API endpoint handlers
- [ ] Lock/unlock session management
- [ ] Auto-lock on timeout

### Daemon API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/status` | GET | Daemon status (running, locked, secret count) |
| `/secrets` | GET | List all secrets (metadata only) |
| `/secret/:path` | GET | Get secret value |
| `/secret/:path` | PUT | Set secret |
| `/secret/:path` | DELETE | Delete secret |
| `/lock` | POST | Lock the vault |
| `/unlock` | POST | Unlock with master password |

### Socket Path

| Platform | Path |
|----------|------|
| macOS/Linux | `~/.omnivault/omnivaultd.sock` |
| Windows | `\\.\pipe\omnivault` |

## Phase 3: CLI (omnivault)

Command-line interface for vault management.

- [ ] `cmd/omnivault/main.go` - CLI entrypoint
- [ ] `cmd/omnivault/get.go` - Get secret
- [ ] `cmd/omnivault/set.go` - Set secret
- [ ] `cmd/omnivault/list.go` - List secrets
- [ ] `cmd/omnivault/delete.go` - Delete secret
- [ ] `cmd/omnivault/lock.go` - Lock vault
- [ ] `cmd/omnivault/unlock.go` - Unlock vault
- [ ] `cmd/omnivault/daemon.go` - Daemon control
- [ ] `cmd/omnivault/status.go` - Show status
- [ ] `cmd/omnivault/init.go` - Initialize vault

### CLI Commands

```bash
# Vault initialization
omnivault init                    # Initialize new vault with master password

# Secret operations
omnivault set <path> [value]      # Set secret (prompts if no value)
omnivault get <path>              # Get secret value
omnivault list [prefix]           # List secrets
omnivault delete <path>           # Delete secret

# Vault control
omnivault lock                    # Lock the vault
omnivault unlock                  # Unlock with master password
omnivault status                  # Show vault status

# Daemon control
omnivault daemon start            # Start daemon
omnivault daemon stop             # Stop daemon
omnivault daemon status           # Daemon status
```

## Phase 4: Daemon Client Library

Go client for daemon IPC communication.

- [ ] `internal/client/client.go` - Unix socket client
- [ ] Automatic daemon startup on first use
- [ ] Connection pooling

## Phase 5: PlexusDesktop Integration

Swift UI for OmniVault in PlexusDesktop.

- [ ] `VaultModels.swift` - Secret info, vault status
- [ ] `VaultDaemonClient.swift` - Unix socket client
- [ ] `VaultManager.swift` - State management
- [ ] `VaultView.swift` - Secret list UI
- [ ] Lock/unlock UI
- [ ] Add/edit secret UI

---

## Security Model

### Encryption
- **Algorithm**: AES-256-GCM (authenticated encryption)
- **Key Derivation**: Argon2id (memory-hard, resistant to GPU attacks)
- **Salt**: Random 32 bytes per vault
- **Nonce**: Random 12 bytes per secret

### Master Password
- Never stored, only used to derive encryption key
- Minimum 8 characters enforced
- Session-based unlock with configurable timeout

### Storage
- Encrypted vault file: `~/.omnivault/vault.enc`
- Metadata stored separately: `~/.omnivault/vault.meta`
- No plaintext secrets on disk

---

## Data Format

### Vault File Structure

```
~/.omnivault/
├── vault.enc           # Encrypted secrets (AES-256-GCM)
├── vault.meta          # Unencrypted metadata (salt, created date)
├── omnivaultd.sock     # Unix socket (runtime)
└── omnivaultd.pid      # Daemon PID file (runtime)
```

### Secret Metadata (in vault.meta)

```json
{
  "version": 1,
  "created_at": "2024-01-01T00:00:00Z",
  "salt": "base64-encoded-salt",
  "argon2_params": {
    "time": 3,
    "memory": 65536,
    "threads": 4
  }
}
```
