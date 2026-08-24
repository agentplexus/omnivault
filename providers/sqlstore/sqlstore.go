// Package sqlstore provides a SQL table-backed vault implementation.
package sqlstore

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/plexusone/omnivault/vault"
)

const (
	defaultTable = "omnivault_secrets"

	// DialectMySQL uses MySQL-compatible SQL, including DoltDB.
	DialectMySQL = "mysql"
	// DialectPostgres uses PostgreSQL-compatible SQL.
	DialectPostgres = "postgres"
	// DialectSQLite uses SQLite-compatible SQL.
	DialectSQLite = "sqlite"
)

// Config configures the SQL-backed vault provider.
type Config struct {
	// DB is the open SQL database handle. The caller owns its lifetime.
	DB *sql.DB

	// Table is the table that stores encrypted secrets. Defaults to
	// "omnivault_secrets".
	Table string

	// Dialect controls placeholder and upsert syntax. Supported values are
	// "mysql", "postgres", and "sqlite". Empty defaults to "mysql".
	Dialect string

	// EncryptionKey is the AES key used to encrypt secret payloads. It must be
	// 16, 24, or 32 bytes. Store this key outside the database, for example in
	// env, keyring, or a cloud secret manager.
	EncryptionKey []byte

	// KeyID is optional metadata that identifies which key encrypted a row.
	KeyID string

	// AutoMigrate creates the table if it does not already exist.
	AutoMigrate bool

	// ReadOnly prevents writes and deletes.
	ReadOnly bool
}

// Provider implements vault.Vault with encrypted rows in a SQL table.
type Provider struct {
	db       *sql.DB
	table    string
	dialect  string
	keyID    string
	readOnly bool
	aead     cipher.AEAD
}

// New creates a SQL-backed vault provider.
func New(config Config) (*Provider, error) {
	if config.DB == nil {
		return nil, errors.New("sqlstore: DB is required")
	}
	if config.Table == "" {
		config.Table = defaultTable
	}
	if config.Dialect == "" {
		config.Dialect = DialectMySQL
	}
	if err := validateIdentifier(config.Table); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(config.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("sqlstore: invalid encryption key: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("sqlstore: create cipher: %w", err)
	}
	p := &Provider{
		db:       config.DB,
		table:    config.Table,
		dialect:  config.Dialect,
		keyID:    config.KeyID,
		readOnly: config.ReadOnly,
		aead:     aead,
	}
	if config.AutoMigrate {
		if err := p.Migrate(context.Background()); err != nil {
			return nil, err
		}
	}
	return p, nil
}

// Migrate creates the provider table if it does not exist.
func (p *Provider) Migrate(ctx context.Context) error {
	nonceType := "BLOB"
	ciphertextType := "BLOB"
	if p.dialect == DialectPostgres {
		nonceType = "BYTEA"
		ciphertextType = "BYTEA"
	}
	_, err := p.db.ExecContext(ctx, fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
path VARCHAR(512) PRIMARY KEY,
nonce %s NOT NULL,
ciphertext %s NOT NULL,
key_id VARCHAR(255) NOT NULL DEFAULT '',
created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
)`, p.table, nonceType, ciphertextType))
	if err != nil {
		return vault.NewVaultError("Migrate", p.table, p.Name(), err)
	}
	return nil
}

// Get retrieves and decrypts a secret.
func (p *Provider) Get(ctx context.Context, path string) (*vault.Secret, error) {
	var nonce, ciphertext []byte
	var keyID string
	row := p.db.QueryRowContext(ctx, p.query("get"), path)
	if err := row.Scan(&nonce, &ciphertext, &keyID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, vault.NewVaultError("Get", path, p.Name(), vault.ErrSecretNotFound)
		}
		return nil, vault.NewVaultError("Get", path, p.Name(), err)
	}
	plaintext, err := p.aead.Open(nil, nonce, ciphertext, []byte(path))
	if err != nil {
		return nil, vault.NewVaultError("Get", path, p.Name(), err)
	}
	var secret vault.Secret
	if err := json.Unmarshal(plaintext, &secret); err != nil {
		return nil, vault.NewVaultError("Get", path, p.Name(), err)
	}
	secret.Metadata.Provider = p.Name()
	secret.Metadata.Path = path
	if secret.Metadata.Extra == nil {
		secret.Metadata.Extra = map[string]any{}
	}
	secret.Metadata.Extra["key_id"] = keyID
	return &secret, nil
}

// Set encrypts and stores a secret.
func (p *Provider) Set(ctx context.Context, path string, secret *vault.Secret) error {
	if p.readOnly {
		return vault.NewVaultError("Set", path, p.Name(), vault.ErrReadOnly)
	}
	if secret == nil {
		return vault.NewVaultError("Set", path, p.Name(), errors.New("secret is required"))
	}
	stored := copySecret(secret)
	now := vault.Now()
	if stored.Metadata.CreatedAt == nil {
		stored.Metadata.CreatedAt = now
	}
	stored.Metadata.ModifiedAt = now
	stored.Metadata.Provider = p.Name()
	stored.Metadata.Path = path

	payload, err := json.Marshal(stored)
	if err != nil {
		return vault.NewVaultError("Set", path, p.Name(), err)
	}
	nonce := make([]byte, p.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return vault.NewVaultError("Set", path, p.Name(), err)
	}
	ciphertext := p.aead.Seal(nil, nonce, payload, []byte(path))
	if _, err := p.db.ExecContext(ctx, p.query("upsert"), path, nonce, ciphertext, p.keyID); err != nil {
		return vault.NewVaultError("Set", path, p.Name(), err)
	}
	return nil
}

// Delete removes a secret.
func (p *Provider) Delete(ctx context.Context, path string) error {
	if p.readOnly {
		return vault.NewVaultError("Delete", path, p.Name(), vault.ErrReadOnly)
	}
	if _, err := p.db.ExecContext(ctx, p.query("delete"), path); err != nil {
		return vault.NewVaultError("Delete", path, p.Name(), err)
	}
	return nil
}

// Exists checks whether a secret exists.
func (p *Provider) Exists(ctx context.Context, path string) (bool, error) {
	var exists int
	if err := p.db.QueryRowContext(ctx, p.query("exists"), path).Scan(&exists); err != nil {
		return false, vault.NewVaultError("Exists", path, p.Name(), err)
	}
	return exists > 0, nil
}

// List returns secret paths with the given prefix.
func (p *Provider) List(ctx context.Context, prefix string) ([]string, error) {
	rows, err := p.db.QueryContext(ctx, p.query("list"), prefix+"%")
	if err != nil {
		return nil, vault.NewVaultError("List", prefix, p.Name(), err)
	}
	defer rows.Close()

	var paths []string
	for rows.Next() {
		var path string
		if err := rows.Scan(&path); err != nil {
			return nil, vault.NewVaultError("List", prefix, p.Name(), err)
		}
		paths = append(paths, path)
	}
	if err := rows.Err(); err != nil {
		return nil, vault.NewVaultError("List", prefix, p.Name(), err)
	}
	return paths, nil
}

// Name returns the provider name.
func (p *Provider) Name() string {
	return "sql"
}

// Capabilities returns provider capabilities.
func (p *Provider) Capabilities() vault.Capabilities {
	return vault.Capabilities{
		Read:       true,
		Write:      !p.readOnly,
		Delete:     !p.readOnly,
		List:       true,
		MultiField: true,
		Binary:     true,
	}
}

// Close does not close the caller-owned database handle.
func (p *Provider) Close() error {
	return nil
}

func (p *Provider) query(name string) string {
	switch name {
	case "get":
		return fmt.Sprintf("SELECT nonce, ciphertext, key_id FROM %s WHERE path = %s", p.table, p.placeholder(1))
	case "upsert":
		switch p.dialect {
		case DialectPostgres:
			return fmt.Sprintf("INSERT INTO %s (path, nonce, ciphertext, key_id) VALUES ($1, $2, $3, $4) ON CONFLICT (path) DO UPDATE SET nonce = EXCLUDED.nonce, ciphertext = EXCLUDED.ciphertext, key_id = EXCLUDED.key_id, updated_at = CURRENT_TIMESTAMP", p.table)
		case DialectSQLite:
			return fmt.Sprintf("INSERT INTO %s (path, nonce, ciphertext, key_id) VALUES (?, ?, ?, ?) ON CONFLICT(path) DO UPDATE SET nonce = excluded.nonce, ciphertext = excluded.ciphertext, key_id = excluded.key_id, updated_at = CURRENT_TIMESTAMP", p.table)
		default:
			return fmt.Sprintf("INSERT INTO %s (path, nonce, ciphertext, key_id) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE nonce = VALUES(nonce), ciphertext = VALUES(ciphertext), key_id = VALUES(key_id), updated_at = CURRENT_TIMESTAMP", p.table)
		}
	case "delete":
		return fmt.Sprintf("DELETE FROM %s WHERE path = %s", p.table, p.placeholder(1))
	case "exists":
		return fmt.Sprintf("SELECT COUNT(1) FROM %s WHERE path = %s", p.table, p.placeholder(1))
	case "list":
		return fmt.Sprintf("SELECT path FROM %s WHERE path LIKE %s ORDER BY path", p.table, p.placeholder(1))
	default:
		panic("unknown sqlstore query")
	}
}

func (p *Provider) placeholder(index int) string {
	if p.dialect == DialectPostgres {
		return fmt.Sprintf("$%d", index)
	}
	return "?"
}

func validateIdentifier(name string) error {
	if name == "" {
		return errors.New("sqlstore: identifier is empty")
	}
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			continue
		}
		return fmt.Errorf("sqlstore: invalid identifier %q", name)
	}
	return nil
}

func copySecret(secret *vault.Secret) *vault.Secret {
	if secret == nil {
		return nil
	}
	copied := &vault.Secret{
		Value:    secret.Value,
		Metadata: secret.Metadata,
	}
	if len(secret.ValueBytes) > 0 {
		copied.ValueBytes = append([]byte(nil), secret.ValueBytes...)
	}
	if secret.Fields != nil {
		copied.Fields = make(map[string]string, len(secret.Fields))
		for k, v := range secret.Fields {
			copied.Fields[k] = v
		}
	}
	if secret.Metadata.Tags != nil {
		copied.Metadata.Tags = make(map[string]string, len(secret.Metadata.Tags))
		for k, v := range secret.Metadata.Tags {
			copied.Metadata.Tags[k] = v
		}
	}
	if secret.Metadata.Labels != nil {
		copied.Metadata.Labels = append([]string(nil), secret.Metadata.Labels...)
	}
	if secret.Metadata.Extra != nil {
		copied.Metadata.Extra = make(map[string]any, len(secret.Metadata.Extra))
		for k, v := range secret.Metadata.Extra {
			copied.Metadata.Extra[k] = v
		}
	}
	return copied
}

// Ensure Provider implements vault.Vault.
var _ vault.Vault = (*Provider)(nil)
