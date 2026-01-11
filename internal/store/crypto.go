// Package store provides encrypted storage for OmniVault.
package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// Argon2Params contains parameters for Argon2id key derivation.
type Argon2Params struct {
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memory"`
	Threads uint8  `json:"threads"`
	KeyLen  uint32 `json:"key_len"`
}

// DefaultArgon2Params returns secure default parameters for Argon2id.
// These are based on OWASP recommendations for password hashing.
func DefaultArgon2Params() Argon2Params {
	return Argon2Params{
		Time:    3,     // 3 iterations
		Memory:  65536, // 64 MB
		Threads: 4,     // 4 parallel threads
		KeyLen:  32,    // 256-bit key for AES-256
	}
}

// Crypto handles encryption and key derivation for the vault.
type Crypto struct {
	params Argon2Params
	salt   []byte
	key    []byte // Derived key (only set when unlocked)
}

// NewCrypto creates a new Crypto instance with the given salt.
// If salt is nil, a new random salt will be generated.
func NewCrypto(salt []byte, params Argon2Params) (*Crypto, error) {
	if salt == nil {
		salt = make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			return nil, fmt.Errorf("failed to generate salt: %w", err)
		}
	}

	if len(salt) < 16 {
		return nil, errors.New("salt must be at least 16 bytes")
	}

	return &Crypto{
		params: params,
		salt:   salt,
	}, nil
}

// Salt returns the salt used for key derivation.
func (c *Crypto) Salt() []byte {
	return c.salt
}

// Params returns the Argon2 parameters.
func (c *Crypto) Params() Argon2Params {
	return c.params
}

// DeriveKey derives an encryption key from a password using Argon2id.
func (c *Crypto) DeriveKey(password string) []byte {
	return argon2.IDKey(
		[]byte(password),
		c.salt,
		c.params.Time,
		c.params.Memory,
		c.params.Threads,
		c.params.KeyLen,
	)
}

// Unlock derives the key from the password and stores it for encryption/decryption.
func (c *Crypto) Unlock(password string) {
	c.key = c.DeriveKey(password)
}

// Lock clears the derived key from memory.
func (c *Crypto) Lock() {
	if c.key != nil {
		// Zero out the key before releasing
		for i := range c.key {
			c.key[i] = 0
		}
		c.key = nil
	}
}

// IsUnlocked returns true if the vault is unlocked.
func (c *Crypto) IsUnlocked() bool {
	return c.key != nil
}

// Encrypt encrypts plaintext using AES-256-GCM.
// Returns base64-encoded ciphertext (nonce + ciphertext + tag).
func (c *Crypto) Encrypt(plaintext []byte) (string, error) {
	if c.key == nil {
		return "", errors.New("vault is locked")
	}

	block, err := aes.NewCipher(c.key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt and append nonce
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts base64-encoded ciphertext using AES-256-GCM.
func (c *Crypto) Decrypt(encoded string) ([]byte, error) {
	if c.key == nil {
		return nil, errors.New("vault is locked")
	}

	ciphertext, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

// EncryptString encrypts a string and returns base64-encoded ciphertext.
func (c *Crypto) EncryptString(plaintext string) (string, error) {
	return c.Encrypt([]byte(plaintext))
}

// DecryptString decrypts base64-encoded ciphertext and returns a string.
func (c *Crypto) DecryptString(encoded string) (string, error) {
	plaintext, err := c.Decrypt(encoded)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// VerifyPassword checks if the given password matches by attempting to decrypt
// a verification blob. Returns true if password is correct.
func (c *Crypto) VerifyPassword(password string, verificationBlob string) bool {
	// Temporarily derive key from password
	key := c.DeriveKey(password)
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()

	// Try to decrypt verification blob
	ciphertext, err := base64.StdEncoding.DecodeString(verificationBlob)
	if err != nil {
		return false
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return false
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return false
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return false
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return false
	}

	// Verify the magic bytes
	return subtle.ConstantTimeCompare(plaintext, []byte(verificationMagic)) == 1
}

// CreateVerificationBlob creates an encrypted blob that can be used to verify passwords.
func (c *Crypto) CreateVerificationBlob() (string, error) {
	return c.EncryptString(verificationMagic)
}

const verificationMagic = "omnivault-v1"

// GenerateRandomBytes generates cryptographically secure random bytes.
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}
