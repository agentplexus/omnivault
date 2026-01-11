package store

import (
	"bytes"
	"testing"
)

func TestCryptoNew(t *testing.T) {
	// Test with nil salt (generates random)
	crypto, err := NewCrypto(nil, DefaultArgon2Params())
	if err != nil {
		t.Fatalf("Failed to create crypto: %v", err)
	}

	if len(crypto.Salt()) != 32 {
		t.Errorf("Expected salt length 32, got %d", len(crypto.Salt()))
	}

	// Test with provided salt
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i)
	}

	crypto2, err := NewCrypto(salt, DefaultArgon2Params())
	if err != nil {
		t.Fatalf("Failed to create crypto with salt: %v", err)
	}

	if !bytes.Equal(crypto2.Salt(), salt) {
		t.Error("Salt mismatch")
	}
}

func TestCryptoShortSalt(t *testing.T) {
	// Salt too short should fail
	_, err := NewCrypto([]byte("short"), DefaultArgon2Params())
	if err == nil {
		t.Error("Expected error for short salt")
	}
}

func TestCryptoLockUnlock(t *testing.T) {
	crypto, _ := NewCrypto(nil, DefaultArgon2Params())

	if crypto.IsUnlocked() {
		t.Error("Expected crypto to be locked initially")
	}

	crypto.Unlock("password123")

	if !crypto.IsUnlocked() {
		t.Error("Expected crypto to be unlocked after Unlock()")
	}

	crypto.Lock()

	if crypto.IsUnlocked() {
		t.Error("Expected crypto to be locked after Lock()")
	}
}

func TestCryptoEncryptDecrypt(t *testing.T) {
	crypto, _ := NewCrypto(nil, DefaultArgon2Params())
	crypto.Unlock("password123")

	plaintext := "Hello, World! This is a secret message."

	// Encrypt
	ciphertext, err := crypto.EncryptString(plaintext)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	if ciphertext == plaintext {
		t.Error("Ciphertext should not equal plaintext")
	}

	// Decrypt
	decrypted, err := crypto.DecryptString(ciphertext)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("Decrypted text mismatch: got '%s', want '%s'", decrypted, plaintext)
	}
}

func TestCryptoEncryptDecryptBytes(t *testing.T) {
	crypto, _ := NewCrypto(nil, DefaultArgon2Params())
	crypto.Unlock("password123")

	plaintext := []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD}

	// Encrypt
	ciphertext, err := crypto.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Decrypt
	decrypted, err := crypto.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypted bytes mismatch")
	}
}

func TestCryptoEncryptWhenLocked(t *testing.T) {
	crypto, _ := NewCrypto(nil, DefaultArgon2Params())

	_, err := crypto.EncryptString("test")
	if err == nil {
		t.Error("Expected error when encrypting with locked crypto")
	}
}

func TestCryptoDecryptWhenLocked(t *testing.T) {
	crypto, _ := NewCrypto(nil, DefaultArgon2Params())
	crypto.Unlock("password123")

	ciphertext, _ := crypto.EncryptString("test")

	crypto.Lock()

	_, err := crypto.DecryptString(ciphertext)
	if err == nil {
		t.Error("Expected error when decrypting with locked crypto")
	}
}

func TestCryptoWrongPassword(t *testing.T) {
	crypto, _ := NewCrypto(nil, DefaultArgon2Params())
	crypto.Unlock("password123")

	ciphertext, _ := crypto.EncryptString("secret data")

	// Create new crypto with same salt but different password
	crypto2, _ := NewCrypto(crypto.Salt(), crypto.Params())
	crypto2.Unlock("wrongpassword")

	_, err := crypto2.DecryptString(ciphertext)
	if err == nil {
		t.Error("Expected error when decrypting with wrong password")
	}
}

func TestCryptoVerifyPassword(t *testing.T) {
	crypto, _ := NewCrypto(nil, DefaultArgon2Params())
	crypto.Unlock("correctpassword")

	blob, err := crypto.CreateVerificationBlob()
	if err != nil {
		t.Fatalf("Failed to create verification blob: %v", err)
	}

	// Correct password
	if !crypto.VerifyPassword("correctpassword", blob) {
		t.Error("Expected verification to succeed with correct password")
	}

	// Wrong password
	if crypto.VerifyPassword("wrongpassword", blob) {
		t.Error("Expected verification to fail with wrong password")
	}
}

func TestCryptoKeyDerivationDeterministic(t *testing.T) {
	salt := make([]byte, 32)
	params := DefaultArgon2Params()

	crypto1, _ := NewCrypto(salt, params)
	crypto2, _ := NewCrypto(salt, params)

	key1 := crypto1.DeriveKey("password123")
	key2 := crypto2.DeriveKey("password123")

	if !bytes.Equal(key1, key2) {
		t.Error("Same password and salt should produce same key")
	}
}

func TestCryptoKeyDerivationUnique(t *testing.T) {
	params := DefaultArgon2Params()

	// Different salts should produce different keys
	crypto1, _ := NewCrypto(nil, params)
	crypto2, _ := NewCrypto(nil, params)

	key1 := crypto1.DeriveKey("password123")
	key2 := crypto2.DeriveKey("password123")

	if bytes.Equal(key1, key2) {
		t.Error("Different salts should produce different keys")
	}
}

func TestCryptoEmptyPlaintext(t *testing.T) {
	crypto, _ := NewCrypto(nil, DefaultArgon2Params())
	crypto.Unlock("password123")

	ciphertext, err := crypto.EncryptString("")
	if err != nil {
		t.Fatalf("Failed to encrypt empty string: %v", err)
	}

	decrypted, err := crypto.DecryptString(ciphertext)
	if err != nil {
		t.Fatalf("Failed to decrypt empty string: %v", err)
	}

	if decrypted != "" {
		t.Errorf("Expected empty string, got '%s'", decrypted)
	}
}

func TestCryptoLongPlaintext(t *testing.T) {
	crypto, _ := NewCrypto(nil, DefaultArgon2Params())
	crypto.Unlock("password123")

	// 1MB of data
	plaintext := make([]byte, 1024*1024)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	ciphertext, err := crypto.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Failed to encrypt large data: %v", err)
	}

	decrypted, err := crypto.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Failed to decrypt large data: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("Large data decryption mismatch")
	}
}

func TestGenerateRandomBytes(t *testing.T) {
	b1, err := GenerateRandomBytes(32)
	if err != nil {
		t.Fatalf("Failed to generate random bytes: %v", err)
	}

	b2, err := GenerateRandomBytes(32)
	if err != nil {
		t.Fatalf("Failed to generate random bytes: %v", err)
	}

	if bytes.Equal(b1, b2) {
		t.Error("Random bytes should be unique")
	}

	if len(b1) != 32 {
		t.Errorf("Expected length 32, got %d", len(b1))
	}
}
