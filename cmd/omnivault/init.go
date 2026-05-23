package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/plexusone/omnivault/internal/client"
	"golang.org/x/term"
)

func cmdInit(_ []string) error {
	c := client.New()
	ctx := context.Background()

	// Check if daemon is running
	if !c.IsDaemonRunning() {
		return fmt.Errorf("daemon is not running, start it with: omnivault daemon start")
	}

	// Check if vault already exists
	status, err := c.GetStatus(ctx)
	if err != nil {
		return fmt.Errorf("failed to get status: %w", err)
	}

	if status.VaultExists {
		return fmt.Errorf("vault already exists")
	}

	// Prompt for password
	fmt.Print("Enter master password (min 8 chars): ")
	password, err := readPassword()
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}

	fmt.Print("Confirm master password: ")
	confirm, err := readPassword()
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	if password != confirm {
		return fmt.Errorf("passwords do not match")
	}

	// Initialize vault
	if err := c.Init(ctx, password); err != nil {
		return fmt.Errorf("failed to initialize vault: %w", err)
	}

	fmt.Println("Vault initialized successfully!")
	fmt.Println("Your vault is now unlocked and ready to use.")
	return nil
}

func cmdUnlock(_ []string) error {
	c := client.New()
	ctx := context.Background()

	if !c.IsDaemonRunning() {
		return fmt.Errorf("daemon is not running, start it with: omnivault daemon start")
	}

	status, err := c.GetStatus(ctx)
	if err != nil {
		return fmt.Errorf("failed to get status: %w", err)
	}

	if !status.VaultExists {
		return fmt.Errorf("vault does not exist, run: omnivault init")
	}

	if !status.Locked {
		fmt.Println("Vault is already unlocked")
		return nil
	}

	fmt.Print("Enter master password: ")
	password, err := readPassword()
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	if err := c.Unlock(ctx, password); err != nil {
		return fmt.Errorf("failed to unlock: %w", err)
	}

	fmt.Println("Vault unlocked successfully!")
	return nil
}

func cmdLock(_ []string) error {
	c := client.New()
	ctx := context.Background()

	if !c.IsDaemonRunning() {
		return fmt.Errorf("daemon is not running")
	}

	if err := c.Lock(ctx); err != nil {
		return fmt.Errorf("failed to lock: %w", err)
	}

	fmt.Println("Vault locked")
	return nil
}

func cmdStatus(args []string) error {
	flags := ParseFlags(args, nil)
	c := client.New()
	ctx := context.Background()

	daemonRunning := c.IsDaemonRunning()
	if !daemonRunning {
		out := NewOutputWriterFromFlags(flags)
		return out.WriteStatus(nil, false)
	}

	status, err := c.GetStatus(ctx)
	if err != nil {
		return fmt.Errorf("failed to get status: %w", err)
	}

	out := NewOutputWriterFromFlags(flags)
	return out.WriteStatus(status, true)
}

func cmdPasswd(_ []string) error {
	c := client.New()
	ctx := context.Background()

	if !c.IsDaemonRunning() {
		return fmt.Errorf("daemon is not running, start it with: omnivault daemon start")
	}

	status, err := c.GetStatus(ctx)
	if err != nil {
		return fmt.Errorf("failed to get status: %w", err)
	}

	if !status.VaultExists {
		return fmt.Errorf("vault does not exist, run: omnivault init")
	}

	if status.Locked {
		return fmt.Errorf("vault is locked, unlock it first with: omnivault unlock")
	}

	// Prompt for current password
	fmt.Print("Enter current password: ")
	currentPassword, err := readPassword()
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	// Prompt for new password
	fmt.Print("Enter new password (min 8 chars): ")
	newPassword, err := readPassword()
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	if len(newPassword) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}

	// Confirm new password
	fmt.Print("Confirm new password: ")
	confirmPassword, err := readPassword()
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	if newPassword != confirmPassword {
		return fmt.Errorf("passwords do not match")
	}

	// Change password
	if err := c.ChangePassword(ctx, currentPassword, newPassword); err != nil {
		return fmt.Errorf("failed to change password: %w", err)
	}

	fmt.Println("Password changed successfully!")
	return nil
}

// readPassword reads a password from the terminal without echo.
func readPassword() (string, error) {
	fd := int(os.Stdin.Fd()) //nolint:gosec // G115: Fd() returns small values, overflow not possible

	// Try to read without echo
	if term.IsTerminal(fd) {
		password, err := term.ReadPassword(fd)
		fmt.Println() // Print newline after password
		if err != nil {
			return "", err
		}
		return string(password), nil
	}

	// Fallback for non-terminal (e.g., piped input)
	reader := bufio.NewReader(os.Stdin)
	password, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(password), nil
}
