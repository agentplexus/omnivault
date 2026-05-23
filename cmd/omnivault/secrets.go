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

func cmdGet(args []string) error {
	flags := ParseFlags(args, nil)

	if len(flags.Args) < 1 {
		return fmt.Errorf("usage: omnivault get <path> [--format text|json|yaml|shell] [--field <name>]")
	}

	path := flags.Args[0]
	c := client.New()
	ctx := context.Background()

	if !c.IsDaemonRunning() {
		return fmt.Errorf("daemon is not running, start it with: omnivault daemon start")
	}

	secret, err := c.GetSecret(ctx, path)
	if err != nil {
		return err
	}

	// Check for expiry warnings
	if err := checkExpiryWarning(secret); err != nil {
		// Warning already printed to stderr, continue
	}

	// Output using the formatter
	out := NewOutputWriterFromFlags(flags)
	fieldName := flags.Get("field")
	return out.WriteSecret(secret, fieldName)
}

func cmdSet(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: omnivault set <path> [value]")
	}

	path := args[0]
	var value string

	if len(args) >= 2 {
		value = args[1]
	} else {
		// Prompt for value
		fmt.Print("Enter secret value: ")
		var err error
		fd := int(os.Stdin.Fd()) //nolint:gosec // G115: Fd() returns small values, overflow not possible
		if term.IsTerminal(fd) {
			// Read without echo for sensitive data
			bytes, err := term.ReadPassword(fd)
			fmt.Println()
			if err != nil {
				return fmt.Errorf("failed to read value: %w", err)
			}
			value = string(bytes)
		} else {
			reader := bufio.NewReader(os.Stdin)
			value, err = reader.ReadString('\n')
			if err != nil {
				return fmt.Errorf("failed to read value: %w", err)
			}
			value = strings.TrimSpace(value)
		}
	}

	c := client.New()
	ctx := context.Background()

	if !c.IsDaemonRunning() {
		return fmt.Errorf("daemon is not running, start it with: omnivault daemon start")
	}

	if err := c.SetSecret(ctx, path, value, nil, nil); err != nil {
		return err
	}

	fmt.Printf("Secret '%s' saved\n", path)
	return nil
}

func cmdList(args []string) error {
	flags := ParseFlags(args, []string{"metadata"})

	prefix := ""
	if len(flags.Args) >= 1 {
		prefix = flags.Args[0]
	}

	c := client.New()
	ctx := context.Background()

	if !c.IsDaemonRunning() {
		return fmt.Errorf("daemon is not running, start it with: omnivault daemon start")
	}

	resp, err := c.ListSecrets(ctx, prefix)
	if err != nil {
		return err
	}

	// Output using the formatter
	out := NewOutputWriterFromFlags(flags)
	showMetadata := flags.GetBool("metadata")
	return out.WriteList(resp, showMetadata)
}

func cmdSearch(args []string) error {
	flags := ParseFlags(args, []string{"regex"})

	if len(flags.Args) < 1 {
		return fmt.Errorf("usage: omnivault search <pattern> [--regex] [--format json|yaml]")
	}

	pattern := flags.Args[0]
	useRegex := flags.GetBool("regex")

	c := client.New()
	ctx := context.Background()

	if !c.IsDaemonRunning() {
		return fmt.Errorf("daemon is not running, start it with: omnivault daemon start")
	}

	resp, err := c.Search(ctx, pattern, useRegex)
	if err != nil {
		return err
	}

	out := NewOutputWriterFromFlags(flags)

	switch out.format {
	case FormatJSON, FormatYAML:
		if out.format == FormatJSON {
			return out.writeJSON(resp)
		}
		return out.writeYAML(resp)
	default:
		if resp.Count == 0 {
			fmt.Println("No secrets found matching pattern")
			return nil
		}

		for _, path := range resp.Paths {
			fmt.Println(path)
		}
		fmt.Printf("\n%d secret(s) found\n", resp.Count)
		return nil
	}
}

func cmdDelete(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: omnivault delete <path>")
	}

	path := args[0]
	c := client.New()
	ctx := context.Background()

	if !c.IsDaemonRunning() {
		return fmt.Errorf("daemon is not running, start it with: omnivault daemon start")
	}

	// Confirm deletion
	fmt.Printf("Delete secret '%s'? [y/N]: ", path)
	reader := bufio.NewReader(os.Stdin)
	response, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	response = strings.ToLower(strings.TrimSpace(response))
	if response != "y" && response != "yes" {
		fmt.Println("Cancelled")
		return nil
	}

	if err := c.DeleteSecret(ctx, path); err != nil {
		return err
	}

	fmt.Printf("Secret '%s' deleted\n", path)
	return nil
}
