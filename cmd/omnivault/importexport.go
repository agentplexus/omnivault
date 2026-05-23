package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/plexusone/omnivault/internal/client"
	"github.com/plexusone/omnivault/internal/daemon"
)

func cmdExport(args []string) error {
	flags := ParseFlags(args, nil)

	prefix := ""
	if len(flags.Args) >= 1 {
		prefix = flags.Args[0]
	}

	c := client.New()
	ctx := context.Background()

	if !c.IsDaemonRunning() {
		return fmt.Errorf("daemon is not running, start it with: omnivault daemon start")
	}

	resp, err := c.Export(ctx, prefix)
	if err != nil {
		return err
	}

	// Determine output destination
	outputFile := flags.Get("output")
	var w io.Writer = os.Stdout

	if outputFile != "" {
		f, err := os.Create(outputFile)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer f.Close()
		w = f
	}

	// Output as JSON
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(resp); err != nil {
		return fmt.Errorf("failed to encode export: %w", err)
	}

	if outputFile != "" {
		fmt.Fprintf(os.Stderr, "Exported %d secret(s) to %s\n", resp.Count, outputFile)
	}

	return nil
}

func cmdImport(args []string) error {
	flags := ParseFlags(args, []string{"merge"})

	merge := flags.GetBool("merge")

	c := client.New()
	ctx := context.Background()

	if !c.IsDaemonRunning() {
		return fmt.Errorf("daemon is not running, start it with: omnivault daemon start")
	}

	// Determine input source
	var r io.Reader = os.Stdin

	if len(flags.Args) >= 1 {
		inputFile := flags.Args[0]
		f, err := os.Open(inputFile)
		if err != nil {
			return fmt.Errorf("failed to open input file: %w", err)
		}
		defer f.Close()
		r = f
	} else {
		// Check if stdin has data
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) != 0 {
			// stdin is a terminal, prompt for input
			fmt.Fprintln(os.Stderr, "Reading from stdin (paste JSON and press Ctrl+D when done)...")
		}
	}

	// Read and parse input
	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("failed to read input: %w", err)
	}

	// Try to parse as ExportResponse first (full export format)
	var exportResp daemon.ExportResponse
	if err := json.Unmarshal(data, &exportResp); err != nil {
		// Try parsing as array of secrets
		var secrets []daemon.ExportedSecret
		if err := json.Unmarshal(data, &secrets); err != nil {
			return fmt.Errorf("failed to parse import data: %w", err)
		}
		exportResp.Secrets = secrets
	}

	if len(exportResp.Secrets) == 0 {
		return fmt.Errorf("no secrets to import")
	}

	// Confirm import
	fmt.Fprintf(os.Stderr, "Import %d secret(s)? ", len(exportResp.Secrets))
	if merge {
		fmt.Fprintf(os.Stderr, "(merge mode - existing secrets will be skipped) ")
	} else {
		fmt.Fprintf(os.Stderr, "(existing secrets will be overwritten) ")
	}
	fmt.Fprint(os.Stderr, "[y/N]: ")

	reader := bufio.NewReader(os.Stdin)
	response, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	response = response[:len(response)-1] // remove newline
	if response != "y" && response != "Y" && response != "yes" && response != "Yes" {
		fmt.Fprintln(os.Stderr, "Cancelled")
		return nil
	}

	resp, err := c.Import(ctx, exportResp.Secrets, merge)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Imported: %d, Skipped: %d, Errors: %d\n",
		resp.Imported, resp.Skipped, resp.Errors)

	if resp.Errors > 0 {
		return fmt.Errorf("%d secret(s) failed to import", resp.Errors)
	}

	return nil
}
