//go:build windows

package main

import (
	"os"
	"os/exec"
)

// setSysProcAttr sets Windows-specific process attributes for daemon detachment.
// On Windows, we don't have Setpgid, but the process will still run independently.
func setSysProcAttr(cmd *exec.Cmd) {
	// No special attributes needed on Windows for basic detachment
}

// signalProcess terminates a process on Windows.
// Windows doesn't have SIGTERM, so we use Process.Kill().
func signalProcess(pid int) error {
	process, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return process.Kill()
}
