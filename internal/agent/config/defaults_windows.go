//go:build windows

package config

import (
	"os"
	"path/filepath"
)

func programData() string {
	if d := os.Getenv("ProgramData"); d != "" {
		return d
	}
	return `C:\ProgramData`
}

// DefaultConfigPath is where the agent looks for its configuration.
var DefaultConfigPath = filepath.Join(programData(), "ra-logger-agent", "agent.toml")

func defaultStateDir() string { return filepath.Join(programData(), "ra-logger-agent") }
