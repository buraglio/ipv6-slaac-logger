//go:build darwin

package config

// DefaultConfigPath is where the agent looks for its configuration.
const DefaultConfigPath = "/Library/Application Support/ra-logger-agent/agent.toml"

func defaultStateDir() string { return "/Library/Application Support/ra-logger-agent" }
