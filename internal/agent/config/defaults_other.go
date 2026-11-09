//go:build !linux && !darwin && !windows

package config

// DefaultConfigPath is where the agent looks for its configuration.
const DefaultConfigPath = "/etc/ra-logger/agent.toml"

func defaultStateDir() string { return "/var/lib/ra-logger-agent" }
