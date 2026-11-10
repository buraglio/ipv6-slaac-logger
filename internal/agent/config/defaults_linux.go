//go:build linux

package config

// DefaultConfigPath is where the agent looks for its configuration.
const DefaultConfigPath = "/etc/slaac-logger/agent.toml"

func defaultStateDir() string { return "/var/lib/slaac-logger-agent" }
