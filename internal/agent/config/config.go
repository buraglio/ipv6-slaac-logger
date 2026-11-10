// Package config loads and validates the agent's TOML configuration.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"path"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/buraglio/ipv6-slaac-logger/internal/dhcp6"
)

const (
	defaultPort      = 547
	minHeartbeat     = time.Minute
	minDUIDLen       = 4
	maxDUIDLen       = 130 // RFC 8415 section 11.1
	defaultPEN       = 32473
	multicastAuto    = "auto"
	multicastAlways  = "always"
	defaultHeartbeat = time.Hour
)

// Config is the agent configuration.
type Config struct {
	StateDir          string   `toml:"state_dir"`
	DUID              string   `toml:"duid"`               // hex, optional
	Hostname          string   `toml:"hostname"`           // optional FQDN override
	Collectors        []string `toml:"collectors"`         // "2001:db8::53" or "[2001:db8::53]:547"
	Multicast         string   `toml:"multicast"`          // "auto" (default) | "always"
	Heartbeat         Duration `toml:"heartbeat"`          // default 1h, min 1m
	IncludeInterfaces []string `toml:"include_interfaces"` // path.Match globs; empty = all
	ExcludeInterfaces []string `toml:"exclude_interfaces"`
	EnterpriseNumber  uint32   `toml:"enterprise_number"` // default 32473
	LogLevel          string   `toml:"log_level"`         // debug|info|warn|error, default info

	addrs []netip.AddrPort
	duid  []byte
}

// Duration is a time.Duration decoded from a string such as "1h".
type Duration struct{ time.Duration }

// UnmarshalText implements encoding.TextUnmarshaler.
func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	if err != nil {
		return err
	}
	d.Duration = v
	return nil
}

// Default returns the configuration used when no file or key overrides it.
func Default() *Config {
	return &Config{
		StateDir:         defaultStateDir(),
		Multicast:        multicastAuto,
		Heartbeat:        Duration{defaultHeartbeat},
		EnterpriseNumber: defaultPEN,
		LogLevel:         "info",
	}
}

// Load reads, defaults and validates the file at path. A missing file yields
// the defaults; unknown keys are errors.
func Load(path string) (*Config, error) {
	c := Default()
	md, err := toml.DecodeFile(path, c)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return c, c.Validate()
		}
		return nil, fmt.Errorf("config: %w", err)
	}
	if und := md.Undecoded(); len(und) > 0 {
		keys := make([]string, len(und))
		for i, k := range und {
			keys[i] = k.String()
		}
		return nil, fmt.Errorf("config: unknown keys: %s", strings.Join(keys, ", "))
	}
	if c.StateDir == "" {
		c.StateDir = defaultStateDir()
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// Validate checks the configuration and caches parsed collector and DUID values.
func (c *Config) Validate() error {
	switch c.Multicast {
	case multicastAuto, multicastAlways:
	default:
		return fmt.Errorf("config: multicast must be %q or %q, got %q", multicastAuto, multicastAlways, c.Multicast)
	}
	if c.Heartbeat.Duration < minHeartbeat {
		return fmt.Errorf("config: heartbeat must be at least %s, got %s", minHeartbeat, c.Heartbeat.Duration)
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("config: log_level must be debug, info, warn or error, got %q", c.LogLevel)
	}
	c.addrs = c.addrs[:0]
	for _, s := range c.Collectors {
		ap, err := parseCollector(s)
		if err != nil {
			return fmt.Errorf("config: collectors: %w", err)
		}
		c.addrs = append(c.addrs, ap)
	}
	c.duid = nil
	if c.DUID != "" {
		b, err := dhcp6.ParseHex(c.DUID)
		if err != nil {
			return fmt.Errorf("config: duid: %w", err)
		}
		if len(b) < minDUIDLen || len(b) > maxDUIDLen {
			return fmt.Errorf("config: duid must be %d to %d bytes, got %d", minDUIDLen, maxDUIDLen, len(b))
		}
		c.duid = b
	}
	for name, globs := range map[string][]string{"include_interfaces": c.IncludeInterfaces, "exclude_interfaces": c.ExcludeInterfaces} {
		for _, g := range globs {
			if _, err := path.Match(g, ""); err != nil {
				return fmt.Errorf("config: %s: bad glob %q: %w", name, g, err)
			}
		}
	}
	return nil
}

func parseCollector(s string) (netip.AddrPort, error) {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return checkV6(ap, s)
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("%q is not an IPv6 address or [address]:port", s)
	}
	return checkV6(netip.AddrPortFrom(a, defaultPort), s)
}

func checkV6(ap netip.AddrPort, s string) (netip.AddrPort, error) {
	if !ap.Addr().Is6() || ap.Addr().Is4In6() {
		return netip.AddrPort{}, fmt.Errorf("%q is not an IPv6 address", s)
	}
	return ap, nil
}

// CollectorAddrs returns the parsed collectors; valid after Validate.
func (c *Config) CollectorAddrs() []netip.AddrPort { return c.addrs }

// DUIDBytes returns the configured DUID, or nil when unset; valid after Validate.
func (c *Config) DUIDBytes() []byte { return c.duid }
