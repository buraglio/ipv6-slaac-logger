// Package config loads and validates the collector's TOML configuration.
package config

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/buraglio/ipv6-ra-logger/internal/collector/logger"
)

// Interface roles.
const (
	RoleListen    = "listen"
	RoleResponder = "responder"
	RoleSniff     = "sniff"
)

var (
	validRoles   = map[string]bool{RoleListen: true, RoleResponder: true, RoleSniff: true}
	validOutputs = map[string]bool{"unix": true, "tcp": true, "tls": true, "stdout": true}
)

type Config struct {
	StateDir      string      `toml:"state_dir"`
	ListenAddr    string      `toml:"listen_addr"`
	RetentionDays int         `toml:"retention_days"`
	Interfaces    []Interface `toml:"interface"`
	Registrar     Registrar   `toml:"registrar"`
	Vendor        Vendor      `toml:"vendor"`
	Sniffer       Sniffer     `toml:"sniffer"`
	Log           Log         `toml:"log"`
}

type Interface struct {
	Name     string   `toml:"name"`
	Roles    []string `toml:"roles"`
	Prefixes []string `toml:"prefixes"`
}

// Has reports whether the interface has role.
func (i Interface) Has(role string) bool { return slices.Contains(i.Roles, role) }

type Registrar struct {
	AllowedPrefixes []string `toml:"allowed_prefixes"`
	RelayPrefixes   []string `toml:"relay_prefixes"`
	TrustedRelays   []string `toml:"trusted_relays"` // IPv6 prefixes of relay agents whose Relay-Forward messages are accepted; empty = none
}

// Sniffer tunes the passive ND/RA sniffer (interfaces with the sniff role).
type Sniffer struct {
	IdleTimeout    string `toml:"idle_timeout"`    // default "24h", min 1m
	LogLinkLocal   bool   `toml:"log_link_local"`  // default false
	ProxyThreshold int    `toml:"proxy_threshold"` // default 32, min 2
	MaxEntries     int    `toml:"max_entries"`     // default 100000, min 100
	MaxRouters     int    `toml:"max_routers"`     // default 1000, min 10
}

// Idle returns IdleTimeout as a duration (0 if it does not parse).
func (s Sniffer) Idle() time.Duration {
	d, _ := time.ParseDuration(s.IdleTimeout)
	return d
}

type Vendor struct {
	EnterpriseNumber uint32 `toml:"enterprise_number"`
}

type Log struct {
	Facility string   `toml:"facility"`
	Outputs  []Output `toml:"output"`
}

type Output struct {
	Type       string `toml:"type"` // unix | tcp | tls | stdout
	Address    string `toml:"address"`
	CAFile     string `toml:"ca_file"`
	ServerName string `toml:"server_name"`
}

var errRetention = errors.New("config: retention_days must be at least 1 (omit it for the 400-day default)")

// Load reads, defaults and validates the file at path. Unknown keys are errors.
func Load(path string) (*Config, error) {
	var c Config
	md, err := toml.DecodeFile(path, &c)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if und := md.Undecoded(); len(und) > 0 {
		keys := make([]string, len(und))
		for i, k := range und {
			keys[i] = k.String()
		}
		return nil, fmt.Errorf("config: unknown keys: %s", strings.Join(keys, ", "))
	}
	if md.IsDefined("sniffer", "proxy_threshold") && c.Sniffer.ProxyThreshold == 0 {
		return nil, errors.New("config: sniffer.proxy_threshold must be at least 2")
	}
	if md.IsDefined("sniffer", "max_entries") && c.Sniffer.MaxEntries == 0 {
		return nil, errors.New("config: sniffer.max_entries must be at least 100")
	}
	if md.IsDefined("sniffer", "max_routers") && c.Sniffer.MaxRouters == 0 {
		return nil, errors.New("config: sniffer.max_routers must be at least 10")
	}
	// An explicit 0 is an error, not "use the default": it would otherwise
	// silently mean 400 days to someone who asked for no retention.
	if md.IsDefined("retention_days") && c.RetentionDays < 1 {
		return nil, errRetention
	}
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) applyDefaults() {
	if c.StateDir == "" {
		c.StateDir = "/var/lib/ra-logger"
	}
	if c.ListenAddr == "" {
		c.ListenAddr = "[::]:547"
	}
	if c.RetentionDays == 0 {
		c.RetentionDays = 400
	}
	if c.Sniffer.IdleTimeout == "" {
		c.Sniffer.IdleTimeout = "24h"
	}
	if c.Sniffer.ProxyThreshold == 0 {
		c.Sniffer.ProxyThreshold = 32
	}
	if c.Sniffer.MaxEntries == 0 {
		c.Sniffer.MaxEntries = 100000
	}
	if c.Sniffer.MaxRouters == 0 {
		c.Sniffer.MaxRouters = 1000
	}
	if c.Vendor.EnterpriseNumber == 0 {
		c.Vendor.EnterpriseNumber = 32473 // RFC 5612 documentation PEN; replace before production
	}
	if c.Log.Facility == "" {
		c.Log.Facility = "local5"
	}
	if len(c.Log.Outputs) == 0 {
		c.Log.Outputs = []Output{{Type: "unix", Address: "/dev/log"}}
	}
}

// Validate checks the configuration for errors.
func (c *Config) Validate() error {
	seen := map[string]bool{}
	for i, ifc := range c.Interfaces {
		if ifc.Name == "" {
			return fmt.Errorf("config: interface[%d]: name is required", i)
		}
		if seen[ifc.Name] {
			return fmt.Errorf("config: interface %s listed twice", ifc.Name)
		}
		seen[ifc.Name] = true
		for _, r := range ifc.Roles {
			if !validRoles[r] {
				return fmt.Errorf("config: interface %s: unknown role %q", ifc.Name, r)
			}
		}
		if ifc.Has(RoleResponder) && !ifc.Has(RoleListen) {
			return fmt.Errorf("config: interface %s: role %q requires %q", ifc.Name, RoleResponder, RoleListen)
		}
		if _, err := ParsePrefixes(ifc.Prefixes); err != nil {
			return fmt.Errorf("config: interface %s: %w", ifc.Name, err)
		}
	}
	if _, err := ParsePrefixes(c.Registrar.AllowedPrefixes); err != nil {
		return fmt.Errorf("config: registrar.allowed_prefixes: %w", err)
	}
	if _, err := ParsePrefixes(c.Registrar.RelayPrefixes); err != nil {
		return fmt.Errorf("config: registrar.relay_prefixes: %w", err)
	}
	if _, err := ParsePrefixes(c.Registrar.TrustedRelays); err != nil {
		return fmt.Errorf("config: registrar.trusted_relays: %w", err)
	}
	if _, err := logger.ParseFacility(c.Log.Facility); err != nil {
		return fmt.Errorf("config: log.facility: %w", err)
	}
	for i, o := range c.Log.Outputs {
		if !validOutputs[o.Type] {
			return fmt.Errorf("config: log.output[%d]: unknown type %q", i, o.Type)
		}
		if o.Type != "stdout" && o.Address == "" {
			return fmt.Errorf("config: log.output[%d]: address is required for type %q", i, o.Type)
		}
	}
	if c.RetentionDays < 1 {
		return errRetention
	}
	if _, err := time.ParseDuration(c.Sniffer.IdleTimeout); err != nil {
		return fmt.Errorf("config: sniffer.idle_timeout: %w", err)
	}
	if c.Sniffer.Idle() < time.Minute {
		return errors.New("config: sniffer.idle_timeout must be at least 1m")
	}
	if c.Sniffer.ProxyThreshold < 2 {
		return errors.New("config: sniffer.proxy_threshold must be at least 2")
	}
	if c.Sniffer.MaxEntries < 100 {
		return errors.New("config: sniffer.max_entries must be at least 100")
	}
	if c.Sniffer.MaxRouters < 10 {
		return errors.New("config: sniffer.max_routers must be at least 10")
	}
	return nil
}

// ParsePrefixes parses IPv6 prefixes and masks them to their network address.
func ParsePrefixes(ss []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, err
		}
		if !p.Addr().Is6() || p.Addr().Is4In6() {
			return nil, fmt.Errorf("%s is not an IPv6 prefix", s)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}
