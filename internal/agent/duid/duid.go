// Package duid resolves the agent's DHCPv6 DUID and persists it so the
// identity stays stable across restarts and MAC randomization.
package duid

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/buraglio/ipv6-ra-logger/internal/dhcp6"
)

// Source says where the chosen DUID came from.
type Source string

const (
	SourceConfig    Source = "config"
	SourceOS        Source = "os"
	SourceState     Source = "state"
	SourceGenerated Source = "generated"
)

// StateFile is the persisted-DUID file name inside Options.StateDir.
const StateFile = "agent-state.json"

const (
	minDUIDLen = 4
	maxDUIDLen = 130
)

// ErrNotFound means a source holds no DUID.
var ErrNotFound = errors.New("duid: not found")

// Result is the resolved DUID and where it came from.
type Result struct {
	DUID   []byte
	Source Source
}

// Options configures Resolve. Zero-valued funcs take their defaults.
type Options struct {
	Configured  []byte
	StateDir    string
	OSDUID      func() ([]byte, error)
	HardwareMAC func() (net.HardwareAddr, error)
	Now         func() time.Time
	Log         *slog.Logger
}

type stateDoc struct {
	DUID   string `json:"duid"`
	Source string `json:"source"`
	Saved  string `json:"saved"`
}

func validLen(d []byte) bool { return len(d) >= minDUIDLen && len(d) <= maxDUIDLen }

// Resolve picks the DUID (config, OS, saved state, generated) and persists it.
func Resolve(o Options) (Result, error) {
	if o.OSDUID == nil {
		o.OSDUID = OSDUID
	}
	if o.HardwareMAC == nil {
		o.HardwareMAC = FirstHardwareMAC
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	statePath := filepath.Join(o.StateDir, StateFile)

	saved, savedSource, err := loadState(statePath, o)
	if err != nil {
		return Result{}, err
	}

	var res Result
	switch {
	case len(o.Configured) > 0:
		res = Result{DUID: o.Configured, Source: SourceConfig}
	default:
		if d, ok := tryOS(o); ok {
			res = Result{DUID: d, Source: SourceOS}
		} else if saved != nil {
			res = Result{DUID: saved, Source: SourceState}
		} else {
			mac, err := o.HardwareMAC()
			if err != nil {
				return Result{}, fmt.Errorf("duid: no source available: %w", err)
			}
			if len(mac) == 0 {
				return Result{}, errors.New("duid: no source available: no hardware address")
			}
			res = Result{DUID: dhcp6.NewDUIDLLT(mac, o.Now()), Source: SourceGenerated}
		}
	}

	if saved != nil && !bytes.Equal(saved, res.DUID) {
		o.Log.Warn("duid changed", "old", dhcp6.FormatHex(saved), "new", dhcp6.FormatHex(res.DUID), "source", string(res.Source))
	}

	if saved == nil || !bytes.Equal(saved, res.DUID) || (res.Source != SourceState && string(res.Source) != savedSource) {
		if err := writeState(statePath, o, res); err != nil {
			return Result{}, err
		}
	}
	return res, nil
}

func tryOS(o Options) ([]byte, bool) {
	d, err := o.OSDUID()
	switch {
	case err == nil:
		if !validLen(d) {
			o.Log.Warn("ignoring OS DUID with invalid length", "len", len(d))
			return nil, false
		}
		return d, true
	case errors.Is(err, ErrNotFound), errors.Is(err, os.ErrPermission):
		o.Log.Debug("OS DUID unavailable", "err", err)
	default:
		o.Log.Warn("OS DUID lookup failed", "err", err)
	}
	return nil, false
}

// loadState returns the saved DUID (nil if none or unusable). An existing but
// bad file is moved aside and logged at Error.
func loadState(path string, o Options) ([]byte, string, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", fmt.Errorf("duid: read state: %w", err)
	}
	var doc stateDoc
	d, perr := func() ([]byte, error) {
		if err := json.Unmarshal(b, &doc); err != nil {
			return nil, err
		}
		d, err := dhcp6.ParseHex(doc.DUID)
		if err != nil {
			return nil, err
		}
		if !validLen(d) {
			return nil, fmt.Errorf("saved DUID has invalid length %d", len(d))
		}
		return d, nil
	}()
	if perr == nil {
		return d, doc.Source, nil
	}
	backup := fmt.Sprintf("%s.corrupt-%d", path, o.Now().Unix())
	if err := os.Rename(path, backup); err != nil {
		return nil, "", fmt.Errorf("duid: back up corrupt state: %w", err)
	}
	o.Log.Error("saved DUID unusable; regenerating", "event", "duid.regenerated", "backup", backup, "err", perr)
	return nil, "", nil
}

func writeState(path string, o Options, r Result) error {
	if err := os.MkdirAll(o.StateDir, 0o700); err != nil {
		return fmt.Errorf("duid: create state dir: %w", err)
	}
	b, err := json.Marshal(stateDoc{
		DUID:   dhcp6.FormatHex(r.DUID),
		Source: string(r.Source),
		Saved:  o.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(o.StateDir, StateFile+".tmp-*")
	if err != nil {
		return fmt.Errorf("duid: write state: %w", err)
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil && !errors.Is(err, errors.ErrUnsupported) {
		tmp.Close()
		return fmt.Errorf("duid: write state: %w", err)
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return fmt.Errorf("duid: write state: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("duid: sync state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("duid: write state: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("duid: write state: %w", err)
	}
	// Best effort: persist the rename itself (unsupported on Windows).
	if d, err := os.Open(o.StateDir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}
