//go:build !linux && !darwin && !windows

package duid

// OSDUID is unsupported on this platform.
func OSDUID() ([]byte, error) { return nil, ErrNotFound }
