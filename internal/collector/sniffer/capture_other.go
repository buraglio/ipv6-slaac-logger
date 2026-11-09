//go:build !linux

package sniffer

import "errors"

// Open is unsupported off Linux (AF_PACKET is Linux-only).
func Open(ifname string) (FrameSource, error) {
	return nil, errors.ErrUnsupported
}
