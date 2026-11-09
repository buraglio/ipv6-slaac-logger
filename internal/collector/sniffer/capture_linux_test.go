//go:build linux

package sniffer

import (
	"os"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func auxCmsg(status uint32, tci uint16) []byte {
	var aux unix.TpacketAuxdata
	aux.Status = status
	aux.Vlan_tci = tci
	dl := int(unsafe.Sizeof(aux))
	b := make([]byte, unix.CmsgSpace(dl))
	h := (*unix.Cmsghdr)(unsafe.Pointer(&b[0]))
	h.Level = unix.SOL_PACKET
	h.Type = unix.PACKET_AUXDATA
	h.SetLen(unix.CmsgLen(dl))
	copy(b[unix.CmsgLen(0):], unsafe.Slice((*byte)(unsafe.Pointer(&aux)), dl))
	return b
}

func TestParseAuxVLAN(t *testing.T) {
	if got := parseAuxVLAN(auxCmsg(unix.TP_STATUS_VLAN_VALID, 0x2014)); got != 20 {
		t.Errorf("valid: got %d, want 20", got)
	}
	if got := parseAuxVLAN(auxCmsg(0, 0x2014)); got != 0 {
		t.Errorf("not valid: got %d, want 0", got)
	}
	if got := parseAuxVLAN(nil); got != 0 {
		t.Errorf("empty: got %d, want 0", got)
	}
}

func TestOpenRequiresPrivilege(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root")
	}
	if src, err := Open("lo"); err == nil {
		_ = src.Close()
		t.Fatal("expected error as non-root")
	}
}
