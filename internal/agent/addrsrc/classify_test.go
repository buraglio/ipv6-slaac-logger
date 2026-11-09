package addrsrc

import (
	"testing"
	"time"

	"github.com/buraglio/ipv6-ra-logger/internal/dhcp6"
)

func TestClassifyDarwin(t *testing.T) {
	tests := []struct {
		flags uint32
		o     Origin
		s     State
	}{
		{0x440, OriginSLAAC, StateReady},
		{0xc0, OriginTemporary, StateReady},
		{0xd0, OriginTemporary, StateReady},
		{0x100, OriginDHCPv6, StateReady},
		{0x0, OriginStatic, StateReady},
		{0x2, OriginStatic, StateNotReady},
		{0x4, OriginStatic, StateDuplicate},
	}
	for _, tt := range tests {
		o, s := ClassifyDarwin(tt.flags)
		if o != tt.o || s != tt.s {
			t.Errorf("ClassifyDarwin(%#x) = (%s,%d), want (%s,%d)", tt.flags, o, s, tt.o, tt.s)
		}
	}
}

func TestClassifyLinux(t *testing.T) {
	tests := []struct {
		flags  uint32
		proto  uint8
		plen   uint8
		valid  uint32
		o      Origin
		s      State
		checkO bool
	}{
		{0x80, 0, 64, dhcp6.Infinity, OriginStatic, StateReady, true},
		{0x00, 2, 64, 86400, OriginSLAAC, StateReady, true},
		{0x01, 2, 64, 86400, OriginTemporary, StateReady, true},
		{0x00, 0, 128, 3600, OriginDHCPv6, StateReady, true},
		{0x00, 0, 64, 3600, OriginSLAAC, StateReady, true},
		{0x40, 2, 64, 3600, OriginSLAAC, StateNotReady, true},
		{0x04, 2, 64, 3600, OriginSLAAC, StateNotReady, true},
		{0x08, 2, 64, 3600, "", StateDuplicate, false},
		{0x00, 1, 128, 3600, OriginOther, StateReady, true},
		{0x00, 3, 64, 3600, OriginOther, StateReady, true},
		{0x00, 0, 128, dhcp6.Infinity, OriginSLAAC, StateReady, true},
	}
	for _, tt := range tests {
		o, s := ClassifyLinux(tt.flags, tt.proto, tt.plen, tt.valid)
		if s != tt.s || (tt.checkO && o != tt.o) {
			t.Errorf("ClassifyLinux(%#x,%d,%d,%d) = (%s,%d), want (%s,%d)", tt.flags, tt.proto, tt.plen, tt.valid, o, s, tt.o, tt.s)
		}
	}
}

func TestClassifyWindows(t *testing.T) {
	tests := []struct {
		po, so, dad int32
		o           Origin
		s           State
	}{
		{4, 4, 4, OriginSLAAC, StateReady},
		{4, 5, 3, OriginSLAAC, StateReady},
		{3, 3, 4, OriginDHCPv6, StateReady},
		{1, 1, 4, OriginStatic, StateReady},
		{4, 5, 1, OriginSLAAC, StateNotReady},
		{4, 5, 2, OriginSLAAC, StateDuplicate},
		{0, 0, 4, OriginOther, StateReady},
	}
	for _, tt := range tests {
		o, s := ClassifyWindows(tt.po, tt.so, tt.dad)
		if o != tt.o || s != tt.s {
			t.Errorf("ClassifyWindows(%d,%d,%d) = (%s,%d), want (%s,%d)", tt.po, tt.so, tt.dad, o, s, tt.o, tt.s)
		}
	}
}

func TestDarwinRemaining(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	if got := DarwinRemaining(0, now); got != dhcp6.Infinity {
		t.Errorf("0 => %d, want Infinity", got)
	}
	if got := DarwinRemaining(now.Unix()+100, now); got != 100 {
		t.Errorf("future => %d, want 100", got)
	}
	if got := DarwinRemaining(now.Unix()-5, now); got != 0 {
		t.Errorf("past => %d, want 0", got)
	}
}
