package dhcp6

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"
)

func TestMessageRoundTrip(t *testing.T) {
	in := []byte{MsgAddrRegInform, 0x01, 0x02, 0x03, 0x00, 0x01, 0x00, 0x01, 0xaa}
	m, err := ParseMessage(in)
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}
	if m.Type != MsgAddrRegInform || m.XID != [3]byte{1, 2, 3} || len(m.Options) != 1 {
		t.Fatalf("unexpected message: %+v", m)
	}
	out, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, in) {
		t.Errorf("round trip = %x, want %x", out, in)
	}
}

func TestParseMessageErrors(t *testing.T) {
	if _, err := ParseMessage([]byte{MsgAddrRegInform, 1, 2}); !errors.Is(err, ErrTruncated) {
		t.Errorf("short: err = %v, want ErrTruncated", err)
	}
	relay := make([]byte, 34)
	relay[0] = MsgRelayForw
	if _, err := ParseMessage(relay); !errors.Is(err, ErrRelay) {
		t.Errorf("relay: err = %v, want ErrRelay", err)
	}
}

func TestRelayRoundTrip(t *testing.T) {
	inner := []byte{MsgAddrRegInform, 9, 9, 9}
	r := &RelayMessage{
		Type:     MsgRelayForw,
		HopCount: 1,
		LinkAddr: netip.MustParseAddr("2001:db8:10::1"),
		PeerAddr: netip.MustParseAddr("2001:db8:10::5"),
		Options:  Options{{Code: OptRelayMsg, Data: inner}},
	}
	b, err := r.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 34+4+len(inner) {
		t.Fatalf("len = %d", len(b))
	}
	got, err := ParseRelay(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != r.Type || got.HopCount != 1 || got.LinkAddr != r.LinkAddr || got.PeerAddr != r.PeerAddr {
		t.Fatalf("got %+v", got)
	}
	if o, ok := got.Options.Get(OptRelayMsg); !ok || !bytes.Equal(o.Data, inner) {
		t.Fatalf("relay message option = %+v", o)
	}
}

func TestParseRelayErrors(t *testing.T) {
	if _, err := ParseRelay(make([]byte, 33)); !errors.Is(err, ErrTruncated) {
		t.Errorf("short: err = %v, want ErrTruncated", err)
	}
	notRelay := make([]byte, 34)
	notRelay[0] = MsgAddrRegInform
	if _, err := ParseRelay(notRelay); err == nil {
		t.Error("non-relay type: expected error")
	}
}

func TestRelayMarshalRejectsNonIPv6(t *testing.T) {
	r := &RelayMessage{Type: MsgRelayRepl, PeerAddr: netip.MustParseAddr("2001:db8::1")}
	if _, err := r.Marshal(); err == nil {
		t.Fatal("expected error for zero LinkAddr")
	}
}

func FuzzParseMessage(f *testing.F) {
	f.Add([]byte{MsgAddrRegInform, 1, 2, 3, 0, 1, 0, 1, 0xaa})
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := ParseMessage(b)
		if err != nil {
			return
		}
		out, err := m.Marshal()
		if err != nil || !bytes.Equal(out, b) {
			t.Fatalf("round trip: %x, %v", out, err)
		}
	})
}

func FuzzParseRelay(f *testing.F) {
	seed := make([]byte, 38)
	seed[0] = MsgRelayForw
	seed[35] = byte(OptRelayMsg)
	f.Add(seed)
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := ParseRelay(b)
		if err != nil {
			return
		}
		out, err := r.Marshal()
		if err != nil || !bytes.Equal(out, b) {
			t.Fatalf("round trip: %x, %v", out, err)
		}
	})
}
