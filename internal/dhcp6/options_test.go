package dhcp6

import (
	"bytes"
	"errors"
	"testing"
)

func TestParseOptionsRoundTrip(t *testing.T) {
	in := []byte{
		0x00, 0x01, 0x00, 0x02, 0xaa, 0xbb, // Client ID, 2 bytes
		0x00, 0x94, 0x00, 0x00, // option 148, empty
	}
	opts, err := ParseOptions(in)
	if err != nil {
		t.Fatalf("ParseOptions: %v", err)
	}
	if len(opts) != 2 {
		t.Fatalf("got %d options, want 2", len(opts))
	}
	if opts[0].Code != OptClientID || !bytes.Equal(opts[0].Data, []byte{0xaa, 0xbb}) {
		t.Errorf("opts[0] = %+v", opts[0])
	}
	if opts[1].Code != OptAddrRegEnable || len(opts[1].Data) != 0 {
		t.Errorf("opts[1] = %+v", opts[1])
	}
	out, err := opts.AppendTo(nil)
	if err != nil {
		t.Fatalf("AppendTo: %v", err)
	}
	if !bytes.Equal(out, in) {
		t.Errorf("round trip = %x, want %x", out, in)
	}
}

func TestParseOptionsTruncated(t *testing.T) {
	cases := map[string][]byte{
		"short header": {0x00},
		"short data":   {0x00, 0x01, 0x00, 0x05, 0xaa},
	}
	for name, in := range cases {
		if _, err := ParseOptions(in); !errors.Is(err, ErrTruncated) {
			t.Errorf("%s: err = %v, want ErrTruncated", name, err)
		}
	}
}

func TestParseOptionsCopiesData(t *testing.T) {
	in := []byte{0x00, 0x01, 0x00, 0x01, 0xaa}
	opts, err := ParseOptions(in)
	if err != nil {
		t.Fatal(err)
	}
	in[4] = 0xff
	if opts[0].Data[0] != 0xaa {
		t.Fatal("option data aliases the input buffer")
	}
}

func TestOptionsGetCount(t *testing.T) {
	opts := Options{{Code: OptIAAddr}, {Code: OptClientID, Data: []byte{1}}, {Code: OptIAAddr}}
	if n := opts.Count(OptIAAddr); n != 2 {
		t.Errorf("Count(IAAddr) = %d, want 2", n)
	}
	if o, ok := opts.Get(OptClientID); !ok || o.Data[0] != 1 {
		t.Errorf("Get(ClientID) = %+v, %v", o, ok)
	}
	if _, ok := opts.Get(OptServerID); ok {
		t.Error("Get(ServerID) found an option that is not present")
	}
}

func TestAppendToRejectsOversizeOption(t *testing.T) {
	opts := Options{{Code: OptClientID, Data: make([]byte, 0x10000)}}
	if _, err := opts.AppendTo(nil); err == nil {
		t.Fatal("expected an error for a 65536-byte option")
	}
}

func FuzzParseOptions(f *testing.F) {
	f.Add([]byte{0x00, 0x01, 0x00, 0x02, 0xaa, 0xbb})
	f.Add([]byte{0x00, 0x94, 0x00, 0x00})
	f.Fuzz(func(t *testing.T, b []byte) {
		opts, err := ParseOptions(b)
		if err != nil {
			return
		}
		out, err := opts.AppendTo(nil)
		if err != nil {
			t.Fatalf("AppendTo after successful parse: %v", err)
		}
		if !bytes.Equal(out, b) {
			t.Fatalf("round trip mismatch: %x != %x", out, b)
		}
	})
}
