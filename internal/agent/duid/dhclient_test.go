package duid

import (
	"bytes"
	"errors"
	"testing"
)

func TestParseDhclientDUID(t *testing.T) {
	want := []byte{0x00, 0x01, 0x00, 0x01, 0x1e, 0xa2, 0xda, 0x34, 0x00, 0x0c, 0x29, 0xb5, 0x7f, 0x8e}
	in := `default-duid "\000\001\000\001\036\242\3324\000\014)\265\177\216";`
	got, err := ParseDhclientDUID(in)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("got %x, %v; want %x", got, err, want)
	}

	two := "default-duid \"\\000\\003\";\nlease6 {\n}\n" + in + "\n"
	got, err = ParseDhclientDUID(two)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("two lines: got %x, %v", got, err)
	}

	if _, err := ParseDhclientDUID("lease6 {\n}\n"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("no line: err = %v, want ErrNotFound", err)
	}
	if _, err := ParseDhclientDUID(`default-duid "\000\001;`); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("unterminated: err = %v, want parse error", err)
	}
	got, err = ParseDhclientDUID(`default-duid "a\\b\"c";`)
	if err != nil || string(got) != `a\b"c` {
		t.Fatalf("escapes: got %q, %v", got, err)
	}
}
