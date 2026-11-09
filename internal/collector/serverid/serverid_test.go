package serverid

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrCreateIsStable(t *testing.T) {
	dir := t.TempDir()
	a, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 18 || a[0] != 0 || a[1] != 4 {
		t.Fatalf("not a DUID-UUID: %x", a)
	}
	b, err := LoadOrCreate(dir)
	if err != nil || string(a) != string(b) {
		t.Fatalf("DUID changed across loads: %x vs %x (%v)", a, b, err)
	}
}

func TestCorruptFileIsAnError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, fileName), []byte("not hex"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreate(dir); err == nil {
		t.Fatal("corrupt server-duid silently replaced")
	}
}
