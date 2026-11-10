package config

import (
	"path/filepath"
	"testing"
)

func TestExampleConfigLoads(t *testing.T) {
	c, err := Load(filepath.Join("..", "..", "..", "packaging", "collector.example.toml"))
	if err != nil {
		t.Fatalf("shipped example config is invalid: %v", err)
	}
	if c.Vendor.EnterpriseNumber != 67611 || len(c.Interfaces) != 1 {
		t.Fatalf("unexpected example config: %+v", c)
	}
}
