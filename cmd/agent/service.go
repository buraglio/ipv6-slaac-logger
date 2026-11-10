package main

import (
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/kardianos/service"

	"github.com/buraglio/ipv6-slaac-logger/internal/agent/config"
)

//go:embed systemd.tmpl
var systemdTemplate string

const serviceName = "slaac-logger-agent"

// serviceConfig describes the service: it runs "agent -config <abs path> run".
func serviceConfig(cfgPath string) *service.Config {
	abs, err := absConfig(cfgPath)
	if err != nil {
		abs = cfgPath
	}
	c := &service.Config{
		Name:        serviceName,
		DisplayName: "IPv6 RA logger agent",
		Description: "Registers self-generated IPv6 addresses (RFC 9686)",
		Arguments:   []string{"-config", abs, "run"},
	}
	switch runtime.GOOS {
	case "linux":
		c.Option = service.KeyValue{"SystemdScript": systemdTemplate}
	case "windows":
		c.UserName = `NT AUTHORITY\LocalService`
	}
	return c
}

func serviceCmd(action, cfgPath string) error {
	svc, err := service.New(&program{}, serviceConfig(cfgPath))
	if err != nil {
		return err
	}
	if action == "install" && runtime.GOOS == "windows" {
		if err := prepareWindowsStateDir(cfgPath); err != nil {
			return err
		}
	}
	return service.Control(svc, action)
}

// prepareWindowsStateDir creates the state directory and lets LocalService write to it.
func prepareWindowsStateDir(cfgPath string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	dir := filepath.Clean(cfg.StateDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	out, err := exec.Command("icacls", dir, "/grant", `NT AUTHORITY\LocalService:(OI)(CI)M`).CombinedOutput()
	if err != nil {
		return fmt.Errorf("icacls %s: %w: %s", dir, err, out)
	}
	return nil
}
