// Command agent is the ipv6-ra-logger RFC 9686 registration client.
package main

import (
	"context"
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/kardianos/service"

	"github.com/buraglio/ipv6-ra-logger/internal/agent"
	"github.com/buraglio/ipv6-ra-logger/internal/agent/addrsrc"
	"github.com/buraglio/ipv6-ra-logger/internal/agent/config"
	"github.com/buraglio/ipv6-ra-logger/internal/agent/duid"
	"github.com/buraglio/ipv6-ra-logger/internal/agent/sched"
	"github.com/buraglio/ipv6-ra-logger/internal/agent/sender"
)

var version = "dev" // set with -ldflags "-X main.version=..."

const usage = `usage: agent [-config PATH] <command>

commands:
  run        run the agent in the foreground, or under the service manager
  install    install the agent as a system service
  uninstall  remove the system service
  start      start the installed service
  stop       stop the installed service
  list       show local IPv6 addresses and whether they would be registered (-json for JSON)
  version    print the version
`

func main() { os.Exit(realMain(os.Args)) }

// realMain runs the CLI and returns the exit code. Usage and errors go to stderr.
func realMain(args []string) int {
	code, out := runCLI(args, os.Stdout)
	if out != "" {
		fmt.Fprint(os.Stderr, out)
	}
	return code
}

// runCLI returns the exit code and the text to show on stderr.
func runCLI(args []string, stdout io.Writer) (int, string) {
	fs := flag.NewFlagSet("agent", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	cfgPath := fs.String("config", config.DefaultConfigPath, "configuration file")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() == 0 {
		return 2, usage
	}
	cmd, rest := fs.Arg(0), fs.Args()[1:]
	var err error
	switch cmd {
	case "run":
		err = runCmd(*cfgPath)
	case "install", "uninstall", "start", "stop":
		err = serviceCmd(cmd, *cfgPath)
	case "list":
		err = listCmd(rest, stdout)
	case "version":
		fmt.Fprintln(stdout, version)
	default:
		return 2, usage
	}
	if err != nil {
		return 1, "agent: " + err.Error() + "\n"
	}
	return 0, ""
}

// program adapts the agent to kardianos/service.
type program struct {
	run    func(ctx context.Context) error
	log    *slog.Logger
	cancel context.CancelFunc
	done   chan struct{}
}

func (p *program) Start(service.Service) error {
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	p.done = make(chan struct{})
	go func() {
		defer close(p.done)
		if err := p.run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			p.log.Error("agent stopped", "err", err)
			os.Exit(1)
		}
	}()
	return nil
}

func (p *program) Stop(service.Service) error {
	p.cancel()
	<-p.done
	return nil
}

func runCmd(cfgPath string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	prog := &program{}
	svc, err := service.New(prog, serviceConfig(cfgPath))
	if err != nil {
		return err
	}
	log, err := newLogger(svc, cfg.LogLevel)
	if err != nil {
		return err
	}
	prog.log = log

	res, err := duid.Resolve(duid.Options{Configured: cfg.DUIDBytes(), StateDir: cfg.StateDir, Log: log})
	if err != nil {
		return err
	}
	log.Info("agent started", "duid", fmt.Sprintf("%x", res.DUID), "duid_source", string(res.Source),
		"version", version, "collectors", cfg.Collectors, "multicast", cfg.Multicast)
	if len(cfg.Collectors) == 0 && cfg.Multicast == "auto" {
		log.Warn("no collectors configured; registering only where an RFC 9686 server answers on the link")
	}
	hostname := cfg.Hostname
	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	prog.run = func(ctx context.Context) error {
		tx := sender.NewTransport(546, log)
		defer tx.Close()
		a := &agent.Agent{
			Src:        addrsrc.New(),
			Filter:     addrsrc.IfFilter{Include: cfg.IncludeInterfaces, Exclude: cfg.ExcludeInterfaces},
			DUID:       res.DUID,
			Info:       sender.Info{Version: version, Hostname: hostname, PEN: cfg.EnterpriseNumber},
			Collectors: cfg.CollectorAddrs(),
			Multicast:  cfg.Multicast,
			Tx:         tx,
			Sched:      sched.New(sched.DefaultParams()),
			Log:        log,
		}
		return a.Run(ctx)
	}
	return svc.Run()
}

func parseLevel(s string) slog.Level {
	var l slog.Level
	if err := l.UnmarshalText([]byte(s)); err != nil {
		return slog.LevelInfo
	}
	return l
}

func newLogger(svc service.Service, level string) (*slog.Logger, error) {
	lvl := parseLevel(level)
	if runtime.GOOS == "windows" && !service.Interactive() {
		sl, err := svc.Logger(nil)
		if err != nil {
			return nil, err
		}
		return slog.New(newSvcHandler(sl, lvl)), nil
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})), nil
}

func absConfig(p string) (string, error) {
	if p == "" || strings.HasPrefix(p, "/dev/") {
		return p, nil
	}
	return filepath.Abs(p)
}
