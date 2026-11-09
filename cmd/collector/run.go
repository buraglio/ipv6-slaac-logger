//go:build !windows

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/buraglio/ipv6-ra-logger/internal/collector/config"
	"github.com/buraglio/ipv6-ra-logger/internal/collector/listener"
	"github.com/buraglio/ipv6-ra-logger/internal/collector/logger"
	"github.com/buraglio/ipv6-ra-logger/internal/collector/netinfo"
	"github.com/buraglio/ipv6-ra-logger/internal/collector/recorder"
	"github.com/buraglio/ipv6-ra-logger/internal/collector/registrar"
	"github.com/buraglio/ipv6-ra-logger/internal/collector/responder"
	"github.com/buraglio/ipv6-ra-logger/internal/collector/serverid"
	"github.com/buraglio/ipv6-ra-logger/internal/collector/sniffer"
	"github.com/buraglio/ipv6-ra-logger/internal/collector/store"
	"github.com/buraglio/ipv6-ra-logger/internal/event"
)

// run starts every collector component and blocks until ctx is cancelled.
// ready, if non-nil, receives the bound UDP address once listening.
func run(ctx context.Context, cfg *config.Config, log *slog.Logger, ready func(net.Addr)) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if err := os.MkdirAll(cfg.StateDir, 0o750); err != nil {
		return err
	}
	st, err := store.Open(filepath.Join(cfg.StateDir, "ra-logger.db"))
	if err != nil {
		return err
	}
	defer st.Close()
	sid, err := serverid.LoadOrCreate(cfg.StateDir)
	if err != nil {
		return err
	}
	fac, err := logger.ParseFacility(cfg.Log.Facility)
	if err != nil {
		return err
	}
	sinks, cursors, err := buildSinks(cfg.Log, fac)
	if err != nil {
		return err
	}
	defer func() {
		for _, s := range sinks {
			s.Close()
		}
	}()
	rec := &recorder.Recorder{Store: st, Fallback: sinks, Log: log}

	static := map[string][]netip.Prefix{}
	var listenIfaces []string
	var sniffIfaces []string
	respIfaces := map[int]bool{}
	listenIdx := map[int]bool{}
	for _, ifc := range cfg.Interfaces {
		pfx, err := config.ParsePrefixes(ifc.Prefixes)
		if err != nil {
			return err
		}
		static[ifc.Name] = pfx
		if ifc.Has(config.RoleListen) {
			ifi, err := net.InterfaceByName(ifc.Name)
			if err != nil {
				return err
			}
			listenIfaces = append(listenIfaces, ifc.Name)
			listenIdx[ifi.Index] = true
		}
		if ifc.Has(config.RoleResponder) {
			ifi, err := net.InterfaceByName(ifc.Name)
			if err != nil {
				return err
			}
			respIfaces[ifi.Index] = true
		}
		if ifc.Has(config.RoleSniff) {
			// The interface may not exist yet: each Sniffer retries its own open.
			sniffIfaces = append(sniffIfaces, ifc.Name)
		}
	}
	allowed, err := config.ParsePrefixes(cfg.Registrar.AllowedPrefixes)
	if err != nil {
		return err
	}
	relay, err := config.ParsePrefixes(cfg.Registrar.RelayPrefixes)
	if err != nil {
		return err
	}
	onLink := netinfo.NewPrefixes(static, 30*time.Second)
	trusted, err := config.ParsePrefixes(cfg.Registrar.TrustedRelays)
	if err != nil {
		return err
	}
	if len(relay) > 0 && len(trusted) == 0 {
		log.Warn("registrar.relay_prefixes is set but registrar.trusted_relays is empty; relayed registrations will be dropped")
	}
	reg := registrar.New(st, rec, &registrar.PrefixPolicy{OnLink: onLink.For, Relay: relay, Unicast: allowed}, sid, cfg.Vendor.EnterpriseNumber)
	reg.Log = log

	tcfg := sniffer.DefaultTrackerConfig()
	tcfg.Idle, tcfg.LogLinkLocal = cfg.Sniffer.Idle(), cfg.Sniffer.LogLinkLocal
	tcfg.ProxyThreshold, tcfg.MaxEntries = cfg.Sniffer.ProxyThreshold, cfg.Sniffer.MaxEntries
	tracker := sniffer.NewTracker(tcfg, rec, time.Now, log)
	rcfg := sniffer.DefaultRAMonitorConfig()
	rcfg.Flush, rcfg.Idle, rcfg.MaxRouters = tcfg.Flush, tcfg.Idle, cfg.Sniffer.MaxRouters
	ramon := sniffer.NewRAMonitor(rcfg, rec, time.Now, log)
	sightings, err := st.Sightings(ctx, false)
	if err != nil {
		return err
	}
	tracker.Load(sightings)
	// Only routers seen within idle_timeout are warm-loaded; older rows stay
	// in the database until retention removes them.
	routers, err := st.Routers(ctx, time.Now().Add(-rcfg.Idle))
	if err != nil {
		return err
	}
	ramon.Load(routers)
	reg.Sightings = tracker
	sniffers := make([]*sniffer.Sniffer, len(sniffIfaces))
	for i, name := range sniffIfaces {
		sniffers[i] = &sniffer.Sniffer{Link: name, Tracker: tracker, RA: ramon, Log: log}
	}
	disp := &listener.Dispatcher{Reg: reg, Log: log, TrustedRelays: trusted, ListenIfaces: listenIdx}
	if len(respIfaces) > 0 {
		disp.Resp = &responder.Responder{ServerID: sid}
		disp.ResponderIfaces = respIfaces
	}

	conn, err := listener.Listen(ctx, cfg.ListenAddr, listenIfaces, log)
	if err != nil {
		return err
	}
	if ready != nil {
		ready(conn.LocalAddr())
	}

	var wg sync.WaitGroup
	for i, s := range sinks {
		f := &logger.Forwarder{Name: cursors[i], Src: st, Sink: s, Log: log}
		wg.Go(func() { f.Run(ctx) })
	}
	for _, sn := range sniffers {
		wg.Go(func() { sn.Run(ctx) })
	}
	wg.Go(func() { periodic(ctx, time.Minute, func() { reg.Sweep(ctx) }) })
	wg.Go(func() {
		periodic(ctx, 30*time.Second, func() {
			tracker.Tick(ctx)
			ramon.Tick(ctx)
		})
	})
	wg.Go(func() {
		periodic(ctx, 24*time.Hour, func() {
			cutoff := time.Now().AddDate(0, 0, -cfg.RetentionDays)
			n, err := st.PurgeEventsBefore(ctx, cutoff)
			if err != nil {
				log.Error("retention sweep failed", "err", err)
				return
			}
			sightings, routers, err := st.PurgeStaleBefore(ctx, cutoff)
			if err != nil {
				log.Error("retention sweep failed", "err", err)
				return
			}
			log.Info("retention sweep", "purged", n, "purged_sightings", sightings, "purged_routers", routers)
		})
	})
	wg.Go(func() {
		periodic(ctx, 15*time.Minute, func() {
			e := event.New(event.Stats, time.Now())
			var sc []map[string]uint64
			for _, sn := range sniffers {
				sc = append(sc, sn.Counters())
			}
			var dup []string
			e.Counters, dup = mergeCounters(
				reg.Stats.Snapshot(),
				map[string]uint64{"dropped": disp.Dropped.Load()},
				tracker.Counters(), ramon.Counters(), sumCounters(sc...))
			if len(dup) > 0 {
				log.Error("stats counter name collision", "names", dup)
			}
			_ = rec.Record(ctx, store.Change{Events: []event.Event{e}})
		})
	})

	log.Info("collector started", "listen", conn.LocalAddr().String(), "interfaces", listenIfaces, "version", version)
	err = conn.Serve(ctx, disp)
	cancel()
	wg.Wait()
	// Write the last_seen of repeat sightings and routers still waiting for
	// their flush interval, before the deferred store and sink closes.
	fctx := context.WithoutCancel(ctx)
	tracker.Flush(fctx)
	ramon.Flush(fctx)
	return err
}

// buildSinks returns one sink per output plus a stable cursor name for each.
func buildSinks(lc config.Log, fac logger.Facility) ([]logger.Sink, []string, error) {
	host, _ := os.Hostname()
	var sinks []logger.Sink
	var cursors []string
	for _, o := range lc.Outputs {
		var s logger.Sink
		switch o.Type {
		case "unix":
			s = logger.NewUnixSink(o.Address, fac)
		case "tcp":
			s = logger.NewTCPSink(o.Address, fac, host)
		case "tls":
			conf := &tls.Config{ServerName: o.ServerName, MinVersion: tls.VersionTLS12}
			if conf.ServerName == "" {
				h, _, err := net.SplitHostPort(o.Address)
				if err != nil {
					return nil, nil, fmt.Errorf("tls output %q: %w", o.Address, err)
				}
				conf.ServerName = h
			}
			if o.CAFile != "" {
				pem, err := os.ReadFile(o.CAFile)
				if err != nil {
					return nil, nil, err
				}
				pool := x509.NewCertPool()
				if !pool.AppendCertsFromPEM(pem) {
					return nil, nil, fmt.Errorf("tls output: no certificates in %s", o.CAFile)
				}
				conf.RootCAs = pool
			}
			s = logger.NewTLSSink(o.Address, conf, fac, host)
		case "stdout":
			s = logger.NewWriterSink("stdout", os.Stdout)
		default:
			return nil, nil, fmt.Errorf("unknown output type %q", o.Type)
		}
		sinks = append(sinks, s)
		cursors = append(cursors, o.Type+":"+o.Address)
	}
	return sinks, cursors, nil
}

// sumCounters adds counter maps that share names, as the per-interface
// sniffers' do.
func sumCounters(ms ...map[string]uint64) map[string]uint64 {
	out := map[string]uint64{}
	for _, m := range ms {
		for k, v := range m {
			out[k] += v
		}
	}
	return out
}

// mergeCounters combines the counter maps of distinct components into one map.
// A name present in more than one map is a bug: the later value wins and the
// name is returned in dup so the caller can report it.
func mergeCounters(ms ...map[string]uint64) (out map[string]uint64, dup []string) {
	out = map[string]uint64{}
	for _, m := range ms {
		for k, v := range m {
			if _, ok := out[k]; ok {
				dup = append(dup, k)
			}
			out[k] = v
		}
	}
	slices.Sort(dup)
	return out, dup
}

func periodic(ctx context.Context, every time.Duration, fn func()) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			fn()
		}
	}
}
