package sender

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/buraglio/ipv6-slaac-logger/internal/agent/addrsrc"
	"github.com/buraglio/ipv6-slaac-logger/internal/dhcp6"
)

// DestMulticast is the Dest.Name of the All_DHCP_Relay_Agents_and_Servers destination.
const DestMulticast = "multicast"

// Dest is a send destination.
type Dest struct {
	Name string
	To   netip.AddrPort // carries the zone for multicast
}

// UnicastDest returns a unicast destination.
func UnicastDest(ap netip.AddrPort) Dest { return Dest{Name: "unicast:" + ap.String(), To: ap} }

// MulticastDest returns ff02::1:2%ifname port 547.
func MulticastDest(ifname string) Dest {
	return Dest{
		Name: DestMulticast,
		To:   netip.AddrPortFrom(dhcp6.AllRelayAgentsAndServers.WithZone(ifname), dhcp6.ServerPort),
	}
}

// Reply is an ADDR-REG-REPLY matched to a registered address.
type Reply struct {
	Local netip.Addr
	From  netip.Addr
	XID   [3]byte
}

// ErrAddrGone means the address is no longer assigned to the host.
var ErrAddrGone = errors.New("sender: address no longer assigned")

type sock struct {
	conn *net.UDPConn
	addr netip.Addr
	done chan struct{} // closed by Drop or Close; interrupts error backoff
	// readFrom is the datagram source; tests replace it to inject errors.
	readFrom func([]byte) (int, netip.AddrPort, error)
}

func (s *sock) shutdown() {
	close(s.done)
	s.conn.Close()
}

// Transport owns one UDP socket per registered address.
type Transport struct {
	ClientPort int // 546; tests use 0
	Log        *slog.Logger

	mu      sync.Mutex
	socks   map[netip.Addr]*sock
	replies chan Reply
	wg      sync.WaitGroup
	closed  bool
}

// NewTransport returns a Transport that binds clientPort (falling back to an
// ephemeral port when it is busy).
func NewTransport(clientPort int, log *slog.Logger) *Transport {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Transport{
		ClientPort: clientPort,
		Log:        log,
		socks:      map[netip.Addr]*sock{},
		replies:    make(chan Reply, 64),
	}
}

// Replies yields matched ADDR-REG-REPLY messages.
func (t *Transport) Replies() <-chan Reply { return t.replies }

func (t *Transport) bind(a addrsrc.Addr, port int) (*net.UDPConn, error) {
	ip := a.Addr.WithZone("")
	if ip.IsLinkLocalUnicast() && a.IfName != "" {
		ip = ip.WithZone(a.IfName)
	}
	lc := net.ListenConfig{Control: reuse}
	pc, err := lc.ListenPacket(context.Background(), "udp6", netip.AddrPortFrom(ip, uint16(port)).String())
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}

func (t *Transport) get(a addrsrc.Addr) (*sock, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil, net.ErrClosed
	}
	key := a.Addr.WithZone("")
	if s, ok := t.socks[key]; ok {
		return s, nil
	}
	conn, err := t.bind(a, t.ClientPort)
	if err != nil {
		if isAddrNotAvail(err) {
			return nil, fmt.Errorf("%w: %v", ErrAddrGone, err)
		}
		t.Log.Debug("client port bind failed, using ephemeral port", "addr", key, "port", t.ClientPort, "err", err)
		if conn, err = t.bind(a, 0); err != nil {
			if isAddrNotAvail(err) {
				return nil, fmt.Errorf("%w: %v", ErrAddrGone, err)
			}
			return nil, err
		}
	}
	s := &sock{conn: conn, addr: key, done: make(chan struct{}), readFrom: conn.ReadFromUDPAddrPort}
	t.socks[key] = s
	t.wg.Add(1)
	go t.read(s)
	return s, nil
}

// Send transmits payload to d from a socket bound to a.Addr.
func (t *Transport) Send(a addrsrc.Addr, d Dest, payload []byte) error {
	s, err := t.get(a)
	if err != nil {
		return err
	}
	if _, err := s.conn.WriteToUDPAddrPort(payload, d.To); err != nil {
		if isAddrNotAvail(err) {
			return fmt.Errorf("%w: %v", ErrAddrGone, err)
		}
		return err
	}
	return nil
}

func (t *Transport) read(s *sock) {
	defer t.wg.Done()
	buf := make([]byte, 2048)
	var errs int
	backoff := 100 * time.Millisecond
	for {
		n, from, err := s.readFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if errs == 0 {
				t.Log.Debug("read error", "addr", s.addr, "err", err)
			}
			errs++
			timer := time.NewTimer(backoff)
			select {
			case <-s.done:
				timer.Stop()
				return
			case <-timer.C:
			}
			backoff = min(backoff*2, 5*time.Second)
			continue
		}
		if errs > 0 {
			t.Log.Debug("read recovered", "addr", s.addr, "errors", errs)
			errs, backoff = 0, 100*time.Millisecond
		}
		m, err := dhcp6.ParseMessage(buf[:n])
		if err != nil || m.Type != dhcp6.MsgAddrRegReply {
			continue
		}
		o, ok := m.Options.Get(dhcp6.OptIAAddr)
		if !ok {
			continue
		}
		ia, err := dhcp6.ParseIAAddress(o.Data)
		if err != nil || ia.Addr != s.addr {
			continue
		}
		r := Reply{Local: s.addr, From: from.Addr().WithZone(""), XID: m.XID}
		select {
		case t.replies <- r:
		default:
			t.Log.Debug("reply channel full, dropping", "addr", s.addr)
		}
	}
}

// Drop closes the socket bound to addr.
func (t *Transport) Drop(addr netip.Addr) {
	addr = addr.WithZone("")
	t.mu.Lock()
	s := t.socks[addr]
	delete(t.socks, addr)
	t.mu.Unlock()
	if s != nil {
		s.shutdown()
	}
}

// BoundPort returns the local port of addr's socket, or 0.
func (t *Transport) BoundPort(addr netip.Addr) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	if s := t.socks[addr.WithZone("")]; s != nil {
		return s.conn.LocalAddr().(*net.UDPAddr).Port
	}
	return 0
}

// Close closes every socket and waits for the readers to exit.
func (t *Transport) Close() error {
	t.mu.Lock()
	t.closed = true
	socks := t.socks
	t.socks = map[netip.Addr]*sock{}
	t.mu.Unlock()
	for _, s := range socks {
		s.shutdown()
	}
	t.wg.Wait()
	return nil
}
