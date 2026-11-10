// Command regsend sends RFC 9686 ADDR-REG-INFORM (or Information-Request)
// messages, valid or deliberately malformed, for testing collectors.
// It is a developer tool and is not shipped in releases.
package main

import (
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/buraglio/ipv6-slaac-logger/internal/dhcp6"
)

func main() { os.Exit(realMain(os.Args[1:], os.Stdout, os.Stderr)) }

func realMain(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("regsend", flag.ContinueOnError)
	fs.SetOutput(stderr)
	mode := fs.String("mode", "inform", "inform (ADDR-REG-INFORM) or info (Information-Request for option 148)")
	iface := fs.String("iface", "", "interface for link-local destinations; also supplies the default DUID MAC")
	addrS := fs.String("addr", "", "address to register; also the UDP source (mode=inform)")
	iaS := fs.String("ia-addr", "", "IA address placed in the message (default: -addr)")
	toS := fs.String("to", "ff02::1:2", "destination address")
	port := fs.Int("port", dhcp6.ServerPort, "destination port")
	sport := fs.Int("sport", 0, "source port (0 = ephemeral; 546 needs privileges)")
	duidS := fs.String("duid", "", "client DUID in hex (default: DUID-LL from -iface MAC, else random DUID-UUID)")
	valid := fs.Uint64("valid", 86400, "valid lifetime (seconds)")
	pref := fs.Uint64("preferred", 14400, "preferred lifetime (seconds)")
	host := fs.String("host", "", "FQDN to include (option 39)")
	agent := fs.Bool("agent", false, "include the slaac-logger agent Vendor Class")
	pen := fs.Uint64("pen", 32473, "Vendor Class enterprise number")
	mutate := fs.String("mutate", "", "malform the message: no-client-id | server-id | oro | two-ia | truncate")
	wait := fs.Duration("wait", 2*time.Second, "how long to wait for a reply")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	usageErr := func(msg string) int { fmt.Fprintln(stderr, "regsend:", msg); return 2 }
	if *valid > math.MaxUint32 || *pref > math.MaxUint32 || *pen > math.MaxUint32 {
		return usageErr("-valid, -preferred and -pen must fit in 32 bits")
	}
	to, err := netip.ParseAddr(*toS)
	if err != nil {
		return usageErr("bad -to: " + err.Error())
	}
	zone := ""
	if to.IsLinkLocalMulticast() || to.IsLinkLocalUnicast() {
		if *iface == "" {
			return usageErr("-iface is required for a link-local destination")
		}
		zone = *iface
	}
	var mac net.HardwareAddr
	if *iface != "" {
		ifi, err := net.InterfaceByName(*iface)
		if err != nil {
			return usageErr(err.Error())
		}
		mac = ifi.HardwareAddr
	}
	duid, err := chooseDUID(*duidS, mac)
	if err != nil {
		return usageErr(err.Error())
	}
	xid, err := dhcp6.RandomXID()
	if err != nil {
		fmt.Fprintln(stderr, "regsend:", err)
		return 1
	}

	var pkt, iaData []byte
	var laddr *net.UDPAddr
	var wantType uint8
	switch *mode {
	case "inform":
		addr, err := netip.ParseAddr(*addrS)
		if err != nil {
			return usageErr("-addr is required in mode=inform: " + err.Error())
		}
		ia := addr
		if *iaS != "" {
			if ia, err = netip.ParseAddr(*iaS); err != nil {
				return usageErr("bad -ia-addr: " + err.Error())
			}
		}
		p := params{Addr: addr, IAAddr: ia, DUID: duid, Valid: uint32(*valid), Preferred: uint32(*pref),
			Host: *host, Agent: *agent, PEN: uint32(*pen), IfName: *iface, MAC: mac, Mutate: *mutate}
		if pkt, iaData, err = buildInform(p, xid); err != nil {
			return usageErr(err.Error())
		}
		laddr = &net.UDPAddr{IP: addr.AsSlice(), Port: *sport}
		wantType = dhcp6.MsgAddrRegReply
	case "info":
		if pkt, err = buildInfoRequest(duid, xid); err != nil {
			fmt.Fprintln(stderr, "regsend:", err)
			return 1
		}
		laddr = &net.UDPAddr{IP: net.IPv6unspecified, Port: *sport}
		wantType = dhcp6.MsgReply
	default:
		return usageErr("-mode must be inform or info")
	}

	conn, err := net.ListenUDP("udp6", laddr)
	if err != nil {
		fmt.Fprintln(stderr, "regsend:", err)
		return 1
	}
	defer conn.Close()
	dst := &net.UDPAddr{IP: to.AsSlice(), Port: *port, Zone: zone}
	if _, err := conn.WriteToUDP(pkt, dst); err != nil {
		fmt.Fprintln(stderr, "regsend: send:", err)
		return 1
	}
	fmt.Fprintf(stdout, "sent: mode=%s xid=%x to=%s bytes=%d\n", *mode, xid, dst, len(pkt))
	_ = conn.SetReadDeadline(time.Now().Add(*wait))
	buf := make([]byte, 65535)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			fmt.Fprintln(stdout, "no reply")
			return 3
		}
		fmt.Fprintln(stderr, "regsend: receive:", err)
		return 1
	}
	desc, ok := checkReply(buf[:n], wantType, xid, iaData)
	fmt.Fprintln(stdout, desc)
	if !ok {
		return 4
	}
	return 0
}

func chooseDUID(hexDUID string, mac net.HardwareAddr) ([]byte, error) {
	if hexDUID != "" {
		return dhcp6.ParseHex(hexDUID)
	}
	if len(mac) == 6 {
		return dhcp6.NewDUIDLL(mac), nil
	}
	var u [16]byte
	if _, err := rand.Read(u[:]); err != nil {
		return nil, err
	}
	return dhcp6.NewDUIDUUID(u), nil
}
