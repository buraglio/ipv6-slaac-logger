package sniffer

import (
	"testing"
)

func TestARPObservations(t *testing.T) {
	const link = "eth0"
	const mac = "aa:bb:cc:dd:ee:ff"
	const ip = "192.168.1.5"

	t.Run("arp reply yields arp-reply observation", func(t *testing.T) {
		obs := ARPObservations(arpFrame(t, nil, mac, ip), 0, link)
		if len(obs) != 1 {
			t.Fatalf("want 1 obs, got %d", len(obs))
		}
		o := obs[0]
		if o.Kind != KindARPReply {
			t.Errorf("kind = %q, want %q", o.Kind, KindARPReply)
		}
		if o.Addr.String() != ip {
			t.Errorf("addr = %q, want %q", o.Addr.String(), ip)
		}
		if o.MAC.String() != mac {
			t.Errorf("mac = %q, want %q", o.MAC.String(), mac)
		}
		if o.Link != link {
			t.Errorf("link = %q, want %q", o.Link, link)
		}
		if o.VLAN != 0 {
			t.Errorf("vlan = %d, want 0", o.VLAN)
		}
	})

	t.Run("arp request yields arp-request observation", func(t *testing.T) {
		req := arpFrameRaw(t, nil, 1, 0x0800, 1, mac, ip)
		obs := ARPObservations(req, 0, link)
		if len(obs) != 1 || obs[0].Kind != KindARPRequest {
			t.Fatalf("want 1 arp-request obs, got %v", obs)
		}
	})

	t.Run("gratuitous ARP (sender IP == target IP) yields garp", func(t *testing.T) {
		f := arpFrame(t, nil, mac, ip)
		// set target IP to same as sender IP (bytes 38-41)
		copy(f[38:42], f[28:32])
		obs := ARPObservations(f, 0, link)
		if len(obs) != 1 || obs[0].Kind != KindGARP {
			t.Fatalf("want 1 garp obs, got %v", obs)
		}
	})

	t.Run("ARP probe (sender IP 0.0.0.0) yields nil", func(t *testing.T) {
		probe := arpFrameRaw(t, nil, 1, 0x0800, 1, mac, "0.0.0.0")
		if obs := ARPObservations(probe, 0, link); len(obs) != 0 {
			t.Fatalf("want nil, got %v", obs)
		}
	})

	t.Run("non-IPv4-over-Ethernet ARP (hwtype != 1) yields nil", func(t *testing.T) {
		f := arpFrameRaw(t, nil, 2, 0x0800, 2, mac, ip)
		if obs := ARPObservations(f, 0, link); len(obs) != 0 {
			t.Fatalf("want nil, got %v", obs)
		}
	})

	t.Run("non-IPv4 protocol type yields nil", func(t *testing.T) {
		f := arpFrameRaw(t, nil, 1, 0x86dd, 2, mac, ip)
		if obs := ARPObservations(f, 0, link); len(obs) != 0 {
			t.Fatalf("want nil, got %v", obs)
		}
	})

	t.Run("VLAN-tagged ARP reply carries VLAN ID", func(t *testing.T) {
		obs := ARPObservations(arpFrame(t, []uint16{10}, mac, ip), 10, link)
		if len(obs) != 1 || obs[0].VLAN != 10 {
			t.Fatalf("want 1 obs with vlan=10, got %v", obs)
		}
	})

	t.Run("frame too short yields nil", func(t *testing.T) {
		if obs := ARPObservations(make([]byte, 10), 0, link); len(obs) != 0 {
			t.Fatalf("want nil, got %v", obs)
		}
	})

	t.Run("link-local IPv4 (169.254.x.x) is recorded", func(t *testing.T) {
		obs := ARPObservations(arpFrame(t, nil, mac, "169.254.1.1"), 0, link)
		if len(obs) != 1 {
			t.Fatalf("want 1 obs for APIPA addr, got %d", len(obs))
		}
	})
}
