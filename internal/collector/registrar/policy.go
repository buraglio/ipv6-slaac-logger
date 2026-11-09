package registrar

import "net/netip"

// PrefixPolicy decides whether an address is "appropriate to the link" (RFC 9686 §5).
type PrefixPolicy struct {
	OnLink  func(ifname string) []netip.Prefix // multicast: on-link prefixes of the arrival interface
	Relay   []netip.Prefix                     // relayed: addr and relay link-address must share one
	Unicast []netip.Prefix                     // direct unicast: explicit allow list, default deny
}

// Allowed reports whether addr may be registered for req.
func (p *PrefixPolicy) Allowed(req *Request, addr netip.Addr) bool {
	switch req.Via {
	case ViaMulticast:
		return p.OnLink != nil && containsAny(p.OnLink(req.IfName), addr)
	case ViaRelay:
		if req.Relay == nil {
			return false
		}
		for _, pf := range p.Relay {
			if pf.Contains(addr) && pf.Contains(req.Relay.LinkAddr) {
				return true
			}
		}
		return false
	case ViaUnicast:
		return containsAny(p.Unicast, addr)
	}
	return false
}

func containsAny(pfx []netip.Prefix, a netip.Addr) bool {
	for _, p := range pfx {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
