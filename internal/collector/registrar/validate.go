package registrar

import "github.com/buraglio/ipv6-slaac-logger/internal/dhcp6"

// Reject reasons (the "reason" field of reg.reject events).
const (
	ReasonNotAddrReg     = "not_addr_reg_inform"
	ReasonClientID       = "client_id"
	ReasonServerID       = "server_id_present"
	ReasonORO            = "oro_present"
	ReasonIAAddr         = "ia_addr"
	ReasonScope          = "scope"
	ReasonSourceMismatch = "source_mismatch"
	ReasonPrefix         = "prefix_not_allowed"
	ReasonRateLimited    = "rate_limited"
	ReasonDeregForeign   = "dereg_foreign_duid"
	ReasonSuppressed     = "suppressed"
)

// MaxDUIDLen is the largest valid DUID: 2-byte type + 128 bytes (RFC 8415 §11.1).
const MaxDUIDLen = 130

// Valid holds the fields of a message that passed validation.
type Valid struct {
	DUID  []byte
	IA    dhcp6.IAAddress
	IARaw []byte // the IA Address option payload, echoed verbatim in the reply
}

// Validate applies RFC 9686 §5 server checks. It returns a reject reason, or "".
func Validate(req *Request, pol *PrefixPolicy) (Valid, string) {
	m := req.Msg
	if m == nil || m.Type != dhcp6.MsgAddrRegInform {
		return Valid{}, ReasonNotAddrReg
	}
	if m.Options.Count(dhcp6.OptClientID) != 1 {
		return Valid{}, ReasonClientID
	}
	cid, _ := m.Options.Get(dhcp6.OptClientID)
	if len(cid.Data) < 2 || len(cid.Data) > MaxDUIDLen {
		return Valid{}, ReasonClientID
	}
	if m.Options.Count(dhcp6.OptServerID) > 0 {
		return Valid{}, ReasonServerID
	}
	if m.Options.Count(dhcp6.OptORO) > 0 {
		return Valid{}, ReasonORO
	}
	if m.Options.Count(dhcp6.OptIAAddr) != 1 {
		return Valid{}, ReasonIAAddr
	}
	iaOpt, _ := m.Options.Get(dhcp6.OptIAAddr)
	if len(iaOpt.Data) != 24 { // RFC 9686 sends a bare IA Address; sub-options are not echoed
		return Valid{}, ReasonIAAddr
	}
	ia, err := dhcp6.ParseIAAddress(iaOpt.Data)
	if err != nil {
		return Valid{}, ReasonIAAddr
	}
	a := ia.Addr
	if a.Is4In6() || !a.IsGlobalUnicast() { // IsGlobalUnicast includes ULA
		return Valid{}, ReasonScope
	}
	if req.Via == ViaRelay {
		if req.Relay == nil || req.Relay.PeerAddr != a {
			return Valid{}, ReasonSourceMismatch
		}
	} else if req.Src.Addr().Unmap().WithZone("") != a {
		return Valid{}, ReasonSourceMismatch
	}
	if !pol.Allowed(req, a) {
		return Valid{}, ReasonPrefix
	}
	return Valid{DUID: cid.Data, IA: ia, IARaw: iaOpt.Data}, ""
}
