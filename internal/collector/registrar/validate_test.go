package registrar

import (
	"net/netip"
	"testing"

	"github.com/buraglio/ipv6-ra-logger/internal/dhcp6"
)

func TestValidate(t *testing.T) {
	good := inform(t, testAddr, testDUID, 7200)
	iaOpt, _ := good.Options.Get(dhcp6.OptIAAddr)
	other := netip.MustParseAddr("2001:db8:10::6")
	offLink := netip.MustParseAddr("2001:db8:99::5")
	outside := netip.MustParseAddr("2001:db9::5")
	ll := netip.MustParseAddr("fe80::1")
	mapped := netip.MustParseAddr("::ffff:192.0.2.1")

	notInform := inform(t, testAddr, testDUID, 7200)
	notInform.Type = dhcp6.MsgInformationRequest

	relayBadLink := relayReq(good, testAddr)
	relayBadLink.Relay.LinkAddr = netip.MustParseAddr("2001:db8:77::1")

	cases := []struct {
		name string
		req  *Request
		want string
	}{
		{"valid multicast", mcastReq(good, testAddr), ""},
		{"not addr-reg-inform", mcastReq(notInform, testAddr), ReasonNotAddrReg},
		{"no client id", mcastReq(without(good, dhcp6.OptClientID), testAddr), ReasonClientID},
		{"two client ids", mcastReq(with(good, dhcp6.Option{Code: dhcp6.OptClientID, Data: testDUID}), testAddr), ReasonClientID},
		{"client id too short", mcastReq(with(without(good, dhcp6.OptClientID), dhcp6.Option{Code: dhcp6.OptClientID, Data: []byte{1}}), testAddr), ReasonClientID},
		{"server id present", mcastReq(with(good, dhcp6.Option{Code: dhcp6.OptServerID, Data: []byte{0, 4, 1}}), testAddr), ReasonServerID},
		{"oro present", mcastReq(with(good, dhcp6.Option{Code: dhcp6.OptORO, Data: []byte{0, 0x94}}), testAddr), ReasonORO},
		{"no ia", mcastReq(without(good, dhcp6.OptIAAddr), testAddr), ReasonIAAddr},
		{"two ia", mcastReq(with(good, iaOpt), testAddr), ReasonIAAddr},
		{"malformed ia", mcastReq(with(without(good, dhcp6.OptIAAddr), dhcp6.Option{Code: dhcp6.OptIAAddr, Data: []byte{1, 2, 3}}), testAddr), ReasonIAAddr},
		{"link-local", mcastReq(inform(t, ll, testDUID, 7200), ll), ReasonScope},
		{"v4-mapped", mcastReq(inform(t, mapped, testDUID, 7200), mapped), ReasonScope},
		{"source mismatch", mcastReq(good, other), ReasonSourceMismatch},
		{"not on link", mcastReq(inform(t, offLink, testDUID, 7200), offLink), ReasonPrefix},
		{"unicast allowed", &Request{Msg: good, Src: netip.AddrPortFrom(testAddr, 546), Via: ViaUnicast}, ""},
		{"unicast outside", &Request{Msg: inform(t, outside, testDUID, 7200), Src: netip.AddrPortFrom(outside, 546), Via: ViaUnicast}, ReasonPrefix},
		{"relay ok", relayReq(good, testAddr), ""},
		{"relay peer mismatch", relayReq(good, other), ReasonSourceMismatch},
		{"relay link outside", relayBadLink, ReasonPrefix},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, reason := Validate(tc.req, testPolicy())
			if reason != tc.want {
				t.Fatalf("reason = %q, want %q", reason, tc.want)
			}
			if tc.want == "" {
				o, _ := tc.req.Msg.Options.Get(dhcp6.OptIAAddr)
				ia, _ := dhcp6.ParseIAAddress(o.Data)
				if v.IA.Addr != ia.Addr || len(v.DUID) == 0 || len(v.IARaw) != 24 {
					t.Fatalf("bad Valid: %+v", v)
				}
			}
		})
	}
}
