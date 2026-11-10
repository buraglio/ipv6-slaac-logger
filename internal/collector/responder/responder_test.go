package responder

import (
	"bytes"
	"testing"

	"github.com/buraglio/ipv6-slaac-logger/internal/dhcp6"
)

var sid = []byte{0, 4, 1, 2, 3, 4}

func infoReq(opts ...dhcp6.Option) *dhcp6.Message {
	return &dhcp6.Message{Type: dhcp6.MsgInformationRequest, XID: [3]byte{9, 8, 7}, Options: opts}
}

var (
	cid      = dhcp6.Option{Code: dhcp6.OptClientID, Data: []byte{0, 3, 0, 1, 1, 2, 3, 4, 5, 6}}
	oro148   = dhcp6.Option{Code: dhcp6.OptORO, Data: []byte{0, 23, 0, 0x94}}
	oroOther = dhcp6.Option{Code: dhcp6.OptORO, Data: []byte{0, 23}}
)

func TestRepliesWithOption148(t *testing.T) {
	r := &Responder{ServerID: sid}
	reply := r.Handle(infoReq(cid, oro148))
	if reply == nil || reply.Type != dhcp6.MsgReply || reply.XID != [3]byte{9, 8, 7} {
		t.Fatalf("reply = %+v", reply)
	}
	if _, ok := reply.Options.Get(dhcp6.OptAddrRegEnable); !ok {
		t.Fatal("option 148 missing")
	}
	if s, ok := reply.Options.Get(dhcp6.OptServerID); !ok || !bytes.Equal(s.Data, sid) {
		t.Fatal("server id missing")
	}
	if c, ok := reply.Options.Get(dhcp6.OptClientID); !ok || !bytes.Equal(c.Data, cid.Data) {
		t.Fatal("client id not echoed")
	}
	if _, err := reply.Marshal(); err != nil {
		t.Fatal(err)
	}
}

func TestIgnores(t *testing.T) {
	r := &Responder{ServerID: sid}
	cases := map[string]*dhcp6.Message{
		"no oro":           infoReq(cid),
		"oro without 148":  infoReq(cid, oroOther),
		"odd-length oro":   infoReq(cid, dhcp6.Option{Code: dhcp6.OptORO, Data: []byte{0, 0x94, 0}[:1]}),
		"other server id":  infoReq(cid, oro148, dhcp6.Option{Code: dhcp6.OptServerID, Data: []byte{0, 4, 9}}),
		"not info-request": {Type: dhcp6.MsgAddrRegInform, Options: dhcp6.Options{cid, oro148}},
		"nil":              nil,
	}
	for name, m := range cases {
		if r.Handle(m) != nil {
			t.Errorf("%s: unexpected reply", name)
		}
	}
	if r.Handle(infoReq(cid, oro148, dhcp6.Option{Code: dhcp6.OptServerID, Data: sid})) == nil {
		t.Error("request addressed to our server id was ignored")
	}
}
