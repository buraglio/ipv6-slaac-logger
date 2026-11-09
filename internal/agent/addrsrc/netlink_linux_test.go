package addrsrc

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// nlAttr encodes one rtattr, padded to 4 bytes.
func nlAttr(typ uint16, data []byte) []byte {
	l := 4 + len(data)
	b := make([]byte, (l+3)&^3)
	binary.NativeEndian.PutUint16(b[0:], uint16(l))
	binary.NativeEndian.PutUint16(b[2:], typ)
	copy(b[4:], data)
	return b
}

// newAddrMsg encodes one RTM_NEWADDR message with the given ifaddrmsg fields
// and attributes.
func newAddrMsg(plen, flags uint8, index uint32, attrs ...[]byte) []byte {
	body := make([]byte, unix.SizeofIfAddrmsg)
	body[0] = unix.AF_INET6
	body[1] = plen
	body[2] = flags
	binary.NativeEndian.PutUint32(body[4:], index)
	for _, a := range attrs {
		body = append(body, a...)
	}
	h := make([]byte, unix.SizeofNlMsghdr)
	binary.NativeEndian.PutUint32(h[0:], uint32(len(h)+len(body)))
	binary.NativeEndian.PutUint16(h[4:], unix.RTM_NEWADDR)
	return append(h, body...)
}

func cacheinfo(pref, valid uint32) []byte {
	b := make([]byte, 16)
	binary.NativeEndian.PutUint32(b[0:], pref)
	binary.NativeEndian.PutUint32(b[4:], valid)
	return b
}

func u32(v uint32) []byte { return binary.NativeEndian.AppendUint32(nil, v) }

func testAddrMsgs() []byte {
	a1 := netip.MustParseAddr("2001:db8::5c1e:9aff:fe3b:21aa").As16()
	a2 := netip.MustParseAddr("2001:db8::1234:5678:9abc:def0").As16()
	m1 := newAddrMsg(64, 0, 3,
		nlAttr(unix.IFA_ADDRESS, a1[:]),
		nlAttr(ifaProto, []byte{2}),
		nlAttr(unix.IFA_CACHEINFO, cacheinfo(14400, 86400)),
	)
	m2 := newAddrMsg(64, 0, 4,
		nlAttr(unix.IFA_ADDRESS, a2[:]),
		nlAttr(unix.IFA_FLAGS, u32(0x1)),
		nlAttr(ifaProto, []byte{2}),
		nlAttr(unix.IFA_CACHEINFO, cacheinfo(3600, 7200)),
	)
	done := make([]byte, unix.SizeofNlMsghdr+4)
	binary.NativeEndian.PutUint32(done[0:], uint32(len(done)))
	binary.NativeEndian.PutUint16(done[4:], unix.NLMSG_DONE)
	return append(append(m1, m2...), done...)
}

func testNames(i int) string { return map[int]string{3: "eth0", 4: "wlan0"}[i] }

func TestParseAddrMsgs(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	got, err := parseAddrMsgs(testAddrMsgs(), now, testNames)
	if err != nil {
		t.Fatal(err)
	}
	want := []Addr{
		{Addr: netip.MustParseAddr("2001:db8::5c1e:9aff:fe3b:21aa"), IfName: "eth0", IfIndex: 3,
			Origin: OriginSLAAC, Preferred: 14400, Valid: 86400, State: StateReady, ObservedAt: now},
		{Addr: netip.MustParseAddr("2001:db8::1234:5678:9abc:def0"), IfName: "wlan0", IfIndex: 4,
			Origin: OriginTemporary, Preferred: 3600, Valid: 7200, State: StateReady, ObservedAt: now},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d addrs, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("addr %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestParseAddrMsgsPrefersLocal(t *testing.T) {
	peer := netip.MustParseAddr("2001:db8::99").As16()
	local := netip.MustParseAddr("2001:db8::1").As16()
	b := newAddrMsg(128, ifaFPermanent, 2, nlAttr(unix.IFA_ADDRESS, peer[:]), nlAttr(unix.IFA_LOCAL, local[:]))
	got, err := parseAddrMsgs(b, time.Now(), testNames)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Addr != netip.AddrFrom16(local) || got[0].Origin != OriginStatic {
		t.Fatalf("got %+v, want local static address", got)
	}
}

func TestParseAddrMsgsTruncated(t *testing.T) {
	b := testAddrMsgs()
	for n := range len(b) {
		got, err := parseAddrMsgs(b[:n], time.Now(), testNames)
		if err == nil {
			for _, a := range got {
				if !a.Addr.Is6() || a.Addr.Zone() != "" {
					t.Errorf("prefix %d: bad addr %v", n, a.Addr)
				}
			}
		}
	}
}

func FuzzParseAddrMsgs(f *testing.F) {
	f.Add(testAddrMsgs())
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		got, err := parseAddrMsgs(b, time.Now(), testNames)
		if err != nil {
			return
		}
		for _, a := range got {
			if !a.Addr.Is6() || a.Addr.Zone() != "" {
				t.Errorf("bad addr %v", a.Addr)
			}
		}
	})
}
