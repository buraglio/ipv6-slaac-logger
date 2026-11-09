package sniffer

import (
	"testing"

	"golang.org/x/net/bpf"
)

func TestFilterProgram(t *testing.T) {
	raw, err := Filter()
	if err != nil {
		t.Fatal(err)
	}
	prog := make([]bpf.Instruction, len(raw))
	for i, r := range raw {
		prog[i] = r.Disassemble()
	}
	vm, err := bpf.NewVM(prog)
	if err != nil {
		t.Fatal(err)
	}
	all := "ff02::1"
	mk := func(vlans []uint16, icmp []byte) []byte {
		return frame(t, hostMAC, "33:33:00:00:00:01", vlans, hostLL, all, 255, icmp)
	}
	hbh := mk(nil, raMsg())
	hbh[20] = 0 // hop-by-hop next header
	echo := mk(nil, []byte{128, 0, 0, 0, 0, 0, 0, 0})
	udp4 := make([]byte, 60)
	udp4[12], udp4[13] = 0x08, 0x00
	udp4[23] = 17

	tests := []struct {
		name  string
		frame []byte
		want  bool
	}{
		{"rs", mk(nil, rsMsg()), true},
		{"ra", mk(nil, raMsg()), true},
		{"ns", mk(nil, ns(hostGUA)), true},
		{"na", mk(nil, na(0x20, hostGUA)), true},
		{"ns vlan", mk([]uint16{10}, ns(hostGUA)), true},
		{"ns qinq 0x88a8 double tag (accepted loss)", mk([]uint16{10, 20}, ns(hostGUA)), false},
		{"echo", echo, false},
		{"ipv4 udp", udp4, false},
		{"hop-by-hop", hbh, false},
		{"runt", make([]byte, 10), false},
		{"vlan echo", mk([]uint16{10}, []byte{128, 0, 0, 0, 0, 0, 0, 0}), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			n, err := vm.Run(tc.frame)
			if err != nil {
				t.Fatal(err)
			}
			if got := n > 0; got != tc.want {
				t.Errorf("accepted = %v, want %v", got, tc.want)
			}
		})
	}
}
