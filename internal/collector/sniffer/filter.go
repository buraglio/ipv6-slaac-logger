// Package sniffer turns raw neighbor discovery frames into MAC/address observations.
package sniffer

import "golang.org/x/net/bpf"

const (
	etherIPv6   = 0x86dd
	etherVLAN   = 0x8100
	etherQinQ   = 0x88a8
	protoICMPv6 = 58
	acceptAll   = 65535
)

// Filter accepts IPv6/ICMPv6 types 133-136 with no extension headers, untagged or with
// one in-frame 802.1Q/802.1ad tag. (Tags stripped to auxdata look untagged to BPF.)
func Filter() ([]bpf.RawInstruction, error) {
	return bpf.Assemble([]bpf.Instruction{
		/* 0 */ bpf.LoadAbsolute{Off: 12, Size: 2},
		/* 1 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: etherIPv6, SkipTrue: 8}, // -> 10
		/* 2 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: etherVLAN, SkipTrue: 1}, // -> 4
		/* 3 */ bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: etherQinQ, SkipTrue: 12}, // -> reject
		// tagged: inner ethertype 16, next header 24, type 58
		/* 4 */ bpf.LoadAbsolute{Off: 16, Size: 2},
		/* 5 */ bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: etherIPv6, SkipTrue: 10},
		/* 6 */ bpf.LoadAbsolute{Off: 24, Size: 1},
		/* 7 */ bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: protoICMPv6, SkipTrue: 8},
		/* 8 */ bpf.LoadAbsolute{Off: 58, Size: 1},
		/* 9 */ bpf.Jump{Skip: 3}, // -> 13
		// untagged: next header 20, type 54
		/* 10 */ bpf.LoadAbsolute{Off: 20, Size: 1},
		/* 11 */ bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: protoICMPv6, SkipTrue: 4},
		/* 12 */ bpf.LoadAbsolute{Off: 54, Size: 1},
		// type is in A: accept 133..136
		/* 13 */ bpf.JumpIf{Cond: bpf.JumpLessThan, Val: 133, SkipTrue: 2},
		/* 14 */ bpf.JumpIf{Cond: bpf.JumpGreaterThan, Val: 136, SkipTrue: 1},
		/* 15 */ bpf.RetConstant{Val: acceptAll},
		/* 16 */ bpf.RetConstant{Val: 0},
	})
}
