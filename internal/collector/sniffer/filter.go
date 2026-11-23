// Package sniffer turns raw neighbor discovery frames into MAC/address observations.
package sniffer

import "golang.org/x/net/bpf"

const (
	etherIPv6   = 0x86dd
	etherARP    = 0x0806
	etherVLAN   = 0x8100
	etherQinQ   = 0x88a8
	protoICMPv6 = 58
	acceptAll   = 65535
)

// Filter accepts IPv6/ICMPv6 types 133-136 (ND/RA) and ARP frames, untagged or
// with one in-frame 802.1Q/802.1ad tag. ARP hardware-type validation is left to
// the Go parser. (Tags stripped to auxdata look untagged to BPF.)
func Filter() ([]bpf.RawInstruction, error) {
	return bpf.Assemble([]bpf.Instruction{
		/*  0 */ bpf.LoadAbsolute{Off: 12, Size: 2},
		/*  1 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: etherIPv6, SkipTrue: 11},  // -> 13 untagged IPv6
		/*  2 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: etherARP, SkipTrue: 15},   // -> 18 accept
		/*  3 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: etherVLAN, SkipTrue: 1},   // -> 5 tagged, skip QinQ check
		/*  4 */ bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: etherQinQ, SkipTrue: 14}, // -> 19 reject
		// tagged path: inner ethertype at offset 16
		/*  5 */ bpf.LoadAbsolute{Off: 16, Size: 2},
		/*  6 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: etherIPv6, SkipTrue: 2},   // -> 9 tagged ICMPv6
		/*  7 */ bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: etherARP, SkipTrue: 11}, // -> 19 reject
		/*  8 */ bpf.RetConstant{Val: acceptAll},                                  // tagged ARP
		// tagged ICMPv6: next header at 24, type at 58
		/*  9 */ bpf.LoadAbsolute{Off: 24, Size: 1},
		/* 10 */ bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: protoICMPv6, SkipTrue: 8}, // -> 19 reject
		/* 11 */ bpf.LoadAbsolute{Off: 58, Size: 1},
		/* 12 */ bpf.Jump{Skip: 3},                                                // -> 16 type check
		// untagged IPv6: next header at 20, type at 54
		/* 13 */ bpf.LoadAbsolute{Off: 20, Size: 1},
		/* 14 */ bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: protoICMPv6, SkipTrue: 4}, // -> 19 reject
		/* 15 */ bpf.LoadAbsolute{Off: 54, Size: 1},
		// ICMPv6 type in A: accept 133..136
		/* 16 */ bpf.JumpIf{Cond: bpf.JumpLessThan, Val: 133, SkipTrue: 2},
		/* 17 */ bpf.JumpIf{Cond: bpf.JumpGreaterThan, Val: 136, SkipTrue: 1},
		/* 18 */ bpf.RetConstant{Val: acceptAll},
		/* 19 */ bpf.RetConstant{Val: 0},
	})
}
