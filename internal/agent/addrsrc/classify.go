package addrsrc

import (
	"time"

	"github.com/buraglio/ipv6-ra-logger/internal/dhcp6"
)

// Linux <linux/if_addr.h>.
const (
	ifaFTemporary  = 0x01
	ifaFOptimistic = 0x04
	ifaFDADFailed  = 0x08
	ifaFTentative  = 0x40
	ifaFPermanent  = 0x80

	ifaProtUnspec   = 0
	ifaProtKernelLo = 1
	ifaProtKernelRA = 2
	ifaProtKernelLL = 3
)

// macOS <netinet6/in6_var.h>.
const (
	darwinTentative  = 0x2
	darwinDuplicated = 0x4
	darwinDetached   = 0x8
	darwinAutoconf   = 0x40
	darwinTemporary  = 0x80
	darwinDynamic    = 0x100
	darwinOptimistic = 0x200
)

// Windows IP_PREFIX_ORIGIN / IP_SUFFIX_ORIGIN / IP_DAD_STATE.
const (
	winPrefixManual = 1 // windows.IpPrefixOriginManual
	winPrefixDhcp   = 3 // windows.IpPrefixOriginDhcp
	winPrefixRA     = 4 // windows.IpPrefixOriginRouterAdvertisement

	winSuffixManual = 1 // windows.IpSuffixOriginManual
	winSuffixDhcp   = 3 // windows.IpSuffixOriginDhcp
	winSuffixLLA    = 4 // windows.IpSuffixOriginLinkLayerAddress
	winSuffixRandom = 5 // windows.IpSuffixOriginRandom

	winDADTentative  = 1 // windows.IpDadStateTentative
	winDADDuplicate  = 2 // windows.IpDadStateDuplicate
	winDADDeprecated = 3 // windows.IpDadStateDeprecated
	winDADPreferred  = 4 // windows.IpDadStatePreferred
)

// ClassifyLinux derives origin and state from IFA_FLAGS, IFA_PROTO, the prefix
// length and the valid lifetime.
func ClassifyLinux(ifaFlags uint32, proto uint8, prefixLen uint8, valid uint32) (Origin, State) {
	state := StateReady
	switch {
	case ifaFlags&ifaFDADFailed != 0:
		state = StateDuplicate
	case ifaFlags&(ifaFTentative|ifaFOptimistic) != 0:
		state = StateNotReady
	}
	switch {
	case ifaFlags&ifaFTemporary != 0:
		return OriginTemporary, state
	case proto == ifaProtKernelRA:
		return OriginSLAAC, state
	case proto == ifaProtKernelLo || proto == ifaProtKernelLL:
		return OriginOther, state
	case ifaFlags&ifaFPermanent != 0:
		return OriginStatic, state
	case prefixLen == 128 && valid != dhcp6.Infinity:
		return OriginDHCPv6, state
	}
	return OriginSLAAC, state
}

// ClassifyDarwin derives origin and state from the in6_ifreq flags. The
// deprecated flag does not affect state.
func ClassifyDarwin(flags6 uint32) (Origin, State) {
	state := StateReady
	switch {
	case flags6&darwinDuplicated != 0:
		state = StateDuplicate
	case flags6&(darwinTentative|darwinOptimistic|darwinDetached) != 0:
		state = StateNotReady
	}
	switch {
	case flags6&darwinDynamic != 0:
		return OriginDHCPv6, state
	case flags6&darwinTemporary != 0:
		return OriginTemporary, state
	case flags6&darwinAutoconf != 0:
		return OriginSLAAC, state
	}
	return OriginStatic, state
}

// ClassifyWindows derives origin and state from the unicast address row's
// PrefixOrigin, SuffixOrigin and DadState.
func ClassifyWindows(prefixOrigin, suffixOrigin, dadState int32) (Origin, State) {
	var state State
	switch dadState {
	case winDADPreferred, winDADDeprecated:
		state = StateReady
	case winDADDuplicate:
		state = StateDuplicate
	default:
		state = StateNotReady
	}
	switch {
	case suffixOrigin == winSuffixDhcp:
		return OriginDHCPv6, state
	case prefixOrigin == winPrefixRA && (suffixOrigin == winSuffixLLA || suffixOrigin == winSuffixRandom):
		return OriginSLAAC, state
	case prefixOrigin == winPrefixManual || suffixOrigin == winSuffixManual:
		return OriginStatic, state
	}
	return OriginOther, state
}

// DarwinRemaining converts an absolute expiry (unix seconds) to remaining
// seconds at now. Zero means infinite; an expiry in the past yields 0.
func DarwinRemaining(expire int64, now time.Time) uint32 {
	if expire == 0 {
		return dhcp6.Infinity
	}
	d := expire - now.Unix()
	if d <= 0 {
		return 0
	}
	if d >= int64(dhcp6.Infinity) {
		return dhcp6.Infinity - 1
	}
	return uint32(d)
}
