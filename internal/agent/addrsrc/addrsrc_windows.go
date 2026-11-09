//go:build windows

package addrsrc

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type ipHelperSource struct{}

// New returns the platform address source (IP Helper).
func New() Source { return ipHelperSource{} }

// List walks GetAdaptersAddresses' unicast IPv6 addresses.
func (ipHelperSource) List() ([]Addr, error) {
	const flags = windows.GAA_FLAG_SKIP_ANYCAST | windows.GAA_FLAG_SKIP_MULTICAST | windows.GAA_FLAG_SKIP_DNS_SERVER
	size := uint32(15 << 10)
	var buf []byte
	for {
		buf = make([]byte, size)
		err := windows.GetAdaptersAddresses(windows.AF_INET6, flags, 0,
			(*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])), &size)
		if err == nil {
			break
		}
		if errors.Is(err, windows.ERROR_NO_DATA) {
			return nil, nil // no IPv6 addresses at all
		}
		if !errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) || size <= uint32(len(buf)) {
			return nil, fmt.Errorf("addrsrc: GetAdaptersAddresses: %w", err)
		}
	}
	now := time.Now()
	var out []Addr
	for aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); aa != nil; aa = aa.Next {
		name := windows.UTF16PtrToString(aa.FriendlyName)
		for u := aa.FirstUnicastAddress; u != nil; u = u.Next {
			sa := u.Address.Sockaddr
			if sa == nil || sa.Addr.Family != windows.AF_INET6 ||
				uintptr(u.Address.SockaddrLength) < unsafe.Sizeof(windows.RawSockaddrInet6{}) {
				continue
			}
			raw := (*windows.RawSockaddrInet6)(unsafe.Pointer(sa))
			origin, state := ClassifyWindows(u.PrefixOrigin, u.SuffixOrigin, u.DadState)
			out = append(out, Addr{
				Addr:       netip.AddrFrom16(raw.Addr), // no zone
				IfName:     name,
				IfIndex:    int(aa.Ipv6IfIndex),
				Origin:     origin,
				Preferred:  u.PreferredLifetime, // remaining; 0xffffffff = infinite
				Valid:      u.ValidLifetime,
				State:      state,
				ObservedAt: now,
			})
		}
	}
	return out, nil
}

// Watchers are found by the address of a token passed as callerContext,
// because a Go func value cannot cross the callback boundary.
var (
	watchMu       sync.Mutex
	watchers      = map[uintptr]chan struct{}{}
	notifyCbOnce  sync.Once
	notifyCbValue uintptr
)

func notifyCallback() uintptr {
	notifyCbOnce.Do(func() {
		notifyCbValue = windows.NewCallback(func(callerContext, row, notificationType uintptr) uintptr {
			watchMu.Lock()
			if ch, ok := watchers[callerContext]; ok {
				signal(ch)
			}
			watchMu.Unlock()
			return 0
		})
	})
	return notifyCbValue
}

// Watch registers NotifyUnicastIpAddressChange and signals on every change.
func (ipHelperSource) Watch(ctx context.Context) (<-chan struct{}, error) {
	token := new(byte) // heap-allocated, never moved; its address is the key
	key := uintptr(unsafe.Pointer(token))
	ch := make(chan struct{}, 1)
	watchMu.Lock()
	watchers[key] = ch
	watchMu.Unlock()
	var h windows.Handle
	if err := windows.NotifyUnicastIpAddressChange(windows.AF_INET6, notifyCallback(), unsafe.Pointer(token), false, &h); err != nil {
		watchMu.Lock()
		delete(watchers, key)
		watchMu.Unlock()
		return nil, fmt.Errorf("addrsrc: NotifyUnicastIpAddressChange: %w", err)
	}
	go func() {
		<-ctx.Done()
		// CancelMibChangeNotify2 waits for in-flight callbacks.
		_ = windows.CancelMibChangeNotify2(h)
		watchMu.Lock()
		delete(watchers, key)
		watchMu.Unlock()
		close(ch)
		runtime.KeepAlive(token) // the registration referenced it until now
	}()
	return ch, nil
}
