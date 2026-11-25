// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package hello

import (
	"fmt"
	"net/netip"
	"slices"

	pb "gvisor.dev/gvisor/pkg/netproxy/hello/hello_go_proto"
)

// Limits on the fields of a message.
const (
	maxRequiredFeatures = 8
	maxFeatureNameLen   = 64
	minMTU              = 68
	maxMTU              = 65535
	minIPv6MTU          = 1280
	maxAddresses        = 32
	maxRoutes           = 256
	maxIfnameLen        = 15
)

// knownFeatures are the required_features names that this package
// implements. This major defines none.
var knownFeatures = map[string]bool{}

func newError(code pb.ErrorCode, field, format string, args ...any) *Error {
	return &Error{Code: code, Field: field, Message: fmt.Sprintf(format, args...)}
}

func invalidValue(field, format string, args ...any) *Error {
	return newError(pb.ErrorCode_ERROR_CODE_INVALID_VALUE, field, format, args...)
}

func limitExceeded(field, format string, args ...any) *Error {
	return newError(pb.ErrorCode_ERROR_CODE_LIMIT_EXCEEDED, field, format, args...)
}

// validFeatureName reports whether name consists of [a-z0-9_].
func validFeatureName(name string) bool {
	for _, c := range []byte(name) {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return name != ""
}

// checkFeatures rejects any name in a required_features list that this
// package doesn't implement, naming the first one.
func checkFeatures(names []string) error {
	if len(names) > maxRequiredFeatures {
		return limitExceeded("required_features", "required_features has %d names; at most %d are allowed", len(names), maxRequiredFeatures)
	}
	for i, name := range names {
		field := fmt.Sprintf("required_features[%d]", i)
		if len(name) > maxFeatureNameLen {
			return limitExceeded(field, "%s is %d bytes; at most %d are allowed", field, len(name), maxFeatureNameLen)
		}
		if !validFeatureName(name) {
			return invalidValue(field, "%s %q is not 1-%d bytes of [a-z0-9_]", field, name, maxFeatureNameLen)
		}
		if !knownFeatures[name] {
			return newError(pb.ErrorCode_ERROR_CODE_UNKNOWN_FEATURE, field, "%s: unknown feature %q", field, name)
		}
	}
	return nil
}

// ValidateOffer checks an Offer as the peer receives it. On failure the error
// is an *Error to send back.
func ValidateOffer(o *pb.Offer) error {
	if err := checkFeatures(o.GetRequiredFeatures()); err != nil {
		return err
	}
	switch n := len(o.GetSupportedMajors()); {
	case n == 0:
		return newError(pb.ErrorCode_ERROR_CODE_MALFORMED, "supported_majors", "supported_majors is empty")
	case n > maxSupportedMajors:
		return limitExceeded("supported_majors", "supported_majors has %d entries; at most %d are allowed", n, maxSupportedMajors)
	}
	if n := len(o.GetSandboxId()); n > MaxSandboxIDLen {
		return limitExceeded("sandbox_id", "sandbox_id is %d bytes; at most %d are allowed", n, MaxSandboxIDLen)
	}
	if n := o.GetLinkCount(); n < 1 || n > MaxLinks {
		return invalidValue("link_count", "link_count %d is not within 1-%d", n, MaxLinks)
	}
	if o.GetLinkIndex() >= o.GetLinkCount() {
		return invalidValue("link_index", "link_index %d is not less than link_count %d", o.GetLinkIndex(), o.GetLinkCount())
	}
	return nil
}

// addrFromBytes returns the address in b, which must be 4 or 16 bytes.
func addrFromBytes(b []byte) (netip.Addr, bool) {
	switch len(b) {
	case 4:
		return netip.AddrFrom4([4]byte(b)), true
	case 16:
		return netip.AddrFrom16([16]byte(b)), true
	default:
		return netip.Addr{}, false
	}
}

// familyName returns "IPv4" or "IPv6".
func familyName(a netip.Addr) string {
	if a.Is4() {
		return "IPv4"
	}
	return "IPv6"
}

// limitedBroadcast is the IPv4 limited broadcast address.
var limitedBroadcast = netip.AddrFrom4([4]byte{255, 255, 255, 255})

// unusableKind returns why a is not usable as an interface address or a
// gateway, or "" if it is.
func unusableKind(a netip.Addr) string {
	switch {
	case a.Is4In6():
		return "an IPv4-mapped IPv6 address"
	case a.IsUnspecified():
		return "unspecified"
	case a.IsMulticast():
		return "multicast"
	case a.IsLoopback():
		return "loopback"
	case a == limitedBroadcast:
		return "the IPv4 limited broadcast address"
	default:
		return ""
	}
}

// linkLocal is the IPv6 link-local prefix. A gateway in it is reachable on
// any link.
var linkLocal = netip.MustParsePrefix("fe80::/10")

// validIfname reports whether name is a valid Config.ifname.
func validIfname(name string) bool {
	if len(name) < 1 || len(name) > maxIfnameLen || name == "lo" || name == "." || name == ".." {
		return false
	}
	for _, c := range []byte(name) {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_', c == '.', c == '-':
		default:
			return false
		}
	}
	return true
}

// ValidateConfig checks a Config that a peer sent in reply to offer. On
// failure the error is an *Error to send back.
func ValidateConfig(c *pb.Config, offer *pb.Offer) error {
	if err := checkFeatures(c.GetRequiredFeatures()); err != nil {
		return err
	}
	if c.LinkIndex != nil && c.GetLinkIndex() != offer.GetLinkIndex() {
		return invalidValue("link_index", "link_index %d does not match offered index %d", c.GetLinkIndex(), offer.GetLinkIndex())
	}
	if name := c.GetIfname(); name == "" {
		if offer.GetLinkCount() > 1 {
			return invalidValue("ifname", "ifname is required with %d links", offer.GetLinkCount())
		}
	} else if !validIfname(name) {
		return invalidValue("ifname", "ifname %q is not 1-%d bytes of [A-Za-z0-9_.-], or is reserved", name, maxIfnameLen)
	}

	mtu := c.GetMtu()
	if mtu < minMTU || mtu > maxMTU {
		return invalidValue("mtu", "mtu %d is not within %d-%d", mtu, minMTU, maxMTU)
	}

	addrs := c.GetAddresses()
	if len(addrs) == 0 {
		return invalidValue("addresses", "addresses is empty")
	}
	if len(addrs) > maxAddresses {
		return limitExceeded("addresses", "addresses has %d entries; at most %d are allowed", len(addrs), maxAddresses)
	}
	prefixes := make([]netip.Prefix, 0, len(addrs))
	seen := make(map[netip.Addr]int, len(addrs))
	hasIPv6 := false
	for i, a := range addrs {
		field := fmt.Sprintf("addresses[%d]", i)
		ip, ok := addrFromBytes(a.GetIp())
		if !ok {
			return invalidValue(field+".ip", "%s.ip has %d bytes; want 4 or 16", field, len(a.GetIp()))
		}
		if kind := unusableKind(ip); kind != "" {
			return invalidValue(field+".ip", "%s %v is %s", field, ip, kind)
		}
		if n := a.GetPrefixLen(); n < 1 || n > uint32(ip.BitLen()) {
			return invalidValue(field+".prefix_len", "%s %v: prefix_len %d is not within 1-%d", field, ip, n, ip.BitLen())
		}
		if j, ok := seen[ip]; ok {
			return invalidValue(field+".ip", "%s %v duplicates addresses[%d]", field, ip, j)
		}
		seen[ip] = i
		hasIPv6 = hasIPv6 || ip.Is6()
		prefixes = append(prefixes, netip.PrefixFrom(ip, int(a.GetPrefixLen())))
	}
	if hasIPv6 && mtu < minIPv6MTU {
		return invalidValue("mtu", "mtu %d is less than %d, the IPv6 minimum link MTU", mtu, minIPv6MTU)
	}

	routes := c.GetRoutes()
	if len(routes) > maxRoutes {
		return limitExceeded("routes", "routes has %d entries; at most %d are allowed", len(routes), maxRoutes)
	}
	// A gateway is reachable if it is within an address prefix, within the
	// destination of an on-link route (one without a gateway, including a
	// default route), or IPv6 link-local.
	reachable := append(slices.Clone(prefixes), linkLocal)
	for _, r := range routes {
		dst, ok := addrFromBytes(r.GetDst())
		if ok && len(r.GetGateway()) == 0 && r.GetDstPrefixLen() <= uint32(dst.BitLen()) {
			reachable = append(reachable, netip.PrefixFrom(dst, int(r.GetDstPrefixLen())))
		}
	}
	dsts := make(map[netip.Prefix]int, len(routes))
	defaultRoute := make(map[string]int, 2) // Keyed by familyName.
	for i, r := range routes {
		field := fmt.Sprintf("routes[%d]", i)
		dst, ok := addrFromBytes(r.GetDst())
		if !ok {
			return invalidValue(field+".dst", "%s.dst has %d bytes; want 4 or 16", field, len(r.GetDst()))
		}
		if dst.Is4In6() {
			return invalidValue(field+".dst", "%s.dst %v is an IPv4-mapped IPv6 address", field, dst)
		}
		if n := r.GetDstPrefixLen(); n > uint32(dst.BitLen()) {
			return invalidValue(field+".dst_prefix_len", "%s %v: dst_prefix_len %d is more than %d", field, dst, n, dst.BitLen())
		}
		p := netip.PrefixFrom(dst, int(r.GetDstPrefixLen()))
		if p.Masked().Addr() != dst {
			return invalidValue(field+".dst", "%s %v/%d has bits set past its prefix length", field, dst, p.Bits())
		}
		if p.Bits() == 0 {
			if j, ok := defaultRoute[familyName(dst)]; ok {
				return invalidValue(field, "%s is a second %s default route after routes[%d]", field, familyName(dst), j)
			}
			defaultRoute[familyName(dst)] = i
		}
		if j, ok := dsts[p]; ok {
			return invalidValue(field+".dst", "%s %v duplicates routes[%d]", field, p, j)
		}
		dsts[p] = i
		if gwb := r.GetGateway(); len(gwb) != 0 {
			if len(gwb) != len(r.GetDst()) {
				return invalidValue(field+".gateway", "%s %v: gateway has %d bytes; dst has %d", field, p, len(gwb), len(r.GetDst()))
			}
			gw, _ := addrFromBytes(gwb)
			if kind := unusableKind(gw); kind != "" {
				return invalidValue(field+".gateway", "%s %v: gateway %v is %s", field, p, gw, kind)
			}
			if j, ok := seen[gw]; ok {
				return invalidValue(field+".gateway", "%s %v: gateway %v is addresses[%d]", field, p, gw, j)
			}
			within := false
			for _, rp := range reachable {
				if rp.Contains(gw) {
					within = true
					break
				}
			}
			if !within {
				return invalidValue(field+".gateway", "%s %v: gateway %v is not within any address prefix or on-link route", field, p, gw)
			}
		}
		if m := r.GetMtu(); m != 0 && (m < minMTU || m > mtu) {
			return invalidValue(field+".mtu", "%s %v: mtu %d is not 0 or within %d-%d", field, p, m, minMTU, mtu)
		}
	}
	return nil
}
