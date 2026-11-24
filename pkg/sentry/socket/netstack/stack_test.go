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

package netstack_test

import (
	"bytes"
	"fmt"
	"net"
	"slices"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/inet"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/socket/netfilter"
	"gvisor.dev/gvisor/pkg/sentry/socket/netlink/nlmsg"
	"gvisor.dev/gvisor/pkg/sentry/socket/netstack"
	"gvisor.dev/gvisor/pkg/state"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/ethernet"
	"gvisor.dev/gvisor/pkg/tcpip/link/loopback"
	"gvisor.dev/gvisor/pkg/tcpip/link/veth"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

func TestDestroyNilStack(t *testing.T) {
	s := &netstack.Stack{
		Stack: nil,
	}
	// This should not panic.
	s.Destroy()
}

func TestDestroyAsyncNilStackCallsDone(t *testing.T) {
	s := &netstack.Stack{
		Stack: nil,
	}
	called := false
	s.DestroyAsync(func() { called = true })
	if !called {
		t.Error("DestroyAsync on a nil stack did not call done")
	}
}

func TestRemoveRouteRemovesFirstMatchOnly(t *testing.T) {
	s := &netstack.Stack{
		Stack: stack.New(stack.Options{}),
	}
	dst := tcpip.AddressWithPrefix{
		Address:   tcpip.AddrFrom4([4]byte{10, 0, 0, 0}),
		PrefixLen: 24,
	}.Subnet()
	s.Stack.AddRoute(tcpip.Route{Destination: dst, NIC: 1})
	s.Stack.AddRoute(tcpip.Route{Destination: dst, NIC: 2})

	delRoute := func() *syserr.Error {
		msg := nlmsg.NewMessage(linux.NetlinkMessageHeader{
			Type: linux.RTM_DELROUTE,
		})
		msg.Put(&linux.RouteMessage{
			Family: linux.AF_INET,
			DstLen: 24,
		})
		msg.PutAttr(linux.RTA_DST, primitive.AsByteSlice([]byte{10, 0, 0, 0}))
		return s.RemoveRoute(context.Background(), msg)
	}

	if err := delRoute(); err != nil {
		t.Fatalf("first RemoveRoute failed: %v", err)
	}
	if got := s.Stack.GetRouteTable(); len(got) != 1 || got[0].NIC != 2 {
		t.Fatalf("route table after first RemoveRoute = %v, want only the NIC 2 route", got)
	}
	if err := delRoute(); err != nil {
		t.Fatalf("second RemoveRoute failed: %v", err)
	}
	if got := s.Stack.GetRouteTable(); len(got) != 0 {
		t.Fatalf("route table after second RemoveRoute = %v, want empty", got)
	}
	if err := delRoute(); err != syserr.ErrNoProcess {
		t.Fatalf("third RemoveRoute = %v, want %v", err, syserr.ErrNoProcess)
	}
}

// While external networking is paused, bringing a non-loopback interface up
// with SIOCSIFFLAGS or RTM_NEWLINK records it as up but leaves it without
// carrier. Resuming enables only interfaces that are up.
func TestSetInterfaceUpWhileExternalNetworkingPaused(t *testing.T) {
	const (
		loopbackNICID = 1
		externalNICID = 2
	)
	ctx := context.Background()
	for _, test := range []struct {
		name  string
		setUp func(s *netstack.Stack, id tcpip.NICID, up bool) *syserr.Error
	}{
		{
			name: "SIOCSIFFLAGS",
			setUp: func(s *netstack.Stack, id tcpip.NICID, up bool) *syserr.Error {
				var flags uint32
				if up {
					flags = linux.IFF_UP
				}
				return s.SetInterfaceFlags(ctx, id, flags)
			},
		},
		{
			name: "RTM_NEWLINK",
			setUp: func(s *netstack.Stack, id tcpip.NICID, up bool) *syserr.Error {
				var flags uint32
				if up {
					flags = linux.IFF_UP
				}
				msg := nlmsg.NewMessage(linux.NetlinkMessageHeader{
					Type:  linux.RTM_NEWLINK,
					Flags: linux.NLM_F_REQUEST,
				})
				msg.Put(&linux.InterfaceInfoMessage{
					Family: linux.AF_UNSPEC,
					Index:  int32(id),
					Flags:  flags,
					Change: linux.IFF_UP,
				})
				return s.SetInterface(ctx, msg)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := &netstack.Stack{
				Stack: stack.New(stack.Options{
					NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
				}),
			}
			defer s.Stack.Destroy()
			if err := s.Stack.CreateNIC(loopbackNICID, loopback.New()); err != nil {
				t.Fatalf("CreateNIC(%d, _): %s", loopbackNICID, err)
			}
			if err := s.Stack.CreateNIC(externalNICID, channel.New(0, 1500, "\x02\x00\x00\x00\x00\x01")); err != nil {
				t.Fatalf("CreateNIC(%d, _): %s", externalNICID, err)
			}

			setUp := func(up bool) {
				t.Helper()
				if err := test.setUp(s, externalNICID, up); err != nil {
					t.Fatalf("setting IFF_UP to %t on NIC %d: %v", up, externalNICID, err)
				}
			}
			const carrier = linux.IFF_RUNNING | linux.IFF_LOWER_UP
			checkFlags := func(want uint32) {
				t.Helper()
				iface, ok := s.Interfaces()[externalNICID]
				if !ok {
					t.Fatalf("interface %d not found", externalNICID)
				}
				if got := iface.Flags & (linux.IFF_UP | carrier); got != want {
					t.Errorf("interface flags = %#x, want %#x", got, want)
				}
				if got, want := s.Stack.CheckNIC(externalNICID), want&carrier != 0; got != want {
					t.Errorf("CheckNIC(%d) = %t, want %t", externalNICID, got, want)
				}
			}

			s.Stack.DisableAllNonLoopbackNICs()
			checkFlags(linux.IFF_UP)

			// Taking the interface down and up again while paused does not
			// enable it.
			setUp(false)
			checkFlags(0)
			setUp(true)
			checkFlags(linux.IFF_UP)

			s.Stack.EnableAllNonLoopbackNICs()
			checkFlags(linux.IFF_UP | carrier)

			// An interface that was taken down stays down across a pause and
			// resume.
			setUp(false)
			s.Stack.DisableAllNonLoopbackNICs()
			s.Stack.EnableAllNonLoopbackNICs()
			checkFlags(0)
			setUp(true)
			checkFlags(linux.IFF_UP | carrier)
		})
	}
}

func mustSubnet(t *testing.T, cidr string) tcpip.Subnet {
	t.Helper()
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("net.ParseCIDR(%q): %v", cidr, err)
	}
	ones, _ := ipNet.Mask.Size()
	return tcpip.AddressWithPrefix{
		Address:   tcpip.AddrFromSlice(ipNet.IP),
		PrefixLen: ones,
	}.Subnet()
}

// RouteTable lists routes in Linux FIB dump order instead of netstack's
// longest-prefix-first lookup order.
func TestRouteTableDumpOrder(t *testing.T) {
	s := &netstack.Stack{
		Stack: stack.New(stack.Options{}),
	}
	v4Gateway := tcpip.AddrFrom4([4]byte{10, 88, 0, 1})
	v6Gateway := tcpip.AddrFromSlice(net.ParseIP("2001:db8:0:1::1"))
	for _, rt := range []struct {
		cidr    string
		nic     tcpip.NICID
		gateway tcpip.Address
	}{
		{"0.0.0.0/0", 1, v4Gateway},
		{"::/0", 1, v6Gateway},
		{"192.168.0.0/16", 1, tcpip.Address{}},
		{"10.0.0.0/8", 1, v4Gateway},
		{"fe80::/64", 1, tcpip.Address{}},
		{"2001:db8::/32", 1, v6Gateway},
		{"10.0.0.0/24", 1, v4Gateway},
		{"10.0.0.0/24", 2, v4Gateway},
		{"127.0.0.0/8", 3, tcpip.Address{}},
		{"2001:db8:1::/48", 1, v6Gateway},
		{"::1/128", 3, tcpip.Address{}},
		{"169.254.1.1/32", 1, tcpip.Address{}},
		{"2001:db8:1:2::/64", 1, v6Gateway},
		{"10.1.0.0/16", 1, v4Gateway},
		{"2001:db8:0:1::/64", 1, tcpip.Address{}},
	} {
		s.Stack.AddRoute(tcpip.Route{
			Destination: mustSubnet(t, rt.cidr),
			Gateway:     rt.gateway,
			NIC:         rt.nic,
		})
	}

	var got []string
	for _, rt := range s.RouteTable() {
		got = append(got, fmt.Sprintf("%s/%d nic%d", net.IP(rt.DstAddr), rt.DstLen, rt.OutputInterface))
	}
	want := []string{
		// IPv4 by ascending destination, longer prefixes first for equal
		// destinations; same-destination routes keep their relative order.
		"0.0.0.0/0 nic1",
		"10.0.0.0/24 nic1",
		"10.0.0.0/24 nic2",
		"10.0.0.0/8 nic1",
		"10.1.0.0/16 nic1",
		"127.0.0.0/8 nic3",
		"169.254.1.1/32 nic1",
		"192.168.0.0/16 nic1",
		// IPv6 in fib6 post-order: more specific routes precede the routes
		// containing them, so the default route comes last.
		"::1/128 nic3",
		"2001:db8:0:1::/64 nic1",
		"2001:db8:1:2::/64 nic1",
		"2001:db8:1::/48 nic1",
		"2001:db8::/32 nic1",
		"fe80::/64 nic1",
		"::/0 nic1",
	}
	if !slices.Equal(got, want) {
		t.Errorf("RouteTable() order:\ngot  %q\nwant %q", got, want)
	}

	// Lookups still use netstack's longest-prefix-first order.
	if got := s.Stack.GetRouteTable()[0].Destination.Prefix(); got != 128 {
		t.Errorf("GetRouteTable()[0] prefix = %d, want 128", got)
	}
}

func TestRestoreNICsAndEndpointsInitializesLinuxIPTables(t *testing.T) {
	s := netstack.NewStack(stack.New(stack.Options{}), 1)
	defer s.Destroy()

	// Simulate post-checkpoint-load state where stack.Stack.tables is nil
	// (because tables is state:"nosave" and ConfigureNetwork is not invoked
	// on restored child network namespaces).
	s.Stack.SetIPTables(nil)
	s.RestoreNICsAndEndpoints()

	tables := s.Stack.IPTables()
	if tables == nil {
		t.Fatal("s.Stack.IPTables() = nil, want non-nil")
	}
	visited := 0
	tables.VisitTargets(func(tgt stack.Target) stack.Target {
		visited++
		switch tgt.(type) {
		case *stack.AcceptTarget, *stack.DropTarget, *stack.ErrorTarget, *stack.UserChainTarget, *stack.ReturnTarget, *stack.RedirectTarget, *stack.CTTarget:
			t.Errorf("target %T is a raw stack.Target instead of a netfilter-wrapped target", tgt)
		}
		return tgt
	})
	if visited == 0 {
		t.Fatal("tables.VisitTargets() visited 0 targets, want > 0")
	}

}

func TestCheckRestorableWithFilterRules(t *testing.T) {
	for _, tc := range []struct {
		name     string
		kind     string
		loopback bool
		iptables bool
		nftables bool
		isRoot   bool
		wantErr  bool
	}{
		{name: "root veth without rules", kind: stack.NICKindVeth, isRoot: true},
		{name: "root veth with nftables", kind: stack.NICKindVeth, nftables: true, isRoot: true, wantErr: true},
		{name: "root veth with iptables", kind: stack.NICKindVeth, iptables: true, isRoot: true, wantErr: true},
		{name: "root bridge with iptables", kind: stack.NICKindBridge, iptables: true, isRoot: true, wantErr: true},
		{name: "root loopback with iptables", loopback: true, iptables: true, isRoot: true},
		{name: "root tun with iptables", kind: stack.NICKindTun, iptables: true, isRoot: true},
		{name: "child loopback without rules", loopback: true},
		{name: "child loopback with iptables", loopback: true, iptables: true, wantErr: true},
		{name: "child tun with iptables", kind: stack.NICKindTun, iptables: true, wantErr: true},
		{name: "child veth with nftables", kind: stack.NICKindVeth, nftables: true, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := netstack.NewStack(stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol}}), 1)
			defer s.Destroy()
			s.InitDefaultTables()
			var ep stack.LinkEndpoint = channel.New(1, 1500, "")
			if tc.loopback {
				ep = loopback.New()
			}
			// The sandbox preserves veth, bridge, and tun NICs and the loopback
			// NIC of each child network namespace.
			if err := s.Stack.CreateNICWithOptions(1, ep, stack.NICOptions{Name: "dev0", Kind: tc.kind, Preserve: true}); err != nil {
				t.Fatalf("CreateNICWithOptions: %s", err)
			}
			if tc.iptables {
				addFilterRule(s)
			}
			if tc.nftables {
				s.Stack.SetNFTablesConfigured(true)
			}
			if err := s.CheckRestorable(tc.isRoot); (err != nil) != tc.wantErr {
				t.Errorf("CheckRestorable(%t) = %v, want error: %t", tc.isRoot, err, tc.wantErr)
			}
		})
	}
}

// natRule returns a NAT table rule with target t. If proto is not zero, the
// rule matches only packets of that transport protocol.
func natRule(ipv6 bool, t stack.Target, proto tcpip.TransportProtocolNumber) stack.Rule {
	filter := stack.EmptyFilter4()
	if ipv6 {
		filter = stack.EmptyFilter6()
	}
	if proto != 0 {
		filter.Protocol = proto
		filter.CheckProtocol = true
	}
	return stack.Rule{Filter: filter, Target: t}
}

// natTableSpec describes a NAT table for TestCheckRestorableRootNATRules.
type natTableSpec struct {
	ipv6 bool
	// post are the POSTROUTING rules before the policy.
	post []stack.Rule
	// policy is the POSTROUTING policy. If nil, it is ACCEPT.
	policy stack.Target
	// chains are user chains. Each chain follows its marker rule.
	chains [][]stack.Rule
	// noEnd omits the ERROR rule at the end of the table.
	noEnd bool
	// postAfterMarker places the POSTROUTING entry after the marker of an
	// extra user chain, so its rules belong to that chain.
	postAfterMarker bool
}

// jumpTo returns a jump to the first rule of user chain k of a natTableSpec.
func jumpTo(k int) *netfilter.JumpTarget {
	return &netfilter.JumpTarget{RuleNum: -(k + 1)}
}

// jumpToMarker returns a jump to the marker rule of user chain k.
func jumpToMarker(k int) *netfilter.JumpTarget {
	return &netfilter.JumpTarget{RuleNum: -(k + 1) - 1000}
}

func (spec natTableSpec) table() stack.Table {
	netProto := header.IPv4ProtocolNumber
	if spec.ipv6 {
		netProto = header.IPv6ProtocolNumber
	}
	accept := func() stack.Target { return &stack.AcceptTarget{NetworkProtocol: netProto} }
	rules := []stack.Rule{natRule(spec.ipv6, accept(), 0), natRule(spec.ipv6, accept(), 0), natRule(spec.ipv6, accept(), 0)}
	postUnderflow := len(rules)
	policy := spec.policy
	if policy == nil {
		policy = accept()
	}
	if spec.postAfterMarker {
		// The POSTROUTING policy comes first. The entry follows the marker
		// of user chain "pre", and the chain ends with RETURN, which ends
		// in the policy.
		rules = append(rules, natRule(spec.ipv6, policy, 0))
		rules = append(rules, natRule(spec.ipv6, &stack.UserChainTarget{Name: "pre", NetworkProtocol: netProto}, 0))
	}
	postStart := len(rules)
	rules = append(rules, spec.post...)
	if spec.postAfterMarker {
		rules = append(rules, natRule(spec.ipv6, &stack.ReturnTarget{NetworkProtocol: netProto}, 0))
	} else {
		postUnderflow = len(rules)
		rules = append(rules, natRule(spec.ipv6, policy, 0))
	}
	var markers []int
	for k, chain := range spec.chains {
		markers = append(markers, len(rules))
		rules = append(rules, natRule(spec.ipv6, &stack.UserChainTarget{Name: fmt.Sprintf("c%d", k), NetworkProtocol: netProto}, 0))
		rules = append(rules, chain...)
	}
	if !spec.noEnd {
		rules = append(rules, natRule(spec.ipv6, &stack.ErrorTarget{NetworkProtocol: netProto}, 0))
	}
	for i := range rules {
		if j, ok := rules[i].Target.(*netfilter.JumpTarget); ok && j.RuleNum < 0 {
			if j.RuleNum <= -1000 {
				j.RuleNum = markers[-(j.RuleNum+1000)-1]
			} else {
				j.RuleNum = markers[-j.RuleNum-1] + 1
			}
			j.NetworkProtocol = netProto
		}
	}
	return stack.Table{
		Rules: rules,
		BuiltinChains: [stack.NumHooks]int{
			stack.Prerouting:  0,
			stack.Input:       1,
			stack.Forward:     stack.HookUnset,
			stack.Output:      2,
			stack.Postrouting: postStart,
		},
		Underflows: [stack.NumHooks]int{
			stack.Prerouting:  0,
			stack.Input:       1,
			stack.Forward:     stack.HookUnset,
			stack.Output:      2,
			stack.Postrouting: postUnderflow,
		},
	}
}

// jumpChains returns n user chains where chain k jumps to chain k+1, and the
// last chain only returns.
func jumpChains(n int) [][]stack.Rule {
	var chains [][]stack.Rule
	for k := 0; k < n; k++ {
		var chain []stack.Rule
		if k+1 < n {
			chain = append(chain, natRule(false, jumpTo(k+1), header.TCPProtocolNumber))
		}
		chain = append(chain, natRule(false, &stack.ReturnTarget{NetworkProtocol: header.IPv4ProtocolNumber}, 0))
		chains = append(chains, chain)
	}
	return chains
}

func TestCheckRestorableRootNATRules(t *testing.T) {
	const (
		ipv4Proto = header.IPv4ProtocolNumber
		ipv6Proto = header.IPv6ProtocolNumber
		tcp       = header.TCPProtocolNumber
		udp       = header.UDPProtocolNumber
	)
	snat := &stack.SNATTarget{NetworkProtocol: ipv4Proto, Addr: tcpip.AddrFrom4([4]byte{10, 0, 0, 1}), ChangeAddress: true}
	snat6 := &stack.SNATTarget{NetworkProtocol: ipv6Proto, Addr: tcpip.AddrFrom16([16]byte{0xfd, 15: 1}), ChangeAddress: true}
	masquerade := &stack.MasqueradeTarget{NetworkProtocol: ipv4Proto}
	dnat := &stack.DNATTarget{NetworkProtocol: ipv4Proto, Addr: tcpip.AddrFrom4([4]byte{127, 0, 0, 1}), Port: 9, ChangeAddress: true, ChangePort: true}
	redirect := &stack.RedirectTarget{NetworkProtocol: ipv4Proto, Port: 15001}
	drop := &stack.DropTarget{NetworkProtocol: ipv4Proto}
	drop6 := &stack.DropTarget{NetworkProtocol: ipv6Proto}
	ret := func() stack.Rule {
		return natRule(false, &stack.ReturnTarget{NetworkProtocol: ipv4Proto}, 0)
	}
	ownerRule := natRule(false, &stack.AcceptTarget{NetworkProtocol: ipv4Proto}, 0)
	ownerRule.Matchers = []stack.Matcher{&netfilter.OwnerMatcher{}}
	for _, tc := range []struct {
		name    string
		spec    natTableSpec
		filter  bool
		wantErr bool
	}{
		{name: "SNAT TCP", spec: natTableSpec{post: []stack.Rule{natRule(false, snat, tcp)}}},
		{name: "MASQUERADE UDP", spec: natTableSpec{post: []stack.Rule{natRule(false, masquerade, udp)}}},
		{name: "jump to a user chain with SNAT", spec: natTableSpec{post: []stack.Rule{natRule(false, jumpTo(0), tcp)}, chains: [][]stack.Rule{{natRule(false, snat, tcp), ret()}}}},
		{name: "jumps shorter than the limit", spec: natTableSpec{post: []stack.Rule{natRule(false, jumpTo(0), tcp)}, chains: jumpChains(stack.MaxJumps - 1)}},
		{name: "IPv6 SNAT TCP", spec: natTableSpec{ipv6: true, post: []stack.Rule{natRule(true, snat6, tcp)}}},
		{name: "SNAT without a protocol", spec: natTableSpec{post: []stack.Rule{natRule(false, snat, 0)}}, wantErr: true},
		{name: "SNAT ICMP", spec: natTableSpec{post: []stack.Rule{natRule(false, snat, header.ICMPv4ProtocolNumber)}}, wantErr: true},
		{name: "DNAT", spec: natTableSpec{post: []stack.Rule{natRule(false, dnat, tcp)}}, wantErr: true},
		{name: "REDIRECT", spec: natTableSpec{post: []stack.Rule{natRule(false, redirect, tcp)}}, wantErr: true},
		{name: "DROP rule", spec: natTableSpec{post: []stack.Rule{natRule(false, drop, tcp)}}, wantErr: true},
		{name: "DROP policy", spec: natTableSpec{post: []stack.Rule{natRule(false, snat, tcp)}, policy: drop}, wantErr: true},
		{name: "owner matcher", spec: natTableSpec{post: []stack.Rule{ownerRule}}, wantErr: true},
		{name: "no ERROR rule at the end", spec: natTableSpec{post: []stack.Rule{natRule(false, snat, tcp)}, noEnd: true}, wantErr: true},
		{name: "jump cycle", spec: natTableSpec{post: []stack.Rule{natRule(false, jumpTo(0), tcp)}, chains: [][]stack.Rule{{natRule(false, jumpTo(0), tcp), ret()}}}, wantErr: true},
		{name: "jumps as long as the limit", spec: natTableSpec{post: []stack.Rule{natRule(false, jumpTo(0), tcp)}, chains: jumpChains(stack.MaxJumps)}, wantErr: true},
		{name: "jumps as long as the limit from a built-in chain after a marker", spec: natTableSpec{postAfterMarker: true, post: []stack.Rule{natRule(false, jumpTo(0), tcp)}, chains: jumpChains(stack.MaxJumps)}, wantErr: true},
		{name: "jump to a user chain marker", spec: natTableSpec{post: []stack.Rule{natRule(false, jumpToMarker(0), tcp)}, chains: [][]stack.Rule{{natRule(false, snat, tcp), ret()}}}, wantErr: true},
		{name: "marker after a conditional rule", spec: natTableSpec{chains: [][]stack.Rule{{natRule(false, snat, tcp)}, {ret()}}}, wantErr: true},
		{name: "IPv6 DROP policy", spec: natTableSpec{ipv6: true, post: []stack.Rule{natRule(true, snat6, tcp)}, policy: drop6}, wantErr: true},
		{name: "SNAT TCP and filter change", spec: natTableSpec{post: []stack.Rule{natRule(false, snat, tcp)}}, filter: true, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := netstack.NewStack(stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol}}), 1)
			defer s.Destroy()
			s.InitDefaultTables()
			if err := s.Stack.CreateNICWithOptions(1, stack.NewBridgeEndpoint(1500), stack.NICOptions{Name: "br0", Kind: stack.NICKindBridge, Preserve: true}); err != nil {
				t.Fatalf("CreateNICWithOptions: %s", err)
			}
			s.Stack.IPTables().ReplaceTable(stack.NATID, tc.spec.table(), tc.spec.ipv6)
			if tc.filter {
				addFilterRule(s)
			}
			if err := s.CheckRestorable(true /* isRoot */); (err != nil) != tc.wantErr {
				t.Errorf("CheckRestorable(true) = %v, want error: %t", err, tc.wantErr)
			}
			// A non-root stack refuses any replaced table.
			if err := s.CheckRestorable(false /* isRoot */); err == nil {
				t.Errorf("CheckRestorable(false) = nil, want error")
			}
		})
	}
}

func TestCheckRestorableNetworkDevices(t *testing.T) {
	const (
		devID    = 1
		bridgeID = 2
	)
	for _, tc := range []struct {
		name string
		// devLoopback makes the device a loopback device.
		devLoopback bool
		// devPreserve preserves the device.
		devPreserve bool
		// bridge adds a preserved bridge with the device as its port.
		bridge  bool
		isRoot  bool
		wantErr bool
	}{
		{name: "root host device", isRoot: true},
		{name: "root host device on a bridge", bridge: true, isRoot: true, wantErr: true},
		{name: "root veth on a bridge", devPreserve: true, bridge: true, isRoot: true},
		{name: "child preserved device", devPreserve: true},
		{name: "child unpreserved loopback", devLoopback: true},
		{name: "child host device", wantErr: true},
		{name: "child veth on a bridge", devPreserve: true, bridge: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := netstack.NewStack(stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol}}), 1)
			defer s.Destroy()
			s.InitDefaultTables()
			var ep stack.LinkEndpoint = ethernet.New(channel.New(1, 1500, "\x02\x02\x03\x04\x05\x06"))
			if tc.devLoopback {
				ep = loopback.New()
			}
			if err := s.Stack.CreateNICWithOptions(devID, ep, stack.NICOptions{Name: "dev0", Preserve: tc.devPreserve}); err != nil {
				t.Fatalf("CreateNICWithOptions(dev0): %s", err)
			}
			if tc.bridge {
				if err := s.Stack.CreateNICWithOptions(bridgeID, stack.NewBridgeEndpoint(1500), stack.NICOptions{Name: "br0", Kind: stack.NICKindBridge, Preserve: true}); err != nil {
					t.Fatalf("CreateNICWithOptions(br0): %s", err)
				}
				if err := s.Stack.SetNICCoordinator(devID, bridgeID); err != nil {
					t.Fatalf("SetNICCoordinator: %s", err)
				}
			}
			if err := s.CheckRestorable(tc.isRoot); (err != nil) != tc.wantErr {
				t.Errorf("CheckRestorable(%t) = %v, want error: %t", tc.isRoot, err, tc.wantErr)
			}
		})
	}
}

func TestCheckRestorableStacksChecksGrandchildDevices(t *testing.T) {
	ctx := contexttest.Context(t)
	root := netstack.NewStack(stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol}}), 1)
	root.InitDefaultTables()
	userNS := auth.NewRootUserNamespace()
	rootNS := inet.NewRootNamespace(root, netstackCreator{}, userNS)
	defer root.Destroy()
	childNS := inet.NewNamespace(rootNS, userNS)
	defer childNS.Destroy(ctx)
	grandchildNS := inet.NewNamespace(childNS, userNS)
	defer grandchildNS.Destroy(ctx)

	// A host device in the root namespace does not block save.
	ethID := root.Stack.NextNICID()
	if err := root.Stack.CreateNICWithOptions(ethID, ethernet.New(channel.New(1, 1500, "\x02\x02\x03\x04\x05\x06")), stack.NICOptions{Name: "eth0"}); err != nil {
		t.Fatalf("CreateNICWithOptions(eth0): %s", err)
	}
	if err := rootNS.CheckRestorableStacks(); err != nil {
		t.Fatalf("CheckRestorableStacks() with a root host device = %v, want nil", err)
	}

	// Move the host device into the grandchild namespace.
	grandchild := grandchildNS.Stack().(*netstack.Stack)
	if _, err := root.Stack.SetNICStack(ethID, grandchild.Stack, ""); err != nil {
		t.Fatalf("SetNICStack: %s", err)
	}
	if err := rootNS.CheckRestorableStacks(); err == nil {
		t.Error("CheckRestorableStacks() with a host device in a grandchild namespace = nil, want error")
	}
}

func TestDestroyAsyncCallsDoneAfterTeardown(t *testing.T) {
	s := netstack.NewStack(stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol}}), 1)
	peer := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol}})
	defer peer.Destroy()
	ep, peerEP := veth.NewPair(1500, veth.DefaultBacklogSize)
	const id = 1
	if err := s.Stack.CreateNICWithOptions(id, ep, stack.NICOptions{Name: "veth0"}); err != nil {
		t.Fatalf("CreateNICWithOptions(veth0): %s", err)
	}
	if err := peer.CreateNICWithOptions(id, peerEP, stack.NICOptions{Name: "veth1"}); err != nil {
		t.Fatalf("CreateNICWithOptions(veth1): %s", err)
	}
	hasNIC := make(chan bool, 2)
	s.DestroyAsync(func() {
		// Stack.Wait removes all NICs. done must run after it.
		hasNIC <- s.Stack.HasNIC(id)
	})
	select {
	case has := <-hasNIC:
		if has {
			t.Error("DestroyAsync called done before Stack.Wait removed the NIC")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("DestroyAsync did not call done")
	}
	select {
	case <-hasNIC:
		t.Error("DestroyAsync called done more than once")
	case <-time.After(100 * time.Millisecond):
	}
}

// addFilterRule replaces the filter table of s with a copy of itself, which
// marks the iptables rules of s as modified.
func addFilterRule(s *netstack.Stack) {
	tables := s.Stack.IPTables()
	tables.ForceReplaceTable(stack.FilterID, tables.GetTable(stack.FilterID, false /* ipv6 */), false /* ipv6 */)
}

type netstackCreator struct{}

// CreateStack implements inet.NetworkStackCreator.CreateStack.
func (netstackCreator) CreateStack() (inet.Stack, error) {
	s := netstack.NewStack(stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol}}), 1)
	s.InitDefaultTables()
	return s, nil
}

func TestCheckRestorableStacksChecksChildNamespaces(t *testing.T) {
	ctx := contexttest.Context(t)
	root := netstack.NewStack(stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol}}), 1)
	root.InitDefaultTables()
	userNS := auth.NewRootUserNamespace()
	rootNS := inet.NewRootNamespace(root, netstackCreator{}, userNS)
	defer root.Destroy()
	childNS := inet.NewNamespace(rootNS, userNS)
	defer childNS.Destroy(ctx)
	child := childNS.Stack().(*netstack.Stack)
	// The child has only its preserved loopback NIC, as the sandbox creates it.
	if err := child.Stack.CreateNICWithOptions(1, loopback.New(), stack.NICOptions{Name: "lo", Preserve: true}); err != nil {
		t.Fatalf("CreateNICWithOptions: %s", err)
	}
	if err := rootNS.CheckRestorableStacks(); err != nil {
		t.Fatalf("CheckRestorableStacks() without rules = %v, want nil", err)
	}
	// Rules in the root namespace with only a loopback NIC do not block save.
	if err := root.Stack.CreateNICWithOptions(1, loopback.New(), stack.NICOptions{Name: "lo"}); err != nil {
		t.Fatalf("CreateNICWithOptions(lo): %s", err)
	}
	addFilterRule(root)
	if err := rootNS.CheckRestorableStacks(); err != nil {
		t.Fatalf("CheckRestorableStacks() with iptables rules in the root namespace only = %v, want nil", err)
	}
	addFilterRule(child)
	if err := rootNS.CheckRestorableStacks(); err == nil {
		t.Error("CheckRestorableStacks() with iptables rules in a child namespace = nil, want error")
	}
}

// stackQueueCreator hands out stacks in order.
type stackQueueCreator struct {
	stacks []inet.Stack
}

// CreateStack implements inet.NetworkStackCreator.CreateStack.
func (c *stackQueueCreator) CreateStack() (inet.Stack, error) {
	s := c.stacks[0]
	c.stacks = c.stacks[1:]
	return s, nil
}

// slowResumeStack runs wait before it resumes its endpoints.
type slowResumeStack struct {
	*netstack.Stack
	wait func()
}

// ResumeEndpoints implements inet.Stack.ResumeEndpoints.
func (s *slowResumeStack) ResumeEndpoints() {
	s.wait()
	s.Stack.ResumeEndpoints()
}

func newUDPStack() *netstack.Stack {
	s := netstack.NewStack(stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{arp.NewProtocol, ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
	}), 1)
	s.InitDefaultTables()
	return s
}

// readUDP waits until ep has a datagram and returns its payload.
func readUDP(t *testing.T, ep tcpip.Endpoint) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var b bytes.Buffer
		_, err := ep.Read(&b, tcpip.ReadOptions{})
		if err == nil {
			return b.String()
		}
		if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
			t.Fatalf("Read: %s", err)
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for a UDP datagram")
		}
		time.Sleep(time.Millisecond)
	}
}

// TestResumeStacksDeliversVethBacklog checks that a datagram that waits in the
// queue of a veth pair during a save reaches its socket after ResumeStacks.
// The root stack holds one end of the veth pair and resumes first. Another
// child stack resumes between the root stack and the receiving child stack,
// and waits until the receiving stack gets a packet or a short time passes.
func TestResumeStacksDeliversVethBacklog(t *testing.T) {
	ctx := contexttest.Context(t)
	userNS := auth.NewRootUserNamespace()
	root := newUDPStack()
	receiver := newUDPStack()
	slow := &slowResumeStack{Stack: newUDPStack()}
	creator := &stackQueueCreator{stacks: []inet.Stack{slow, receiver}}
	rootNS := inet.NewRootNamespace(root, creator, userNS)
	defer root.Destroy()
	slowNS := inet.NewNamespace(rootNS, userNS)
	defer slowNS.Destroy(ctx)
	receiverNS := inet.NewNamespace(rootNS, userNS)
	defer receiverNS.Destroy(ctx)
	child := receiverNS.Stack().(*netstack.Stack)

	rootVeth, childVeth := veth.NewPair(1500, veth.DefaultBacklogSize)
	rootVeth.SetLinkAddress("\x02\x00\x00\x00\x00\x01")
	childVeth.SetLinkAddress("\x02\x00\x00\x00\x00\x02")
	rootAddr := tcpip.AddressWithPrefix{Address: tcpip.AddrFrom4([4]byte{10, 1, 0, 1}), PrefixLen: 24}
	childAddr := tcpip.AddressWithPrefix{Address: tcpip.AddrFrom4([4]byte{10, 1, 0, 2}), PrefixLen: 24}
	for _, c := range []struct {
		s    *netstack.Stack
		ep   *veth.Endpoint
		addr tcpip.AddressWithPrefix
	}{
		{root, rootVeth, rootAddr},
		{child, childVeth, childAddr},
	} {
		if err := c.s.Stack.CreateNICWithOptions(1, ethernet.New(c.ep), stack.NICOptions{Name: "veth0", Kind: stack.NICKindVeth, Preserve: true}); err != nil {
			t.Fatalf("CreateNICWithOptions: %s", err)
		}
		if err := c.s.Stack.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: c.addr}, stack.AddressProperties{}); err != nil {
			t.Fatalf("AddProtocolAddress: %s", err)
		}
		c.s.Stack.SetRouteTable([]tcpip.Route{{Destination: c.addr.Subnet(), NIC: 1}})
	}

	var rootWQ, childWQ waiter.Queue
	rootEP, err := root.Stack.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &rootWQ)
	if err != nil {
		t.Fatalf("root NewEndpoint: %s", err)
	}
	defer rootEP.Close()
	childEP, err := child.Stack.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &childWQ)
	if err != nil {
		t.Fatalf("child NewEndpoint: %s", err)
	}
	defer childEP.Close()
	childFull := tcpip.FullAddress{Addr: childAddr.Address, Port: 5000}
	if err := childEP.Bind(childFull); err != nil {
		t.Fatalf("child Bind: %s", err)
	}
	send := func(msg string) {
		t.Helper()
		var r bytes.Reader
		r.Reset([]byte(msg))
		if _, err := rootEP.Write(&r, tcpip.WriteOptions{To: &childFull}); err != nil {
			t.Fatalf("root Write(%q): %s", msg, err)
		}
	}

	// Resolve the link address before the save, so the next datagram goes
	// straight to the veth queue.
	send("warm-up")
	if got := readUDP(t, childEP); got != "warm-up" {
		t.Fatalf("child read %q, want %q", got, "warm-up")
	}

	rootNS.PauseStacks()
	send("backlog")
	received := child.Stack.Stats().IP.PacketsReceived.Value()
	slow.wait = func() {
		deadline := time.Now().Add(200 * time.Millisecond)
		for child.Stack.Stats().IP.PacketsReceived.Value() == received && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
	}
	saved := []any{root.Stack, child.Stack, rootEP, childEP, &rootWQ, &childWQ}
	var buf bytes.Buffer
	if _, err := state.Save(ctx, &buf, &saved); err != nil {
		t.Fatalf("state.Save: %v", err)
	}
	rootNS.ResumeStacks()

	if got := readUDP(t, childEP); got != "backlog" {
		t.Fatalf("child read %q after ResumeStacks, want %q", got, "backlog")
	}
}
