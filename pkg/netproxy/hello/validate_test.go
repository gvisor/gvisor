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
	"bytes"
	"fmt"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	pb "gvisor.dev/gvisor/pkg/netproxy/hello/hello_go_proto"
)

func TestValidateConfig(t *testing.T) {
	u32 := func(v uint32) *uint32 { return &v }
	for _, tc := range []struct {
		name   string
		offer  *pb.Offer
		modify func(c *pb.Config)
		code   pb.ErrorCode // Unspecified: valid.
		field  string
	}{
		{name: "valid"},
		{name: "IPv4 only", modify: func(c *pb.Config) {
			c.Addresses = c.Addresses[:1]
			c.Routes = c.Routes[:2]
			c.Mtu = minMTU
		}},
		{name: "no routes", modify: func(c *pb.Config) { c.Routes = nil }},
		{name: "ifname", modify: func(c *pb.Config) { c.Ifname = "net1_a.b-c" }},
		{name: "ifname 15 bytes", modify: func(c *pb.Config) { c.Ifname = strings.Repeat("a", 15) }},
		{name: "link_index echoed", offer: &pb.Offer{LinkIndex: 1, LinkCount: 2}, modify: func(c *pb.Config) {
			c.Ifname = "net1"
			c.LinkIndex = u32(1)
		}},
		{name: "link_index 0 echoed", modify: func(c *pb.Config) { c.LinkIndex = u32(0) }},
		{name: "route mtu equal to link mtu", modify: func(c *pb.Config) { c.Routes[0].Mtu = 1500 }},
		{name: "route mtu minimum", modify: func(c *pb.Config) { c.Routes[0].Mtu = minMTU }},
		{name: "gateway on non-default route", modify: func(c *pb.Config) {
			c.Routes = append(c.Routes, route("192.168.0.0/16", "10.0.0.254"))
		}},
		{name: "IPv6 link-local address", modify: func(c *pb.Config) {
			c.Addresses = append(c.Addresses, addr("fe80::2/64"))
		}},
		{name: "offloads", modify: func(c *pb.Config) { c.Offloads = &pb.Offloads{TxCsum: true, RxCsum: true} }},
		{name: "gateway within on-link route", modify: func(c *pb.Config) {
			c.Addresses = []*pb.Address{addr("10.1.2.3/32")}
			c.Routes = []*pb.Route{route("169.254.1.1/32", ""), route("0.0.0.0/0", "169.254.1.1")}
		}},
		{name: "IPv6 link-local gateway", modify: func(c *pb.Config) {
			c.Addresses[1] = addr("2001:db8::2/128")
			c.Routes = []*pb.Route{route("::/0", "fe80::1")}
		}},
		{name: "on-link default routes", modify: func(c *pb.Config) {
			c.Addresses = []*pb.Address{addr("192.0.2.7/32"), addr("2001:db8::7/128")}
			c.Routes = []*pb.Route{route("0.0.0.0/0", ""), route("::/0", "")}
		}},
		{name: "gateway within an on-link default route", modify: func(c *pb.Config) {
			c.Addresses = c.Addresses[:1]
			c.Routes = []*pb.Route{route("172.16.0.0/12", "192.0.2.1"), route("0.0.0.0/0", "")}
		}},

		// required_features.
		{name: "unknown required feature", modify: func(c *pb.Config) { c.RequiredFeatures = []string{"virtio_net_hdr"} },
			code: pb.ErrorCode_ERROR_CODE_UNKNOWN_FEATURE, field: "required_features[0]"},
		{name: "too many required features", modify: func(c *pb.Config) { c.RequiredFeatures = make([]string, 9) },
			code: pb.ErrorCode_ERROR_CODE_LIMIT_EXCEEDED, field: "required_features"},
		{name: "required feature too long", modify: func(c *pb.Config) { c.RequiredFeatures = []string{strings.Repeat("a", 65)} },
			code: pb.ErrorCode_ERROR_CODE_LIMIT_EXCEEDED, field: "required_features[0]"},
		{name: "required feature empty", modify: func(c *pb.Config) { c.RequiredFeatures = []string{""} },
			code: pb.ErrorCode_ERROR_CODE_INVALID_VALUE, field: "required_features[0]"},
		{name: "required feature bad character", modify: func(c *pb.Config) { c.RequiredFeatures = []string{"virtio-net"} },
			code: pb.ErrorCode_ERROR_CODE_INVALID_VALUE, field: "required_features[0]"},
		{name: "required feature upper case", modify: func(c *pb.Config) { c.RequiredFeatures = []string{"Virtio"} },
			code: pb.ErrorCode_ERROR_CODE_INVALID_VALUE, field: "required_features[0]"},

		// link_index.
		{name: "link_index mismatch", offer: &pb.Offer{LinkIndex: 1, LinkCount: 2}, modify: func(c *pb.Config) {
			c.Ifname = "net1"
			c.LinkIndex = u32(0)
		}, code: pb.ErrorCode_ERROR_CODE_INVALID_VALUE, field: "link_index"},

		// ifname.
		{name: "ifname required with several links", offer: &pb.Offer{LinkIndex: 0, LinkCount: 2},
			code: pb.ErrorCode_ERROR_CODE_INVALID_VALUE, field: "ifname"},
		{name: "ifname too long", modify: func(c *pb.Config) { c.Ifname = strings.Repeat("a", 16) },
			code: pb.ErrorCode_ERROR_CODE_INVALID_VALUE, field: "ifname"},
		{name: "ifname bad character", modify: func(c *pb.Config) { c.Ifname = "eth/0" },
			code: pb.ErrorCode_ERROR_CODE_INVALID_VALUE, field: "ifname"},
		{name: "ifname space", modify: func(c *pb.Config) { c.Ifname = "eth 0" },
			code: pb.ErrorCode_ERROR_CODE_INVALID_VALUE, field: "ifname"},
		{name: "ifname lo", modify: func(c *pb.Config) { c.Ifname = "lo" },
			code: pb.ErrorCode_ERROR_CODE_INVALID_VALUE, field: "ifname"},
		{name: "ifname dot", modify: func(c *pb.Config) { c.Ifname = "." },
			code: pb.ErrorCode_ERROR_CODE_INVALID_VALUE, field: "ifname"},
		{name: "ifname dotdot", modify: func(c *pb.Config) { c.Ifname = ".." },
			code: pb.ErrorCode_ERROR_CODE_INVALID_VALUE, field: "ifname"},

		// mtu.
		{name: "mtu unset", modify: func(c *pb.Config) {
			c.Addresses = c.Addresses[:1]
			c.Routes = c.Routes[:2]
			c.Mtu = 0
		}, code: pb.ErrorCode_ERROR_CODE_INVALID_VALUE, field: "mtu"},
		{name: "mtu too small", modify: func(c *pb.Config) {
			c.Addresses = c.Addresses[:1]
			c.Routes = c.Routes[:2]
			c.Mtu = minMTU - 1
		}, code: pb.ErrorCode_ERROR_CODE_INVALID_VALUE, field: "mtu"},
		{name: "mtu too large", modify: func(c *pb.Config) { c.Mtu = maxMTU + 1 },
			code: pb.ErrorCode_ERROR_CODE_INVALID_VALUE, field: "mtu"},
		{name: "mtu below IPv6 minimum", modify: func(c *pb.Config) {
			c.Mtu = minIPv6MTU - 1
			c.Routes = nil
		}, code: pb.ErrorCode_ERROR_CODE_INVALID_VALUE, field: "mtu"},

		// addresses.
		{name: "no addresses", modify: func(c *pb.Config) {
			c.Addresses = nil
			c.Routes = nil
		}, code: pb.ErrorCode_ERROR_CODE_INVALID_VALUE, field: "addresses"},
		{name: "too many addresses", modify: func(c *pb.Config) {
			c.Addresses = nil
			for i := range maxAddresses + 1 {
				c.Addresses = append(c.Addresses, addr(fmt.Sprintf("10.0.0.%d/24", i+2)))
			}
		}, code: pb.ErrorCode_ERROR_CODE_LIMIT_EXCEEDED, field: "addresses"},
		{name: "address length", modify: func(c *pb.Config) { c.Addresses[1].Ip = make([]byte, 5) },
			code: pb.ErrorCode_ERROR_CODE_INVALID_VALUE, field: "addresses[1].ip"},
		{name: "address unspecified", modify: func(c *pb.Config) { c.Addresses[0] = addr("0.0.0.0/8") },
			code: pb.ErrorCode_ERROR_CODE_INVALID_VALUE, field: "addresses[0].ip"},
		{name: "address IPv6 unspecified", modify: func(c *pb.Config) { c.Addresses[1] = addr("::/64") },
			code: pb.ErrorCode_ERROR_CODE_INVALID_VALUE, field: "addresses[1].ip"},
		{name: "address multicast", modify: func(c *pb.Config) { c.Addresses[0] = addr("224.0.0.1/4") },
			code: pb.ErrorCode_ERROR_CODE_INVALID_VALUE, field: "addresses[0].ip"},
		{name: "address IPv6 multicast", modify: func(c *pb.Config) { c.Addresses[1] = addr("ff02::1/16") },
			code: pb.ErrorCode_ERROR_CODE_INVALID_VALUE, field: "addresses[1].ip"},
		{name: "address loopback", modify: func(c *pb.Config) { c.Addresses[0] = addr("127.0.0.2/8") },
			code: pb.ErrorCode_ERROR_CODE_INVALID_VALUE, field: "addresses[0].ip"},
		{name: "address IPv6 loopback", modify: func(c *pb.Config) { c.Addresses[1] = addr("::1/128") },
			code: pb.ErrorCode_ERROR_CODE_INVALID_VALUE, field: "addresses[1].ip"},
		{name: "address limited broadcast", modify: func(c *pb.Config) { c.Addresses[0] = addr("255.255.255.255/32") },
			code: pb.ErrorCode_ERROR_CODE_INVALID_VALUE, field: "addresses[0].ip"},
		{name: "address IPv4-mapped", modify: func(c *pb.Config) { c.Addresses[1] = addr("::ffff:10.0.0.3/120") },
			code: pb.ErrorCode_ERROR_CODE_INVALID_VALUE, field: "addresses[1].ip"},
		{name: "address prefix 0", modify: func(c *pb.Config) { c.Addresses[0].PrefixLen = 0 },
			code: pb.ErrorCode_ERROR_CODE_INVALID_VALUE, field: "addresses[0].prefix_len"},
		{name: "address IPv4 prefix 33", modify: func(c *pb.Config) { c.Addresses[0].PrefixLen = 33 },
			code: pb.ErrorCode_ERROR_CODE_INVALID_VALUE, field: "addresses[0].prefix_len"},
		{name: "address IPv6 prefix 129", modify: func(c *pb.Config) { c.Addresses[1].PrefixLen = 129 },
			code: pb.ErrorCode_ERROR_CODE_INVALID_VALUE, field: "addresses[1].prefix_len"},
		{name: "duplicate address", modify: func(c *pb.Config) {
			c.Addresses = append(c.Addresses, addr("10.0.0.2/16"))
		}, code: pb.ErrorCode_ERROR_CODE_INVALID_VALUE, field: "addresses[2].ip"},

		// routes.
		{name: "too many routes", modify: func(c *pb.Config) {
			c.Routes = nil
			for i := range maxRoutes + 1 {
				c.Routes = append(c.Routes, route(fmt.Sprintf("10.%d.%d.0/24", i/256, i%256), ""))
			}
		}, code: pb.ErrorCode_ERROR_CODE_LIMIT_EXCEEDED, field: "routes"},
		{name: "route dst length", modify: func(c *pb.Config) { c.Routes[0].Dst = make([]byte, 3) },
			code: pb.ErrorCode_ERROR_CODE_INVALID_VALUE, field: "routes[0].dst"},
		{name: "route dst IPv4-mapped", modify: func(c *pb.Config) { c.Routes[2] = route("::ffff:10.0.0.0/120", "") },
			code: pb.ErrorCode_ERROR_CODE_INVALID_VALUE, field: "routes[2].dst"},
		{name: "route IPv4 prefix 33", modify: func(c *pb.Config) { c.Routes[0].DstPrefixLen = 33 },
			code: pb.ErrorCode_ERROR_CODE_INVALID_VALUE, field: "routes[0].dst_prefix_len"},
		{name: "route IPv6 prefix 129", modify: func(c *pb.Config) { c.Routes[2].DstPrefixLen = 129 },
			code: pb.ErrorCode_ERROR_CODE_INVALID_VALUE, field: "routes[2].dst_prefix_len"},
		{name: "route host bits", modify: func(c *pb.Config) { c.Routes[0].Dst = ip("10.0.0.1") },
			code: pb.ErrorCode_ERROR_CODE_INVALID_VALUE, field: "routes[0].dst"},
		{name: "default route host bits", modify: func(c *pb.Config) { c.Routes[1].Dst = ip("10.0.0.0") },
			code: pb.ErrorCode_ERROR_CODE_INVALID_VALUE, field: "routes[1].dst"},
		{name: "duplicate route", modify: func(c *pb.Config) {
			c.Routes = append(c.Routes, route("10.0.0.0/24", "10.0.0.1"))
		}, code: pb.ErrorCode_ERROR_CODE_INVALID_VALUE, field: "routes[4].dst"},
		{name: "gateway length", modify: func(c *pb.Config) { c.Routes[1].Gateway = ip("2001:db8::1") },
			code: pb.ErrorCode_ERROR_CODE_INVALID_VALUE, field: "routes[1].gateway"},
		// The address prefixes below contain each unusable gateway, so only
		// the gateway's kind rejects it.
		{name: "gateway unspecified", modify: func(c *pb.Config) {
			c.Addresses[0].PrefixLen = 1
			c.Routes[1].Gateway = ip("0.0.0.0")
		}, code: pb.ErrorCode_ERROR_CODE_INVALID_VALUE, field: "routes[1].gateway"},
		{name: "gateway loopback", modify: func(c *pb.Config) {
			c.Addresses[0].PrefixLen = 1
			c.Routes[1].Gateway = ip("127.0.0.1")
		}, code: pb.ErrorCode_ERROR_CODE_INVALID_VALUE, field: "routes[1].gateway"},
		{name: "gateway multicast", modify: func(c *pb.Config) {
			c.Addresses[0] = addr("192.168.0.2/1")
			c.Routes[1].Gateway = ip("224.0.0.1")
		}, code: pb.ErrorCode_ERROR_CODE_INVALID_VALUE, field: "routes[1].gateway"},
		{name: "gateway limited broadcast", modify: func(c *pb.Config) {
			c.Addresses[0] = addr("192.168.0.2/1")
			c.Routes[1].Gateway = ip("255.255.255.255")
		}, code: pb.ErrorCode_ERROR_CODE_INVALID_VALUE, field: "routes[1].gateway"},
		{name: "gateway IPv6 multicast", modify: func(c *pb.Config) {
			c.Addresses[1] = addr("fe80::2/7")
			c.Routes[3].Gateway = ip("ff02::1")
		}, code: pb.ErrorCode_ERROR_CODE_INVALID_VALUE, field: "routes[3].gateway"},
		{name: "gateway IPv6 loopback", modify: func(c *pb.Config) {
			c.Addresses[1] = addr("::2/8")
			c.Routes[3].Gateway = ip("::1")
		}, code: pb.ErrorCode_ERROR_CODE_INVALID_VALUE, field: "routes[3].gateway"},
		{name: "gateway IPv4-mapped", modify: func(c *pb.Config) {
			c.Addresses[1] = addr("::2/8")
			c.Routes[3].Gateway = ip("::ffff:10.0.0.1")
		}, code: pb.ErrorCode_ERROR_CODE_INVALID_VALUE, field: "routes[3].gateway"},
		{name: "gateway outside address prefixes", modify: func(c *pb.Config) {
			c.Routes = append(c.Routes, route("10.0.0.0/8", "192.168.1.1"))
		}, code: pb.ErrorCode_ERROR_CODE_INVALID_VALUE, field: "routes[4].gateway"},
		{name: "IPv6 gateway outside address prefixes", modify: func(c *pb.Config) { c.Routes[3].Gateway = ip("2001:db9::1") },
			code: pb.ErrorCode_ERROR_CODE_INVALID_VALUE, field: "routes[3].gateway"},
		{name: "gateway within a route with a gateway", modify: func(c *pb.Config) {
			c.Routes = append(c.Routes, route("169.254.1.0/24", "10.0.0.1"), route("172.16.0.0/12", "169.254.1.1"))
		}, code: pb.ErrorCode_ERROR_CODE_INVALID_VALUE, field: "routes[5].gateway"},
		{name: "IPv6 gateway within only an IPv4 on-link default route", modify: func(c *pb.Config) {
			c.Routes = []*pb.Route{route("0.0.0.0/0", ""), route("2001:db9::/32", "2001:dba::1")}
		}, code: pb.ErrorCode_ERROR_CODE_INVALID_VALUE, field: "routes[1].gateway"},
		{name: "gateway within a default route", modify: func(c *pb.Config) {
			c.Routes = append(c.Routes, route("172.16.0.0/12", "192.0.2.1"))
		}, code: pb.ErrorCode_ERROR_CODE_INVALID_VALUE, field: "routes[4].gateway"},
		{name: "gateway is the link's address", modify: func(c *pb.Config) { c.Routes[1].Gateway = ip("10.0.0.2") },
			code: pb.ErrorCode_ERROR_CODE_INVALID_VALUE, field: "routes[1].gateway"},
		{name: "IPv6 gateway is the link's address", modify: func(c *pb.Config) { c.Routes[3].Gateway = ip("2001:db8::2") },
			code: pb.ErrorCode_ERROR_CODE_INVALID_VALUE, field: "routes[3].gateway"},
		{name: "second IPv4 default route", modify: func(c *pb.Config) {
			c.Routes = append(c.Routes, route("0.0.0.0/0", "10.0.0.254"))
		}, code: pb.ErrorCode_ERROR_CODE_INVALID_VALUE, field: "routes[4]"},
		{name: "second IPv6 default route", modify: func(c *pb.Config) {
			c.Routes = append(c.Routes, route("::/0", "2001:db8::fe"))
		}, code: pb.ErrorCode_ERROR_CODE_INVALID_VALUE, field: "routes[4]"},
		{name: "route mtu too small", modify: func(c *pb.Config) { c.Routes[0].Mtu = minMTU - 1 },
			code: pb.ErrorCode_ERROR_CODE_INVALID_VALUE, field: "routes[0].mtu"},
		{name: "route mtu above link mtu", modify: func(c *pb.Config) { c.Routes[0].Mtu = 1501 },
			code: pb.ErrorCode_ERROR_CODE_INVALID_VALUE, field: "routes[0].mtu"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := validConfig()
			if tc.modify != nil {
				tc.modify(c)
			}
			offer := tc.offer
			if offer == nil {
				offer = singleLinkOffer()
			}
			err := ValidateConfig(c, offer)
			if tc.code == pb.ErrorCode_ERROR_CODE_UNSPECIFIED {
				if err != nil {
					t.Fatalf("ValidateConfig() = %v, want nil", err)
				}
				return
			}
			e := wantCode(t, err, tc.code)
			if e.Field != tc.field {
				t.Errorf("ValidateConfig() field = %q (%v), want %q", e.Field, e, tc.field)
			}
			if !strings.Contains(e.Message, strings.SplitN(tc.field, ".", 2)[0]) && tc.field != "" {
				t.Errorf("ValidateConfig() message %q does not name %q", e.Message, tc.field)
			}
		})
	}
}

func TestValidateConfigGatewayMessage(t *testing.T) {
	c := validConfig()
	c.Routes = append(c.Routes[:3], route("10.0.0.0/8", "192.168.1.1"))
	err := ValidateConfig(c, singleLinkOffer())
	if want := "routes[3] 10.0.0.0/8: gateway 192.168.1.1 is not within any address prefix or on-link route"; err == nil || err.Error() != want {
		t.Errorf("ValidateConfig() = %v, want %q", err, want)
	}
}

func TestValidateOffer(t *testing.T) {
	for _, tc := range []struct {
		name  string
		offer *pb.Offer
		code  pb.ErrorCode
		field string
	}{
		{name: "single link", offer: singleLinkOffer()},
		{name: "last of 16 links", offer: &pb.Offer{SupportedMajors: []uint32{1, 2}, LinkIndex: 15, LinkCount: 16, Restore: true, SandboxId: strings.Repeat("s", 128)}},
		{name: "no majors", offer: &pb.Offer{LinkCount: 1},
			code: pb.ErrorCode_ERROR_CODE_MALFORMED, field: "supported_majors"},
		{name: "too many majors", offer: &pb.Offer{SupportedMajors: make([]uint32, 17), LinkCount: 1},
			code: pb.ErrorCode_ERROR_CODE_LIMIT_EXCEEDED, field: "supported_majors"},
		{name: "sandbox_id too long", offer: &pb.Offer{SupportedMajors: []uint32{1}, LinkCount: 1, SandboxId: strings.Repeat("s", 129)},
			code: pb.ErrorCode_ERROR_CODE_LIMIT_EXCEEDED, field: "sandbox_id"},
		{name: "link_count 0", offer: &pb.Offer{SupportedMajors: []uint32{1}},
			code: pb.ErrorCode_ERROR_CODE_INVALID_VALUE, field: "link_count"},
		{name: "link_count 17", offer: &pb.Offer{SupportedMajors: []uint32{1}, LinkCount: 17},
			code: pb.ErrorCode_ERROR_CODE_INVALID_VALUE, field: "link_count"},
		{name: "link_index out of range", offer: &pb.Offer{SupportedMajors: []uint32{1}, LinkIndex: 1, LinkCount: 1},
			code: pb.ErrorCode_ERROR_CODE_INVALID_VALUE, field: "link_index"},
		{name: "unknown required feature", offer: &pb.Offer{SupportedMajors: []uint32{1}, LinkCount: 1, RequiredFeatures: []string{"a", "b"}},
			code: pb.ErrorCode_ERROR_CODE_UNKNOWN_FEATURE, field: "required_features[0]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateOffer(tc.offer)
			if tc.code == pb.ErrorCode_ERROR_CODE_UNSPECIFIED {
				if err != nil {
					t.Fatalf("ValidateOffer() = %v, want nil", err)
				}
				return
			}
			if e := wantCode(t, err, tc.code); e.Field != tc.field {
				t.Errorf("ValidateOffer() field = %q (%v), want %q", e.Field, e, tc.field)
			}
		})
	}
}

// TestWorstCaseConfigFits checks that the largest Config this major allows,
// without required features, fits in a datagram.
func TestWorstCaseConfigFits(t *testing.T) {
	linkIndex := uint32(MaxLinks - 1)
	c := &pb.Config{
		Mtu:       maxMTU,
		Offloads:  &pb.Offloads{TxCsum: true, RxCsum: true},
		Ifname:    strings.Repeat("n", maxIfnameLen),
		LinkIndex: &linkIndex,
	}
	ip := bytes.Repeat([]byte{0xff}, 16)
	for range maxAddresses {
		c.Addresses = append(c.Addresses, &pb.Address{Ip: ip, PrefixLen: 128})
	}
	for range maxRoutes {
		c.Routes = append(c.Routes, &pb.Route{Dst: ip, DstPrefixLen: 128, Gateway: ip, Mtu: maxMTU})
	}
	b := mustMarshal(t, Header{Type: TypeConfig, Major: Major}, c)
	if want := 12301; len(b) != want {
		t.Errorf("worst-case Config is %d bytes, want %d", len(b), want)
	}
}

// TestGatewayOnOtherLink checks that a gateway must be reachable on the
// route's own link: one inside another link's prefix only is rejected.
func TestGatewayOnOtherLink(t *testing.T) {
	c := &pb.Config{
		Mtu:       1500,
		Ifname:    "net1",
		LinkIndex: proto.Uint32(1),
		Addresses: []*pb.Address{addr("10.1.0.2/24")},
		Routes:    []*pb.Route{route("10.1.0.0/24", ""), route("0.0.0.0/0", "10.0.0.1")},
	}
	err := ValidateConfig(c, &pb.Offer{SupportedMajors: []uint32{Major}, LinkIndex: 1, LinkCount: 2})
	if e := wantCode(t, err, pb.ErrorCode_ERROR_CODE_INVALID_VALUE); e.Field != "routes[1].gateway" {
		t.Errorf("ValidateConfig() field = %q, want routes[1].gateway", e.Field)
	}
}

// TestValidateDoesNotModify checks that validation leaves its input as it was.
func TestValidateDoesNotModify(t *testing.T) {
	c := validConfig()
	want := proto.Clone(c)
	if err := ValidateConfig(c, singleLinkOffer()); err != nil {
		t.Fatalf("ValidateConfig() = %v", err)
	}
	if !proto.Equal(c, want) {
		t.Errorf("validation modified the Config: got %v, want %v", c, want)
	}
}
