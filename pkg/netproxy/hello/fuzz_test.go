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
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"
	pb "gvisor.dev/gvisor/pkg/netproxy/hello/hello_go_proto"
)

// seeds returns a valid datagram of each type.
func seeds(f *testing.F) [][]byte {
	var out [][]byte
	for _, m := range []struct {
		typ Type
		msg proto.Message
	}{
		{TypeOffer, singleLinkOffer()},
		{TypeConfig, validConfig()},
		{TypeConfig, &pb.Config{Mtu: 1500, Ifname: "net1", LinkIndex: proto.Uint32(1), Addresses: []*pb.Address{addr("10.1.0.2/24")}}},
		{TypeAck, &pb.Ack{}},
		{TypeError, (&Error{Code: pb.ErrorCode_ERROR_CODE_REFUSED, Field: "ifname", Message: "no"}).Proto()},
	} {
		b, err := Marshal(Header{Type: m.typ, Major: Major, XID: 7}, m.msg)
		if err != nil {
			f.Fatalf("Marshal(%v) failed: %v", m.typ, err)
		}
		out = append(out, b)
	}
	return out
}

// checkError fails t unless err is nil or an *Error with a known code.
func checkError(t *testing.T, what string, err error) {
	t.Helper()
	if err == nil {
		return
	}
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("%s returned %v (%T), want an *Error", what, err, err)
	}
	if _, ok := pb.ErrorCode_name[int32(e.Code)]; !ok || e.Code == pb.ErrorCode_ERROR_CODE_UNSPECIFIED {
		t.Fatalf("%s returned code %v, want a defined code", what, e.Code)
	}
}

// FuzzRoundTrip checks that any datagram that decodes encodes again to one
// that decodes to an equal header and message.
func FuzzRoundTrip(f *testing.F) {
	for _, b := range seeds(f) {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		h, msg, err := Unmarshal(b)
		checkError(t, "Unmarshal()", err)
		if err != nil {
			return
		}
		b2, err := Marshal(h, msg)
		if err != nil {
			// Dropping unknown fields only shrinks a message.
			t.Fatalf("Marshal() of a decoded %v failed: %v", h.Type, err)
		}
		h2, msg2, err := Unmarshal(b2)
		if err != nil {
			t.Fatalf("Unmarshal() of a re-encoded %v failed: %v", h.Type, err)
		}
		if h2 != h {
			t.Errorf("header changed in a round trip: got %+v, want %+v", h2, h)
		}
		if !proto.Equal(msg2, msg) {
			t.Errorf("message changed in a round trip: got %v, want %v", msg2, msg)
		}
	})
}
