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
	"errors"
	"net/netip"
	"strings"
	"testing"
	"unicode/utf8"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	pb "gvisor.dev/gvisor/pkg/netproxy/hello/hello_go_proto"
)

func ip(s string) []byte {
	return netip.MustParseAddr(s).AsSlice()
}

func addr(s string) *pb.Address {
	p := netip.MustParsePrefix(s)
	return &pb.Address{Ip: p.Addr().AsSlice(), PrefixLen: uint32(p.Bits())}
}

func route(dst, gw string) *pb.Route {
	p := netip.MustParsePrefix(dst)
	r := &pb.Route{Dst: p.Addr().AsSlice(), DstPrefixLen: uint32(p.Bits())}
	if gw != "" {
		r.Gateway = ip(gw)
	}
	return r
}

// validConfig returns a valid dual-stack Config.
func validConfig() *pb.Config {
	return &pb.Config{
		Mtu: 1500,
		Addresses: []*pb.Address{
			addr("10.0.0.2/24"),
			addr("2001:db8::2/64"),
		},
		Routes: []*pb.Route{
			route("10.0.0.0/24", ""),
			route("0.0.0.0/0", "10.0.0.1"),
			route("2001:db8::/64", ""),
			route("::/0", "2001:db8::1"),
		},
	}
}

func singleLinkOffer() *pb.Offer {
	return &pb.Offer{SupportedMajors: []uint32{Major}, LinkIndex: 0, LinkCount: 1}
}

func mustMarshal(t testing.TB, h Header, msg proto.Message) []byte {
	t.Helper()
	b, err := Marshal(h, msg)
	if err != nil {
		t.Fatalf("Marshal(%+v, %v) failed: %v", h, msg, err)
	}
	return b
}

// wantCode fails t unless err is an *Error with code.
func wantCode(t *testing.T, err error, code pb.ErrorCode) *Error {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("got error %v (%T), want an *Error with code %v", err, err, CodeName(code))
	}
	if e.Code != code {
		t.Fatalf("got code %v (%v), want %v", CodeName(e.Code), e, CodeName(code))
	}
	return e
}

func TestRoundTrip(t *testing.T) {
	linkIndex := uint32(0)
	for _, tc := range []struct {
		typ Type
		msg proto.Message
	}{
		{TypeOffer, &pb.Offer{SupportedMajors: []uint32{1}, SandboxId: "sandbox", LinkIndex: 0, LinkCount: 1, Restore: true}},
		{TypeConfig, validConfig()},
		{TypeConfig, &pb.Config{Mtu: 1500, LinkIndex: &linkIndex, Offloads: &pb.Offloads{TxCsum: true}}},
		{TypeAck, &pb.Ack{}},
		{TypeError, &pb.Error{Code: pb.ErrorCode_ERROR_CODE_UNSUPPORTED_VERSION, Field: "major", Message: "no common major", SupportedMajors: []uint32{2, 3}}},
	} {
		t.Run(tc.typ.String(), func(t *testing.T) {
			h := Header{Type: tc.typ, Major: Major, XID: 0xdeadbeef}
			b := mustMarshal(t, h, tc.msg)
			if want := []byte{0xF0, 'G', 'V', 'H', byte(tc.typ), Major, 0, 0}; !bytes.Equal(b[:8], want) {
				t.Errorf("header bytes 0-7 = % x, want % x", b[:8], want)
			}
			if got, want := int(b[8])<<8|int(b[9]), len(b); got != want {
				t.Errorf("header length = %d, want datagram size %d", got, want)
			}
			if want := []byte{0, 0, 0xde, 0xad, 0xbe, 0xef}; !bytes.Equal(b[10:16], want) {
				t.Errorf("header bytes 10-15 = % x, want % x", b[10:16], want)
			}
			gotH, got, err := Unmarshal(b)
			if err != nil {
				t.Fatalf("Unmarshal() failed: %v", err)
			}
			if gotH != h {
				t.Errorf("Unmarshal() header = %+v, want %+v", gotH, h)
			}
			if !proto.Equal(got, tc.msg) {
				t.Errorf("Unmarshal() message = %v, want %v", got, tc.msg)
			}
		})
	}
}

func TestMarshalRejectsWrongMessage(t *testing.T) {
	if _, err := Marshal(Header{Type: TypeOffer}, &pb.Config{}); err == nil {
		t.Errorf("Marshal(Offer, Config) succeeded, want error")
	}
	if _, err := Marshal(Header{Type: 5}, &pb.Ack{}); err == nil {
		t.Errorf("Marshal(type 5) succeeded, want error")
	}
}

func TestMarshalTooLarge(t *testing.T) {
	c := &pb.Config{Ifname: strings.Repeat("x", MaxMessageSize)}
	_, err := Marshal(Header{Type: TypeConfig}, c)
	wantCode(t, err, pb.ErrorCode_ERROR_CODE_LIMIT_EXCEEDED)
}

func TestUnmarshalHeader(t *testing.T) {
	valid := mustMarshal(t, Header{Type: TypeAck, Major: Major, XID: 1}, &pb.Ack{})
	with := func(i int, v byte) []byte {
		b := bytes.Clone(valid)
		b[i] = v
		return b
	}
	for _, tc := range []struct {
		name string
		b    []byte
		code pb.ErrorCode
	}{
		{"empty", nil, pb.ErrorCode_ERROR_CODE_MALFORMED},
		{"truncated header", valid[:HeaderSize-1], pb.ErrorCode_ERROR_CODE_MALFORMED},
		{"bad magic", with(0, 0x45), pb.ErrorCode_ERROR_CODE_MALFORMED},
		{"bad magic last byte", with(3, 'X'), pb.ErrorCode_ERROR_CODE_MALFORMED},
		{"rsvd byte", with(7, 1), pb.ErrorCode_ERROR_CODE_MALFORMED},
		{"reserved high byte", with(10, 1), pb.ErrorCode_ERROR_CODE_MALFORMED},
		{"reserved low byte", with(11, 1), pb.ErrorCode_ERROR_CODE_MALFORMED},
		{"length short", with(9, HeaderSize-1), pb.ErrorCode_ERROR_CODE_MALFORMED},
		{"length long", with(9, HeaderSize+1), pb.ErrorCode_ERROR_CODE_MALFORMED},
		{"length too high", with(8, 1), pb.ErrorCode_ERROR_CODE_MALFORMED},
		{"type 0", with(4, 0), pb.ErrorCode_ERROR_CODE_MALFORMED},
		{"type 5", with(4, 5), pb.ErrorCode_ERROR_CODE_MALFORMED},
		{"oversized", append(bytes.Clone(valid), make([]byte, MaxMessageSize+1-HeaderSize)...), pb.ErrorCode_ERROR_CODE_LIMIT_EXCEEDED},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := Unmarshal(tc.b)
			wantCode(t, err, tc.code)
		})
	}

	t.Run("flags ignored", func(t *testing.T) {
		h, _, err := Unmarshal(with(6, 0xff))
		if err != nil {
			t.Fatalf("Unmarshal() with flags 0xff failed: %v", err)
		}
		if h.Type != TypeAck {
			t.Errorf("Unmarshal() type = %v, want Ack", h.Type)
		}
	})
}

func TestUnmarshalMaxSize(t *testing.T) {
	// A datagram of exactly MaxMessageSize bytes is accepted.
	c := &pb.Config{Ifname: "x"}
	b := mustMarshal(t, Header{Type: TypeConfig}, c)
	pad := MaxMessageSize - len(b) - protowire.SizeTag(99) - 2 // 2-byte length.
	body := protowire.AppendBytes(protowire.AppendTag(b[HeaderSize:], 99, protowire.BytesType), make([]byte, pad))
	b = append(b[:HeaderSize], body...)
	b[8], b[9] = byte(len(b)>>8), byte(len(b))
	if len(b) != MaxMessageSize {
		t.Fatalf("test datagram is %d bytes, want %d", len(b), MaxMessageSize)
	}
	if _, _, err := Unmarshal(b); err != nil {
		t.Errorf("Unmarshal() of %d bytes failed: %v", len(b), err)
	}
}

func TestUnmarshalBody(t *testing.T) {
	header := func(typ Type, body []byte) []byte {
		b := mustMarshal(t, Header{Type: typ, Major: Major}, newMessage(typ))
		b = append(b[:HeaderSize], body...)
		b[8], b[9] = byte(len(b)>>8), byte(len(b))
		return b
	}

	t.Run("empty body", func(t *testing.T) {
		_, msg, err := Unmarshal(header(TypeConfig, nil))
		if err != nil {
			t.Fatalf("Unmarshal() failed: %v", err)
		}
		if !proto.Equal(msg, &pb.Config{}) {
			t.Errorf("Unmarshal() = %v, want an empty Config", msg)
		}
	})

	t.Run("truncated body", func(t *testing.T) {
		body, err := proto.Marshal(validConfig())
		if err != nil {
			t.Fatalf("proto.Marshal() failed: %v", err)
		}
		_, _, err = Unmarshal(header(TypeConfig, body[:len(body)-1]))
		e := wantCode(t, err, pb.ErrorCode_ERROR_CODE_MALFORMED)
		if !strings.HasPrefix(e.Message, "Config: ") {
			t.Errorf("error %q does not name the message", e.Message)
		}
	})

	t.Run("invalid wire format", func(t *testing.T) {
		_, _, err := Unmarshal(header(TypeConfig, []byte{0xff, 0xff, 0xff}))
		wantCode(t, err, pb.ErrorCode_ERROR_CODE_MALFORMED)
	})

	t.Run("invalid UTF-8", func(t *testing.T) {
		body := protowire.AppendString(protowire.AppendTag(nil, 5, protowire.BytesType), "\xff")
		_, _, err := Unmarshal(header(TypeConfig, body))
		wantCode(t, err, pb.ErrorCode_ERROR_CODE_MALFORMED)
	})

	t.Run("unknown field ignored", func(t *testing.T) {
		want := validConfig()
		body, err := proto.Marshal(want)
		if err != nil {
			t.Fatalf("proto.Marshal() failed: %v", err)
		}
		body = protowire.AppendVarint(protowire.AppendTag(body, 99, protowire.VarintType), 7)
		body = protowire.AppendBytes(protowire.AppendTag(body, 100, protowire.BytesType), []byte("future"))
		_, msg, err := Unmarshal(header(TypeConfig, body))
		if err != nil {
			t.Fatalf("Unmarshal() with unknown fields failed: %v", err)
		}
		if !proto.Equal(msg, want) {
			t.Errorf("Unmarshal() = %v, want %v", msg, want)
		}
		if u := msg.ProtoReflect().GetUnknown(); len(u) != 0 {
			t.Errorf("Unmarshal() kept %d bytes of unknown fields, want 0", len(u))
		}
	})

	t.Run("nested unknown groups", func(t *testing.T) {
		// Nesting deeper than RecursionLimit in unknown groups is skipped
		// rather than rejected: the limit applies to known messages.
		var body []byte
		for range 20 {
			body = protowire.AppendTag(body, 99, protowire.StartGroupType)
		}
		for range 20 {
			body = protowire.AppendTag(body, 99, protowire.EndGroupType)
		}
		if _, _, err := Unmarshal(header(TypeConfig, body)); err != nil {
			t.Errorf("Unmarshal() with nested unknown groups failed: %v", err)
		}
	})
}

func TestErrorProto(t *testing.T) {
	e := &Error{
		Code:            pb.ErrorCode_ERROR_CODE_INVALID_VALUE,
		Field:           strings.Repeat("f", 200),
		Message:         "a" + strings.Repeat("é", 200), // Byte 256 is mid-rune.
		SupportedMajors: []uint32{1},
	}
	m := e.Proto()
	if len(m.GetField()) != maxErrorFieldLen {
		t.Errorf("Proto().Field is %d bytes, want %d", len(m.GetField()), maxErrorFieldLen)
	}
	if n := len(m.GetMessage()); n != maxErrorMessageLen-1 || !utf8.ValidString(m.GetMessage()) {
		t.Errorf("Proto().Message is %d bytes (valid UTF-8 %v), want %d bytes of valid UTF-8", n, utf8.ValidString(m.GetMessage()), maxErrorMessageLen-1)
	}
	b := mustMarshal(t, Header{Type: TypeError, Major: Major}, m)
	if _, _, err := Unmarshal(b); err != nil {
		t.Errorf("Unmarshal() of a truncated Error failed: %v", err)
	}

	got := ErrorFromProto(&pb.Error{Code: 99, Message: "bad\xffbyte"})
	if got.Code != 99 || !utf8.ValidString(got.Message) {
		t.Errorf("ErrorFromProto() = %+v, want code 99 and a valid UTF-8 message", got)
	}
}

func TestErrorFromProtoLimitsMajors(t *testing.T) {
	majors := make([]uint32, 100)
	for i := range majors {
		majors[i] = uint32(i + 1)
	}
	got := ErrorFromProto(&pb.Error{Code: pb.ErrorCode_ERROR_CODE_UNSUPPORTED_VERSION, SupportedMajors: majors})
	if len(got.SupportedMajors) != maxSupportedMajors || got.SupportedMajors[0] != 1 {
		t.Errorf("ErrorFromProto() SupportedMajors = %v, want the first %d", got.SupportedMajors, maxSupportedMajors)
	}
}

func TestCodeName(t *testing.T) {
	for code, want := range map[pb.ErrorCode]string{
		pb.ErrorCode_ERROR_CODE_NOT_READY: "NOT_READY",
		pb.ErrorCode_ERROR_CODE_MALFORMED: "MALFORMED",
		99:                                "99",
	} {
		if got := CodeName(code); got != want {
			t.Errorf("CodeName(%d) = %q, want %q", code, got, want)
		}
	}
}
