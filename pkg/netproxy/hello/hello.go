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

// Package hello implements the hello that runsc and an external network proxy
// exchange on a --network-proxy-path socket before it carries IP packets.
//
// runsc sends an Offer right after connect(). The peer replies with a Config
// describing the link, or with an Error. runsc then sends an Ack or an Error,
// and only after an Ack donates the socket to the sentry. Each message is one
// SOCK_SEQPACKET datagram: a 16-byte header followed by one serialized
// protobuf message from hello.proto, chosen by the header's type.
package hello

import (
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"
	pb "gvisor.dev/gvisor/pkg/netproxy/hello/hello_go_proto"
)

const (
	// HeaderSize is the size of the fixed header that starts every datagram.
	HeaderSize = 16

	// MaxMessageSize is the largest datagram, header included. A receiver
	// reads into a buffer of at least MaxMessageSize+1 bytes so that it can
	// tell a larger datagram apart.
	MaxMessageSize = 16384

	// Major is the major version that this package implements.
	Major = 1

	// MaxLinks is the largest Offer.link_count.
	MaxLinks = 16

	// MaxSandboxIDLen is the largest Offer.sandbox_id, in bytes.
	MaxSandboxIDLen = 128

	// DefaultInterfaceName is the interface name of a link whose Config has
	// an empty ifname.
	DefaultInterfaceName = "eth0"
)

// magic starts every datagram. Its first nibble, F, is never an IP version.
var magic = [4]byte{0xF0, 0x47, 0x56, 0x48}

// Type is the header field that selects the message in the body.
type Type uint8

// Message types.
const (
	TypeOffer  Type = 1
	TypeConfig Type = 2
	TypeAck    Type = 3
	TypeError  Type = 4
)

// String implements fmt.Stringer.
func (t Type) String() string {
	switch t {
	case TypeOffer:
		return "Offer"
	case TypeConfig:
		return "Config"
	case TypeAck:
		return "Ack"
	case TypeError:
		return "Error"
	default:
		return fmt.Sprintf("Type(%d)", uint8(t))
	}
}

// newMessage returns an empty message of type t, or nil if t is unknown.
func newMessage(t Type) proto.Message {
	switch t {
	case TypeOffer:
		return &pb.Offer{}
	case TypeConfig:
		return &pb.Config{}
	case TypeAck:
		return &pb.Ack{}
	case TypeError:
		return &pb.Error{}
	default:
		return nil
	}
}

// Header is the fixed part of a datagram. The length is that of the datagram,
// and the flags, which define no bits in this major, are sent as 0 and
// ignored on receipt.
type Header struct {
	Type  Type
	Major uint8
	XID   uint32
}

// unmarshalOptions decode every body. Unknown fields are dropped, since a
// received message is never re-encoded with them. The schema nests two
// messages deep.
var unmarshalOptions = proto.UnmarshalOptions{
	DiscardUnknown: true,
	RecursionLimit: 8,
}

// Marshal returns the datagram that carries msg with header h. msg must be
// the message type that h.Type selects.
func Marshal(h Header, msg proto.Message) ([]byte, error) {
	want := newMessage(h.Type)
	if want == nil {
		return nil, fmt.Errorf("unknown hello message type %d", uint8(h.Type))
	}
	if got := msg.ProtoReflect().Descriptor().FullName(); got != want.ProtoReflect().Descriptor().FullName() {
		return nil, fmt.Errorf("hello message type %v cannot carry %s", h.Type, got)
	}
	b := make([]byte, HeaderSize, HeaderSize+proto.Size(msg))
	b, err := proto.MarshalOptions{}.MarshalAppend(b, msg)
	if err != nil {
		return nil, fmt.Errorf("marshaling %v: %w", h.Type, err)
	}
	if len(b) > MaxMessageSize {
		return nil, &Error{
			Code:    pb.ErrorCode_ERROR_CODE_LIMIT_EXCEEDED,
			Message: fmt.Sprintf("%v of %d bytes exceeds %d bytes", h.Type, len(b), MaxMessageSize),
		}
	}
	copy(b[0:4], magic[:])
	b[4] = byte(h.Type)
	b[5] = h.Major
	// b[6] (flags), b[7] and b[10:12] (reserved) stay 0.
	binary.BigEndian.PutUint16(b[8:10], uint16(len(b)))
	binary.BigEndian.PutUint32(b[12:16], h.XID)
	return b, nil
}

// Unmarshal decodes datagram b. The message it returns is the type that the
// header selects: *pb.Offer, *pb.Config, *pb.Ack or *pb.Error. On failure the
// error is an *Error whose code is LIMIT_EXCEEDED or MALFORMED.
func Unmarshal(b []byte) (Header, proto.Message, error) {
	if len(b) > MaxMessageSize {
		return Header{}, nil, &Error{
			Code:    pb.ErrorCode_ERROR_CODE_LIMIT_EXCEEDED,
			Message: fmt.Sprintf("hello exceeds %d bytes", MaxMessageSize),
		}
	}
	malformed := func(format string, args ...any) (Header, proto.Message, error) {
		return Header{}, nil, &Error{
			Code:    pb.ErrorCode_ERROR_CODE_MALFORMED,
			Message: fmt.Sprintf(format, args...),
		}
	}
	if len(b) < HeaderSize {
		return malformed("hello of %d bytes is shorter than its %d-byte header", len(b), HeaderSize)
	}
	if [4]byte(b[0:4]) != magic {
		return malformed("hello has bad magic % x", b[0:4])
	}
	if b[7] != 0 || b[10] != 0 || b[11] != 0 {
		return malformed("hello header has nonzero reserved bytes")
	}
	if length := binary.BigEndian.Uint16(b[8:10]); int(length) != len(b) {
		return malformed("hello header length %d does not match datagram size %d", length, len(b))
	}
	h := Header{
		Type:  Type(b[4]),
		Major: b[5],
		XID:   binary.BigEndian.Uint32(b[12:16]),
	}
	msg := newMessage(h.Type)
	if msg == nil {
		return malformed("unknown hello message type %d", uint8(h.Type))
	}
	if err := unmarshalOptions.Unmarshal(b[HeaderSize:], msg); err != nil {
		return malformed("%v: %v", h.Type, err)
	}
	return h, msg, nil
}

// Limits on the strings of an Error message.
const (
	maxErrorFieldLen   = 128
	maxErrorMessageLen = 256
)

// maxSupportedMajors is the largest number of supported_majors in an Offer or
// an Error.
const maxSupportedMajors = 16

// Error is a refusal: one that a receiver sends as an Error message, or one
// that it received.
type Error struct {
	Code pb.ErrorCode
	// Field is the path of the offending field, for example
	// "routes[3].gateway", or empty.
	Field string
	// Message is human-readable and names the field.
	Message string
	// SupportedMajors are the sender's majors, with UNSUPPORTED_VERSION.
	SupportedMajors []uint32
}

// Error implements error.
func (e *Error) Error() string {
	if e.Message == "" {
		return CodeName(e.Code)
	}
	return e.Message
}

// Proto returns e as an Error message, with Field and Message cut to their
// limits.
func (e *Error) Proto() *pb.Error {
	return &pb.Error{
		Code:            e.Code,
		Field:           truncate(e.Field, maxErrorFieldLen),
		Message:         truncate(e.Message, maxErrorMessageLen),
		SupportedMajors: e.SupportedMajors,
	}
}

// ErrorFromProto returns the Error carried by m. Field and Message are cut to
// their limits and made valid UTF-8, and SupportedMajors to its Offer limit.
func ErrorFromProto(m *pb.Error) *Error {
	return &Error{
		Code:            m.GetCode(),
		Field:           truncate(m.GetField(), maxErrorFieldLen),
		Message:         truncate(m.GetMessage(), maxErrorMessageLen),
		SupportedMajors: m.GetSupportedMajors()[:min(len(m.GetSupportedMajors()), maxSupportedMajors)],
	}
}

// CodeName returns c without its ERROR_CODE_ prefix, for example "MALFORMED".
// An unknown code is returned as its number.
func CodeName(c pb.ErrorCode) string {
	return strings.TrimPrefix(c.String(), "ERROR_CODE_")
}

// truncate returns s as valid UTF-8 of at most n bytes, cut at a rune
// boundary. proto3 strings must be valid UTF-8.
func truncate(s string, n int) string {
	s = strings.ToValidUTF8(s, "\uFFFD")
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
