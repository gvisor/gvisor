// Copyright 2020 The gVisor Authors.
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

package header_test

import (
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/prependable"
)

func TestIPv4OptionIteratorNext(t *testing.T) {
	tests := []struct {
		name             string
		options          header.IPv4Options
		wantOptions      []header.IPv4Options
		wantConcreteType any
		wantProblem      *header.IPv4OptParameterProblem
	}{
		{
			name: "Empty",
		},
		{
			name:        "NOP",
			options:     header.IPv4Options{byte(header.IPv4OptionNOPType)},
			wantOptions: []header.IPv4Options{{byte(header.IPv4OptionNOPType)}},
		},
		{
			name:        "ListEnd",
			options:     header.IPv4Options{byte(header.IPv4OptionListEndType)},
			wantOptions: []header.IPv4Options{{byte(header.IPv4OptionListEndType)}},
		},
		{
			name:        "Generic",
			options:     header.IPv4Options{2, 3, 0xff},
			wantOptions: []header.IPv4Options{{2, 3, 0xff}},
		},
		{
			name:             "RouterAlert",
			options:          header.IPv4Options{byte(header.IPv4OptionRouterAlertType), header.IPv4OptionRouterAlertLength, 0, 0},
			wantOptions:      []header.IPv4Options{{byte(header.IPv4OptionRouterAlertType), header.IPv4OptionRouterAlertLength, 0, 0}},
			wantConcreteType: (*header.IPv4OptionRouterAlert)(nil),
		},
		{
			name:        "TruncatedAfterNOP",
			options:     header.IPv4Options{byte(header.IPv4OptionNOPType), 2},
			wantOptions: []header.IPv4Options{{byte(header.IPv4OptionNOPType)}},
			wantProblem: &header.IPv4OptParameterProblem{Pointer: header.IPv4MinimumSize + 1, NeedICMP: true},
		},
		{
			name:        "LengthTooShortAfterNOP",
			options:     header.IPv4Options{byte(header.IPv4OptionNOPType), 2, 1},
			wantOptions: []header.IPv4Options{{byte(header.IPv4OptionNOPType)}},
			wantProblem: &header.IPv4OptParameterProblem{Pointer: header.IPv4MinimumSize + 1, NeedICMP: true},
		},
		{
			name:        "LengthTooLongAfterNOP",
			options:     header.IPv4Options{byte(header.IPv4OptionNOPType), 2, 3},
			wantOptions: []header.IPv4Options{{byte(header.IPv4OptionNOPType)}},
			wantProblem: &header.IPv4OptParameterProblem{Pointer: header.IPv4MinimumSize + 1, NeedICMP: true},
		},
		{
			name:    "InvalidRouterAlertLength",
			options: header.IPv4Options{byte(header.IPv4OptionRouterAlertType), 3, 0},
			wantProblem: &header.IPv4OptParameterProblem{
				Pointer:  header.IPv4MinimumSize + header.IPv4OptionLengthOffset,
				NeedICMP: true,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			iterator := test.options.MakeIterator()
			for optionIndex, wantOption := range test.wantOptions {
				option, done, problem := iterator.Next()
				if problem != nil {
					t.Fatalf("iterator.Next() option %d returned unexpected problem: %+v", optionIndex, problem)
				}
				if done {
					t.Fatalf("iterator.Next() option %d unexpectedly indicated completion", optionIndex)
				}
				if diff := cmp.Diff([]byte(wantOption), option.Contents()); diff != "" {
					t.Errorf("iterator.Next() option %d contents mismatch (-want +got):\n%s", optionIndex, diff)
				}
				if got, want := option.Type(), header.IPv4OptionType(wantOption[0]); got != want {
					t.Errorf("iterator.Next() option %d type = %d, want %d", optionIndex, got, want)
				}
				if got, want := option.Size(), uint8(len(wantOption)); got != want {
					t.Errorf("iterator.Next() option %d size = %d, want %d", optionIndex, got, want)
				}
				if test.wantConcreteType != nil && reflect.TypeOf(option) != reflect.TypeOf(test.wantConcreteType) {
					t.Errorf("iterator.Next() option %d concrete type = %T, want %T", optionIndex, option, test.wantConcreteType)
				}
			}

			option, done, problem := iterator.Next()
			if option != nil {
				t.Errorf("iterator.Next() final option = %v, want nil", option)
			}
			if diff := cmp.Diff(test.wantProblem, problem); diff != "" {
				t.Errorf("iterator.Next() final problem mismatch (-want +got):\n%s", diff)
			}
			if problem == nil && !done {
				t.Errorf("iterator.Next() final done = false, want true")
			}
		})
	}
}

func TestIPv4OptionIteratorReplacement(t *testing.T) {
	original := header.IPv4Options{byte(header.IPv4OptionNOPType), 2, 3, 0xaa}
	iterator := original.MakeIterator()

	nop, done, problem := iterator.Next()
	if problem != nil || done {
		t.Fatalf("iterator.Next() for NOP = (_, %t, %+v), want (_, false, nil)", done, problem)
	}
	iterator.PushNOPOrEnd(nop.Type())

	option, done, problem := iterator.Next()
	if problem != nil || done {
		t.Fatalf("iterator.Next() for generic option = (_, %t, %+v), want (_, false, nil)", done, problem)
	}
	replacement := iterator.InitReplacement(option)
	replacement[2] = 0xbb
	iterator.ConsumeBuffer(len(replacement))
	iterator.PushNOPOrEnd(header.IPv4OptionListEndType)

	if diff := cmp.Diff([]byte{byte(header.IPv4OptionNOPType), 2, 3, 0xbb, 0, 0, 0, 0}, []byte(iterator.Finalize())); diff != "" {
		t.Errorf("iterator.Finalize() mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]byte{byte(header.IPv4OptionNOPType), 2, 3, 0xaa}, []byte(original)); diff != "" {
		t.Errorf("original options changed (-want +got):\n%s", diff)
	}
}

func TestIPv4OptionsSerializer(t *testing.T) {
	optCases := []struct {
		name   string
		option []header.IPv4SerializableOption
		expect []byte
	}{
		{
			name: "NOP",
			option: []header.IPv4SerializableOption{
				&header.IPv4SerializableNOPOption{},
			},
			expect: []byte{1, 0, 0, 0},
		},
		{
			name: "ListEnd",
			option: []header.IPv4SerializableOption{
				&header.IPv4SerializableListEndOption{},
			},
			expect: []byte{0, 0, 0, 0},
		},
		{
			name: "RouterAlert",
			option: []header.IPv4SerializableOption{
				&header.IPv4SerializableRouterAlertOption{},
			},
			expect: []byte{148, 4, 0, 0},
		}, {
			name: "NOP and RouterAlert",
			option: []header.IPv4SerializableOption{
				&header.IPv4SerializableNOPOption{},
				&header.IPv4SerializableRouterAlertOption{},
			},
			expect: []byte{1, 148, 4, 0, 0, 0, 0, 0},
		},
	}

	for _, opt := range optCases {
		t.Run(opt.name, func(t *testing.T) {
			s := header.IPv4OptionsSerializer(opt.option)
			l := s.Length()
			if got := len(opt.expect); got != int(l) {
				t.Fatalf("s.Length() = %d, want = %d", got, l)
			}
			b := make([]byte, l)
			for i := range b {
				// Fill the buffer with full bytes to ensure padding is being set
				// correctly.
				b[i] = 0xFF
			}
			if serializedLength := s.Serialize(b); serializedLength != l {
				t.Fatalf("s.Serialize(_) = %d, want %d", serializedLength, l)
			}
			if diff := cmp.Diff(opt.expect, b); diff != "" {
				t.Errorf("mismatched serialized option (-want +got):\n%s", diff)
			}
		})
	}
}

// TestIPv4Encode checks that ipv4.Encode correctly fills out the requested
// fields when options are supplied.
func TestIPv4EncodeOptions(t *testing.T) {
	tests := []struct {
		name           string
		numberOfNops   int
		encodedOptions header.IPv4Options // reply should look like this
		wantIHL        int
	}{
		{
			name:    "valid no options",
			wantIHL: header.IPv4MinimumSize,
		},
		{
			name:           "one byte options",
			numberOfNops:   1,
			encodedOptions: header.IPv4Options{1, 0, 0, 0},
			wantIHL:        header.IPv4MinimumSize + 4,
		},
		{
			name:           "two byte options",
			numberOfNops:   2,
			encodedOptions: header.IPv4Options{1, 1, 0, 0},
			wantIHL:        header.IPv4MinimumSize + 4,
		},
		{
			name:           "three byte options",
			numberOfNops:   3,
			encodedOptions: header.IPv4Options{1, 1, 1, 0},
			wantIHL:        header.IPv4MinimumSize + 4,
		},
		{
			name:           "four byte options",
			numberOfNops:   4,
			encodedOptions: header.IPv4Options{1, 1, 1, 1},
			wantIHL:        header.IPv4MinimumSize + 4,
		},
		{
			name:           "five byte options",
			numberOfNops:   5,
			encodedOptions: header.IPv4Options{1, 1, 1, 1, 1, 0, 0, 0},
			wantIHL:        header.IPv4MinimumSize + 8,
		},
		{
			name:         "thirty nine byte options",
			numberOfNops: 39,
			encodedOptions: header.IPv4Options{
				1, 1, 1, 1, 1, 1, 1, 1,
				1, 1, 1, 1, 1, 1, 1, 1,
				1, 1, 1, 1, 1, 1, 1, 1,
				1, 1, 1, 1, 1, 1, 1, 1,
				1, 1, 1, 1, 1, 1, 1, 0,
			},
			wantIHL: header.IPv4MinimumSize + 40,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			serializeOpts := header.IPv4OptionsSerializer(make([]header.IPv4SerializableOption, test.numberOfNops))
			for i := range serializeOpts {
				serializeOpts[i] = &header.IPv4SerializableNOPOption{}
			}
			paddedOptionLength := serializeOpts.Length()
			ipHeaderLength := int(header.IPv4MinimumSize + paddedOptionLength)
			if ipHeaderLength > header.IPv4MaximumHeaderSize {
				t.Fatalf("IP header length too large: got = %d, want <= %d ", ipHeaderLength, header.IPv4MaximumHeaderSize)
			}
			totalLen := uint16(ipHeaderLength)
			hdr := prependable.New(int(totalLen))
			ip := header.IPv4(hdr.Prepend(ipHeaderLength))
			// To check the padding works, poison the last byte of the options space.
			if paddedOptionLength != serializeOpts.Length() {
				ip.SetHeaderLength(uint8(ipHeaderLength))
				ip.Options()[paddedOptionLength-1] = 0xff
				ip.SetHeaderLength(0)
			}
			ip.Encode(&header.IPv4Fields{
				Options: serializeOpts,
			})
			options := ip.Options()
			wantOptions := test.encodedOptions
			if got, want := int(ip.HeaderLength()), test.wantIHL; got != want {
				t.Errorf("got IHL of %d, want %d", got, want)
			}

			// cmp.Diff does not consider nil slices equal to empty slices, but we do.
			if len(wantOptions) == 0 && len(options) == 0 {
				return
			}

			if diff := cmp.Diff(wantOptions, options); diff != "" {
				t.Errorf("options mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestIsV4LinkLocalUnicastAddress(t *testing.T) {
	tests := []struct {
		name     string
		addr     string
		expected bool
	}{
		{
			name:     "Valid (lowest)",
			addr:     "\xa9\xfe\x00\x00",
			expected: true,
		},
		{
			name:     "Valid (highest)",
			addr:     "\xa9\xfe\xff\xff",
			expected: true,
		},
		{
			name:     "Invalid (before subnet)",
			addr:     "\xa9\xfd\xff\xff",
			expected: false,
		},
		{
			name:     "Invalid (after subnet)",
			addr:     "\xa9\xff\x00\x00",
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := header.IsV4LinkLocalUnicastAddress(tcpip.AddrFromSlice([]byte(test.addr))); got != test.expected {
				t.Errorf("got header.IsV4LinkLocalUnicastAddress(%s) = %t, want = %t", test.addr, got, test.expected)
			}
		})
	}
}

func TestIsV4LinkLocalMulticastAddress(t *testing.T) {
	tests := []struct {
		name     string
		addr     string
		expected bool
	}{
		{
			name:     "Valid (lowest)",
			addr:     "\xe0\x00\x00\x00",
			expected: true,
		},
		{
			name:     "Valid (highest)",
			addr:     "\xe0\x00\x00\xff",
			expected: true,
		},
		{
			name:     "Invalid (before subnet)",
			addr:     "\xdf\xff\xff\xff",
			expected: false,
		},
		{
			name:     "Invalid (after subnet)",
			addr:     "\xe0\x00\x01\x00",
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := header.IsV4LinkLocalMulticastAddress(tcpip.AddrFrom4Slice([]byte(test.addr))); got != test.expected {
				t.Errorf("got header.IsV4LinkLocalMulticastAddress(%s) = %t, want = %t", test.addr, got, test.expected)
			}
		})
	}
}
