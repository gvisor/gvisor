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

package sandbox

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/netproxy/hello"
	pb "gvisor.dev/gvisor/pkg/netproxy/hello/hello_go_proto"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/urpc"
	"gvisor.dev/gvisor/runsc/boot/sentryapi"
	"gvisor.dev/gvisor/runsc/config"
)

// peerHelloTimeout bounds the wait for the peer's reply, from the Offer.
const peerHelloTimeout = 5 * time.Second

// errHelloTimeout is returned when the hello deadline passes.
var errHelloTimeout = errors.New("hello timed out")

// createInterfacesAndRoutesFromPeer dials the peer at --network-proxy-path,
// takes the configuration of its link from the peer's hello, and creates the
// links and routes in the sandbox. It neither joins nor reads the sandbox's
// network namespace, and touches no host interface, so it works the same
// whichever namespace that is, including the host's.
func createInterfacesAndRoutesFromPeer(conn *urpc.Client, conf *config.Config, sandboxID string, disableIPv6, isRestore bool) error {
	path := conf.NetworkProxyPath
	udsFile, err := dialExternalUDS(path)
	if err != nil {
		return fmt.Errorf("dialing external UDS: %w", err)
	}
	defer udsFile.Close()

	var args sentryapi.CreateLinksAndRoutesArgs
	defer func() {
		// The sentry receives its own copies of the files.
		for _, f := range args.FilePayload.Files {
			if f != udsFile {
				f.Close()
			}
		}
	}()
	if err := peerHello(udsFile, path, peerOffer(sandboxID, isRestore), peerHelloTimeout, func(cfg *pb.Config) error {
		var err error
		if args, err = peerLinksAndRoutes(conf, []*pb.Config{cfg}, disableIPv6); err != nil {
			return err
		}
		if err := pcapAndNAT(&args, conf); err != nil {
			return &hello.Error{Code: pb.ErrorCode_ERROR_CODE_INTERNAL, Message: err.Error()}
		}
		return nil
	}); err != nil {
		return err
	}
	// The sentry takes the link FDs before the PCAP and NAT files.
	args.FilePayload.Files = append([]*os.File{udsFile}, args.FilePayload.Files...)
	args.IsRestore = isRestore
	log.Debugf("Setting up network from network proxy peer, config: %+v", args)
	if err := conn.Call(sentryapi.ContMgrSetNetworkArgs, &args, nil); err != nil {
		return fmt.Errorf("creating links and routes: %w", err)
	}
	return nil
}

// peerOffer returns the Offer for the single --network-proxy-path link.
func peerOffer(sandboxID string, isRestore bool) *pb.Offer {
	if len(sandboxID) > hello.MaxSandboxIDLen {
		sandboxID = sandboxID[:hello.MaxSandboxIDLen]
	}
	return &pb.Offer{
		SupportedMajors: []uint32{hello.Major},
		SandboxId:       strings.ToValidUTF8(sandboxID, ""),
		LinkIndex:       0,
		LinkCount:       1,
		Restore:         isRestore,
	}
}

// peerHello runs the hello on f, connected to the peer at path. It sends
// offer, waits up to timeout for the peer's Config and validates it, then
// passes it to accept. It replies Ack if accept succeeds. On any failure that
// the peer didn't report itself, it replies Error, except when the peer is
// gone or silent. Either way the error describes the failure. IP packets that
// the peer sends before its Config are discarded.
func peerHello(f *os.File, path string, offer *pb.Offer, timeout time.Duration, accept func(*pb.Config) error) error {
	fd := int(f.Fd())
	if cred, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED); err == nil {
		log.Infof("Network proxy peer at %q has PID %d, UID %d", path, cred.Pid, cred.Uid)
	} else {
		log.Warningf("Failed to get the credentials of network proxy peer at %q: %v", path, err)
	}
	defer func() {
		for _, opt := range []int{unix.SO_RCVTIMEO, unix.SO_SNDTIMEO} {
			if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, opt, &unix.Timeval{}); err != nil {
				log.Warningf("Failed to clear socket timeout %d on UDS socket: %v", opt, err)
			}
		}
	}()

	deadline := time.Now().Add(timeout)
	xid := rand.Uint32()
	if err := sendHello(fd, deadline, hello.Header{Type: hello.TypeOffer, Major: hello.Major, XID: xid}, offer); err != nil {
		return fmt.Errorf("sending hello to network proxy peer at %q: %w", path, err)
	}

	// Replies get their own bound, so that a Config that arrives just
	// before the deadline is still answered.
	reply := func(typ hello.Type, msg proto.Message) error {
		return sendHello(fd, time.Now().Add(timeout), hello.Header{Type: typ, Major: hello.Major, XID: xid}, msg)
	}
	refuse := func(err error, code pb.ErrorCode) {
		if err := reply(hello.TypeError, asHelloError(err, code).Proto()); err != nil {
			log.Warningf("Failed to send hello Error to network proxy peer at %q: %v", path, err)
		}
	}
	invalid := func(err error) error {
		refuse(err, pb.ErrorCode_ERROR_CODE_MALFORMED)
		return fmt.Errorf("invalid hello from network proxy peer at %q: %w", path, err)
	}

	// One byte more than the limit, so a datagram over the limit reads as
	// longer than it.
	buf := make([]byte, hello.MaxMessageSize+1)
	discarded := 0
	discardedNote := func() string {
		if discarded == 0 {
			return ""
		}
		return fmt.Sprintf(" (%d IP packets discarded)", discarded)
	}
	for {
		n, eof, err := recvHello(fd, buf, deadline)
		switch {
		case errors.Is(err, errHelloTimeout):
			return fmt.Errorf("network proxy peer at %q sent no hello reply within %v%s (--network-proxy-config=peer requires a peer that speaks hello v%d)", path, timeout, discardedNote(), hello.Major)
		case err != nil:
			return fmt.Errorf("receiving hello from network proxy peer at %q: %w", path, err)
		case eof:
			return fmt.Errorf("network proxy peer at %q closed the connection during hello%s", path, discardedNote())
		}
		// IP packets that the peer sends before its Config are discarded.
		if n > 0 {
			if v := buf[0] >> 4; v == 4 || v == 6 {
				discarded++
				continue
			}
		}
		if n > hello.MaxMessageSize {
			return invalid(&hello.Error{
				Code:    pb.ErrorCode_ERROR_CODE_LIMIT_EXCEEDED,
				Message: fmt.Sprintf("hello exceeds %d bytes", hello.MaxMessageSize),
			})
		}
		h, msg, err := hello.Unmarshal(buf[:n])
		if err != nil {
			return invalid(err)
		}
		if h.XID != xid {
			return invalid(&hello.Error{
				Code:    pb.ErrorCode_ERROR_CODE_MALFORMED,
				Message: fmt.Sprintf("hello reply xid %#x does not match offer xid %#x", h.XID, xid),
			})
		}
		switch m := msg.(type) {
		case *pb.Error:
			e := hello.ErrorFromProto(m)
			if e.Code == pb.ErrorCode_ERROR_CODE_UNSUPPORTED_VERSION {
				return fmt.Errorf("network proxy peer at %q supports hello majors %v; runsc supports %v", path, e.SupportedMajors, offer.GetSupportedMajors())
			}
			if e.Field != "" {
				return fmt.Errorf("network proxy peer at %q refused (%s, field %q): %q", path, hello.CodeName(e.Code), e.Field, e.Message)
			}
			return fmt.Errorf("network proxy peer at %q refused (%s): %q", path, hello.CodeName(e.Code), e.Message)
		case *pb.Config:
			if discarded > 0 {
				log.Debugf("Discarded %d IP packets from network proxy peer at %q before its hello reply", discarded, path)
			}
			if h.Major != hello.Major {
				return invalid(&hello.Error{
					Code:            pb.ErrorCode_ERROR_CODE_UNSUPPORTED_VERSION,
					Message:         fmt.Sprintf("Config has major %d; runsc offered %v", h.Major, offer.GetSupportedMajors()),
					SupportedMajors: offer.GetSupportedMajors(),
				})
			}
			if err := hello.ValidateConfig(m, offer); err != nil {
				return invalid(err)
			}
			if err := accept(m); err != nil {
				refuse(err, pb.ErrorCode_ERROR_CODE_REFUSED)
				return fmt.Errorf("refusing hello from network proxy peer at %q: %w", path, err)
			}
			if err := reply(hello.TypeAck, &pb.Ack{}); err != nil {
				return fmt.Errorf("sending hello Ack to network proxy peer at %q: %w", path, err)
			}
			name := m.GetIfname()
			if name == "" {
				name = hello.DefaultInterfaceName
			}
			log.Infof("Network proxy peer at %q configured interface %q: MTU %d, %d addresses, %d routes", path, name, m.GetMtu(), len(m.GetAddresses()), len(m.GetRoutes()))
			return nil
		default:
			return invalid(&hello.Error{
				Code:    pb.ErrorCode_ERROR_CODE_MALFORMED,
				Message: fmt.Sprintf("unexpected %v in reply to Offer", h.Type),
			})
		}
	}
}

// asHelloError returns err as the *hello.Error that it wraps, or as an Error
// with code and err's text.
func asHelloError(err error, code pb.ErrorCode) *hello.Error {
	var e *hello.Error
	if errors.As(err, &e) {
		return e
	}
	return &hello.Error{Code: code, Message: err.Error()}
}

// setTimeout sets socket option opt (SO_RCVTIMEO or SO_SNDTIMEO) on fd to
// the time left until deadline.
func setTimeout(fd, opt int, deadline time.Time) error {
	left := time.Until(deadline)
	// A zero timeout means no timeout.
	if left < time.Microsecond {
		return errHelloTimeout
	}
	tv := unix.NsecToTimeval(left.Nanoseconds())
	return unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, opt, &tv)
}

// sendHello sends msg with header h as one datagram on fd, by deadline.
func sendHello(fd int, deadline time.Time, h hello.Header, msg proto.Message) error {
	b, err := hello.Marshal(h, msg)
	if err != nil {
		return err
	}
	for {
		if err := setTimeout(fd, unix.SO_SNDTIMEO, deadline); err != nil {
			return err
		}
		n, err := unix.SendmsgN(fd, b, nil, nil, unix.MSG_NOSIGNAL)
		switch {
		case errors.Is(err, unix.EINTR):
			continue
		case errors.Is(err, unix.EAGAIN):
			return errHelloTimeout
		case err != nil:
			return err
		case n != len(b):
			return fmt.Errorf("short write of hello %v: %d of %d bytes", h.Type, n, len(b))
		}
		return nil
	}
}

// recvHello receives one datagram from fd into buf, by deadline, and returns
// its length. A datagram larger than buf is truncated to len(buf). The bool
// is true if the peer has closed the connection or shut down its writes.
func recvHello(fd int, buf []byte, deadline time.Time) (int, bool, error) {
	for {
		if err := setTimeout(fd, unix.SO_RCVTIMEO, deadline); err != nil {
			return 0, false, err
		}
		n, err := unix.Read(fd, buf)
		switch {
		case errors.Is(err, unix.EINTR):
			continue
		case errors.Is(err, unix.EAGAIN):
			return 0, false, errHelloTimeout
		case err != nil:
			return 0, false, err
		case n > 0:
			return n, false, nil
		}
		// An empty datagram and EOF both read as 0 bytes. Only EOF sets
		// RCV_SHUTDOWN, which poll(2) reports as POLLRDHUP.
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLRDHUP}}
		if _, err := unix.Poll(fds, 0); err != nil && !errors.Is(err, unix.EINTR) {
			return 0, false, err
		}
		return 0, fds[0].Revents&unix.POLLRDHUP != 0, nil
	}
}

// peerLinksAndRoutes returns the args that create one proxy link for each
// Config in cfgs, which have passed hello validation and are indexed by
// link_index. The links' FDs are not added.
func peerLinksAndRoutes(conf *config.Config, cfgs []*pb.Config, disableIPv6 bool) (sentryapi.CreateLinksAndRoutesArgs, error) {
	loopback := sentryapi.DefaultLoopbackLink
	loopback.GVisorGRO = conf.GVisorGRO
	if disableIPv6 {
		loopback.Addresses = nil
		for _, a := range sentryapi.DefaultLoopbackLink.Addresses {
			if a.Address.To4() != nil {
				loopback.Addresses = append(loopback.Addresses, a)
			}
		}
		loopback.Routes = nil
		for _, r := range sentryapi.DefaultLoopbackLink.Routes {
			if r.Destination.IP.To4() != nil {
				loopback.Routes = append(loopback.Routes, r)
			}
		}
	}
	args := sentryapi.CreateLinksAndRoutesArgs{
		LoopbackLinks:           []sentryapi.LoopbackLink{loopback},
		PauseExternalNetworking: conf.PauseExternalNetworking,
		AllowConnectedOnSave:    conf.AllowConnectedOnSave,
	}

	for _, c := range cfgs {
		name := c.GetIfname()
		if name == "" {
			name = hello.DefaultInterfaceName
		}
		link := sentryapi.FDBasedLink{
			Name:                 name,
			MTU:                  int(c.GetMtu()),
			Multicast:            true,
			NumChannels:          conf.NumNetworkChannels,
			ProcessorsPerChannel: conf.NetworkProcessorsPerChannel,
			QDisc:                conf.QDisc,
			TBFRate:              conf.TBFRate,
			TBFBurst:             uint32(conf.TBFBurst),
			GVisorGRO:            conf.GVisorGRO,
		}
		offloads := c.GetOffloads()
		if offloads == nil {
			link.TXChecksumOffload = conf.TXChecksumOffload
			link.RXChecksumOffload = conf.RXChecksumOffload
		}

		dropped := 0
		for _, a := range c.GetAddresses() {
			if disableIPv6 && len(a.GetIp()) == net.IPv6len {
				dropped++
				continue
			}
			link.Addresses = append(link.Addresses, sentryapi.IPWithPrefix{
				Address:   net.IP(a.GetIp()),
				PrefixLen: int(a.GetPrefixLen()),
			})
		}
		if len(link.Addresses) == 0 {
			return sentryapi.CreateLinksAndRoutesArgs{}, &hello.Error{
				Code:    pb.ErrorCode_ERROR_CODE_REFUSED,
				Field:   "addresses",
				Message: fmt.Sprintf("interface %q has no IPv4 address, and the container disables IPv6", name),
			}
		}
		for _, r := range c.GetRoutes() {
			dst := net.IP(r.GetDst())
			if disableIPv6 && len(dst) == net.IPv6len {
				dropped++
				continue
			}
			route := sentryapi.Route{
				Destination: net.IPNet{
					IP:   dst,
					Mask: net.CIDRMask(int(r.GetDstPrefixLen()), 8*len(dst)),
				},
				MTU: r.GetMtu(),
			}
			if gw := r.GetGateway(); len(gw) != 0 {
				route.Gateway = net.IP(gw)
			}
			if r.GetDstPrefixLen() != 0 {
				link.Routes = append(link.Routes, route)
				continue
			}
			// hello.ValidateConfig allows one default route per family.
			def := sentryapi.DefaultRoute{Route: route, Name: name}
			if len(dst) == net.IPv4len {
				args.Defaultv4Gateway = def
			} else {
				args.Defaultv6Gateway = def
			}
		}
		if dropped > 0 {
			log.Infof("Dropped %d IPv6 addresses and routes of interface %q: the container disables IPv6", dropped, name)
		}

		configureProxyLink(&link)
		// configureProxyLink's TX-implies-RX rule applies only to the
		// flags. The peer's offloads are used as given, so incoming L4
		// checksums are verified unless the peer sets rx_csum.
		if offloads != nil {
			link.TXChecksumOffload = offloads.GetTxCsum()
			link.RXChecksumOffload = offloads.GetRxCsum()
		}
		if conf.GVisorGSO {
			// A proxy link never uses host GSO.
			link.GSOMaxSize = tcpip.GVisorGSOMaxSize
			link.GVisorGSOEnabled = true
		}
		args.FDBasedLinks = append(args.FDBasedLinks, link)
	}
	return args, nil
}
