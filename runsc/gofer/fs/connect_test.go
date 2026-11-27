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

package connect_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/lisafs"
	"gvisor.dev/gvisor/pkg/unet"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/gofer/fs"
)

func init() {
	if err := fs.OpenProcSelfFD("/proc/self/fd"); err != nil {
		panic(err)
	}
}

// listen creates a socket listening at path. If full, it fills the accept
// queue. It does not accept connections.
func listen(t *testing.T, path string, sockType int, full bool) int {
	t.Helper()
	fd, err := unix.Socket(unix.AF_UNIX, sockType, 0)
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	if err := unix.Bind(fd, &unix.SockaddrUnix{Name: path}); err != nil {
		t.Fatalf("bind(%q): %v", path, err)
	}
	backlog := 16
	if full {
		backlog = 0
	}
	if err := unix.Listen(fd, backlog); err != nil {
		t.Fatalf("listen: %v", err)
	}
	for full {
		c, err := unix.Socket(unix.AF_UNIX, sockType|unix.SOCK_NONBLOCK, 0)
		if err != nil {
			t.Fatalf("socket: %v", err)
		}
		t.Cleanup(func() { _ = unix.Close(c) })
		if err := unix.Connect(c, &unix.SockaddrUnix{Name: path}); err == unix.EAGAIN {
			break
		} else if err != nil {
			t.Fatalf("connect(%q): %v", path, err)
		}
	}
	return fd
}

type result struct {
	fd  int
	err error
}

// connect walks root to name and connects to it in another goroutine.
func connect(t *testing.T, root lisafs.ClientFD, name string, sockType linux.SockType, blocking, creds bool) <-chan result {
	t.Helper()
	ctx := context.Background()
	inode, err := root.Walk(ctx, name)
	if err != nil {
		t.Fatalf("Walk(%q): %v", name, err)
	}
	fd := root.Client().NewFD(inode.ControlFD)
	uid, gid := lisafs.NoUID, lisafs.NoGID
	if creds {
		uid, gid = lisafs.UID(unix.Geteuid()), lisafs.GID(unix.Getegid())
	}
	ch := make(chan result, 1)
	go func() {
		sock, err := fd.Connect(ctx, sockType, blocking, uid, gid, nil /* groups */)
		fd.Close(ctx, false /* flush */)
		ch <- result{sock, err}
	}()
	return ch
}

func TestNonBlockingConnect(t *testing.T) {
	for _, tc := range []struct {
		name string
		// creds selects ConnectWithCreds or ConnectWithGroups over Connect, and
		// canSetGroups selects ConnectWithGroups over ConnectWithCreds. The
		// requested groups match the gofer's, so the gofer does not change them.
		creds        bool
		canSetGroups bool
	}{
		{name: "Connect"},
		{name: "ConnectWithCreds", creds: true},
		{name: "ConnectWithGroups", creds: true, canSetGroups: true},
	} {
		for _, st := range []struct {
			name string
			typ  int
		}{{"stream", unix.SOCK_STREAM}, {"seqpacket", unix.SOCK_SEQPACKET}} {
			t.Run(tc.name+"/"+st.name, func(t *testing.T) {
				// A socket path must fit in sockaddr_un, so use a short directory.
				dir, err := os.MkdirTemp("/tmp", "connect_test")
				if err != nil {
					t.Fatalf("MkdirTemp: %v", err)
				}
				t.Cleanup(func() { _ = os.RemoveAll(dir) })

				serverSock, clientSock, err := unet.SocketPair(false)
				if err != nil {
					t.Fatalf("SocketPair: %v", err)
				}
				server := lisafs.NewServer()
				impl := fs.NewConnectionImpl(&fs.Config{
					HostUDS:      config.HostUDSOpen,
					RUID:         unix.Getuid(),
					EUID:         unix.Geteuid(),
					RGID:         unix.Getgid(),
					EGID:         unix.Getegid(),
					Groups:       []int{},
					CanSetGroups: tc.canSetGroups,
				})
				conn, err := server.CreateConnection(serverSock, dir, fs.ConnectionOpts(false /* readonly */), impl)
				if err != nil {
					t.Fatalf("CreateConnection: %v", err)
				}
				server.StartConnection(conn)
				client, rootInode, _, err := lisafs.NewClient(clientSock)
				if err != nil {
					t.Fatalf("NewClient: %v", err)
				}
				t.Cleanup(func() {
					client.Close()
					server.Wait()
				})
				if err := client.StartChannels(); err != nil {
					t.Fatalf("StartChannels: %v", err)
				}
				if got := client.IsSupported(lisafs.ConnectWithGroups); got != tc.canSetGroups {
					t.Fatalf("IsSupported(ConnectWithGroups) = %t, want %t", got, tc.canSetGroups)
				}
				root := client.NewFD(rootInode.ControlFD)
				sockType := linux.SockType(st.typ)

				// Cleanups run in reverse order, so the listeners close before
				// the server shuts down. That ends any connect still waiting in
				// the gofer.
				full := listen(t, filepath.Join(dir, "full"), st.typ, true /* full */)
				listen(t, filepath.Join(dir, "room"), st.typ, false /* full */)

				// A non-blocking connect to a full queue fails at once.
				select {
				case r := <-connect(t, root, "full", sockType, false /* blocking */, tc.creds):
					if r.err != unix.EAGAIN {
						if r.err == nil {
							_ = unix.Close(r.fd)
						}
						t.Errorf("non-blocking connect to a full queue: got (%d, %v), want EAGAIN", r.fd, r.err)
					}
				case <-time.After(5 * time.Second):
					t.Fatalf("non-blocking connect to a full queue did not return")
				}

				// A non-blocking connect to a queue with room succeeds.
				r := <-connect(t, root, "room", sockType, false /* blocking */, tc.creds)
				if r.err != nil {
					t.Errorf("non-blocking connect to a queue with room: %v", r.err)
				} else {
					_ = unix.Close(r.fd)
				}

				// A blocking connect to a full queue waits until the queue has room.
				ch := connect(t, root, "full", sockType, true /* blocking */, tc.creds)
				select {
				case r := <-ch:
					t.Fatalf("blocking connect to a full queue returned (%d, %v), want it to wait", r.fd, r.err)
				case <-time.After(200 * time.Millisecond):
				}
				nfd, _, err := unix.Accept4(full, unix.SOCK_CLOEXEC)
				if err != nil {
					t.Fatalf("accept: %v", err)
				}
				_ = unix.Close(nfd)
				select {
				case r := <-ch:
					if r.err != nil {
						t.Errorf("blocking connect after accept: %v", r.err)
					} else {
						_ = unix.Close(r.fd)
					}
				case <-time.After(5 * time.Second):
					t.Fatalf("blocking connect did not return after accept")
				}
			})
		}
	}
}
