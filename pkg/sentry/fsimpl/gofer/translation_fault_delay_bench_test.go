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

package gofer

import (
	"fmt"
	"math"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/lisafs"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/limits"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/mm"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/platform"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/unet"
	"gvisor.dev/gvisor/pkg/usermem"
)

const (
	// slowReadStride separates faulted file pages so that each fault's
	// readahead (maxFillRange, 64 KB) leaves the next one cold.
	slowReadStride = 64 << 10
	// slowReadSharedName is a large file shared by all faulting threads.
	// Other names "f<n>" are distinct files of slowReadStride bytes.
	slowReadSharedName = "shared"
	slowReadSharedSize = 1 << 40
	slowReadFileByte   = 0x5a
	// slowReadAnonPages is the number of pre-faulted anonymous pages each
	// anonymous thread cycles through.
	slowReadAnonPages = 64
	// slowReadContentionFaults is the number of cold faults each faulting
	// thread performs per round in BenchmarkSlowReadAnonContention.
	slowReadContentionFaults = 4
)

var (
	slowReadDelays  = []time.Duration{0, 100 * time.Microsecond, time.Millisecond, 10 * time.Millisecond}
	slowReadThreads = []int{1, 4, 16}
	slowReadLayouts = []string{"shared", "distinct"}
)

// slowReadConnImpl serves a root directory containing slowReadSharedName and
// any number of files "f<n>". No host FD is donated, so all page cache fills
// are PReads, each of which sleeps for readDelay.
type slowReadConnImpl struct {
	rootStat  lisafs.Statx
	readDelay time.Duration
	preads    atomicbitops.Int64
}

func (s *slowReadConnImpl) fileStat(name string) (lisafs.Statx, bool) {
	st := lisafs.Statx{
		Mask: linux.STATX_TYPE | linux.STATX_MODE | linux.STATX_INO | linux.STATX_SIZE,
		Mode: linux.S_IFREG | 0644,
	}
	if name == slowReadSharedName {
		st.Ino = 2
		st.Size = slowReadSharedSize
		return st, true
	}
	if len(name) < 2 || name[0] != 'f' {
		return lisafs.Statx{}, false
	}
	n, err := strconv.ParseUint(name[1:], 10, 32)
	if err != nil {
		return lisafs.Statx{}, false
	}
	st.Ino = 1000 + n
	st.Size = slowReadStride
	return st, true
}

// +checklocksread:c.server.renameMu
// +checklocksexclude:c.fdsMu
func (s *slowReadConnImpl) Mount(c *lisafs.Connection, mountNode *lisafs.Node) (*lisafs.ControlFD, lisafs.Statx, int, error) {
	mountNode.IncRef()
	fd := &slowReadControlFD{conn: s, isRoot: true, stat: s.rootStat}
	fd.Init(c, mountNode, linux.ModeDirectory, fd)
	return fd.FD(), s.rootStat, -1, nil
}

func (s *slowReadConnImpl) MaxMessageSize() uint32 {
	return lisafs.MaxMessageSize()
}

func (s *slowReadConnImpl) SupportedMessages() []lisafs.MID {
	return []lisafs.MID{
		lisafs.Mount,
		lisafs.Channel,
		lisafs.FStat,
		lisafs.Walk,
		lisafs.WalkStat,
		lisafs.OpenAt,
		lisafs.Close,
		lisafs.Flush,
		lisafs.PRead,
	}
}

type slowReadControlFD struct {
	lisafs.ControlFD
	lisafs.ControlFDImpl
	conn   *slowReadConnImpl
	isRoot bool
	stat   lisafs.Statx
}

func (fd *slowReadControlFD) FD() *lisafs.ControlFD       { return &fd.ControlFD }
func (fd *slowReadControlFD) Close()                      {}
func (fd *slowReadControlFD) Stat() (lisafs.Statx, error) { return fd.stat, nil }

// +checklocksread:fd.ControlFD.conn.server.renameMu
// +checklocksexclude:fd.ControlFD.conn.fdsMu
func (fd *slowReadControlFD) Walk(name string) (*lisafs.ControlFD, lisafs.Statx, error) {
	st, ok := fd.conn.fileStat(name)
	if !fd.isRoot || !ok {
		return nil, lisafs.Statx{}, unix.ENOENT
	}
	var childNode *lisafs.Node
	fd.Node().WithChildrenMu(func() {
		childNode = fd.Node().LookupChildLocked(name)
		if childNode == nil {
			childNode = &lisafs.Node{}
			childNode.InitLocked(name, fd.Node())
		} else {
			childNode.IncRef()
		}
	})
	child := &slowReadControlFD{conn: fd.conn, stat: st}
	child.Init(fd.Conn(), childNode, linux.FileMode(st.Mode), child) // +checklocksignore
	return child.FD(), st, nil
}

func (fd *slowReadControlFD) WalkStat(path lisafs.StringArray, recordStat func(lisafs.Statx)) error {
	curIsRoot := fd.isRoot
	for i, comp := range path {
		if i == 0 && comp == "" {
			recordStat(fd.stat)
			continue
		}
		if !curIsRoot {
			break
		}
		st, ok := fd.conn.fileStat(comp)
		if !ok {
			break
		}
		recordStat(st)
		curIsRoot = false
	}
	return nil
}

func (fd *slowReadControlFD) Open(flags uint32) (*lisafs.OpenFD, int, error) {
	ofd := &slowReadOpenFD{conn: fd.conn, stat: fd.stat}
	ofd.Init(fd.FD(), flags, ofd)
	return &ofd.OpenFD, -1, nil
}

type slowReadOpenFD struct {
	lisafs.OpenFD
	lisafs.OpenFDImpl
	conn *slowReadConnImpl
	stat lisafs.Statx
}

func (fd *slowReadOpenFD) FD() *lisafs.OpenFD          { return &fd.OpenFD }
func (fd *slowReadOpenFD) Close()                      {}
func (fd *slowReadOpenFD) Stat() (lisafs.Statx, error) { return fd.stat, nil }

func (fd *slowReadOpenFD) Read(buf []byte, off uint64) (uint64, error) {
	fd.conn.preads.Add(1)
	// A blocking host sleep, like a gofer blocked in pread(2). time.Sleep
	// rounds sub-millisecond sleeps up to the netpoller's 1ms timeout when
	// the process is otherwise idle.
	if d := fd.conn.readDelay; d > 0 {
		ts := unix.NsecToTimespec(int64(d))
		for unix.Nanosleep(&ts, &ts) == unix.EINTR {
		}
	}
	if off >= fd.stat.Size {
		return 0, nil
	}
	n := min(uint64(len(buf)), fd.stat.Size-off)
	for i := range buf[:n] {
		buf[i] = slowReadFileByte
	}
	return n, nil
}

// slowReadEnv is a gofer mount backed by slowReadConnImpl and a
// MemoryManager whose goroutines act as threads of one process.
type slowReadEnv struct {
	ctx      context.Context
	creds    *auth.Credentials
	conn     *slowReadConnImpl
	vfsObj   *vfs.VirtualFilesystem
	root     vfs.VirtualDentry
	mm       *mm.MemoryManager
	shared   *vfs.FileDescription
	nextOff  uint64
	nextFile int
}

func newSlowReadEnv(b *testing.B, delay time.Duration) *slowReadEnv {
	b.Helper()
	e := &slowReadEnv{ctx: contexttest.Context(b)}
	ctx := e.ctx
	e.creds = auth.CredentialsFromContext(ctx)

	serverSock, clientSock, err := unet.SocketPair(false)
	if err != nil {
		b.Fatalf("unet.SocketPair: %v", err)
	}
	srv := lisafs.NewServer()
	b.Cleanup(func() { srv.Destroy() })
	e.conn = &slowReadConnImpl{
		rootStat: lisafs.Statx{
			Mask: linux.STATX_TYPE | linux.STATX_MODE | linux.STATX_INO,
			Mode: linux.S_IFDIR | 0755,
			Ino:  1,
		},
		readDelay: delay,
	}
	conn, err := srv.CreateConnection(serverSock, "/", lisafs.ConnectionOpts{WalkStatSupported: true}, e.conn)
	if err != nil {
		clientSock.Close()
		serverSock.Close()
		b.Fatalf("srv.CreateConnection: %v", err)
	}
	srv.StartConnection(conn)
	b.Cleanup(func() { srv.Wait() })

	e.vfsObj = &vfs.VirtualFilesystem{}
	if err := e.vfsObj.Init(ctx); err != nil {
		clientSock.Close()
		b.Fatalf("vfsObj.Init: %v", err)
	}
	b.Cleanup(func() { e.vfsObj.Release(ctx) })
	e.vfsObj.MustRegisterFilesystemType(Name, FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserMount: true,
	})
	sockFD, err := clientSock.Release()
	if err != nil {
		b.Fatalf("clientSock.Release: %v", err)
	}
	mntns, err := e.vfsObj.NewMountNamespace(ctx, e.creds, "", Name, &vfs.MountOptions{
		GetFilesystemOptions: vfs.GetFilesystemOptions{
			Data: fmt.Sprintf("trans=fd,rfdno=%d,wfdno=%d,cache=%s", sockFD, sockFD, cacheFSCache),
		},
	}, nil)
	if err != nil {
		_ = unix.Close(sockFD)
		b.Fatalf("NewMountNamespace: %v", err)
	}
	b.Cleanup(func() { mntns.DecRef(ctx) })
	e.root = mntns.Root(ctx)
	b.Cleanup(func() { e.root.DecRef(ctx) })

	e.mm, err = mm.NewMemoryManager(platform.FromContext(ctx), pgalloc.MemoryFileFromContext(ctx))
	if err != nil {
		b.Fatalf("NewMemoryManager: %v", err)
	}
	b.Cleanup(func() { e.mm.DecUsers(ctx) })
	if _, err := e.mm.SetMmapLayout(&arch.Context64{}, limits.NewLimitSet()); err != nil {
		b.Fatalf("SetMmapLayout: %v", err)
	}

	e.shared = e.open(b, slowReadSharedName)
	b.Cleanup(func() { e.shared.DecRef(ctx) })
	return e
}

func (e *slowReadEnv) open(b *testing.B, name string) *vfs.FileDescription {
	fd, err := e.vfsObj.OpenAt(e.ctx, e.creds, &vfs.PathOperation{
		Root:  e.root,
		Start: e.root,
		Path:  fspath.Parse(name),
	}, &vfs.OpenOptions{Flags: linux.O_RDONLY})
	if err != nil {
		b.Fatalf("OpenAt(%q): %v", name, err)
	}
	if got := fd.Dentry().Impl().(*dentry).inode.mmapFD.Load(); got >= 0 {
		b.Fatalf("%q: mmapFD = %d, want none", name, got)
	}
	return fd
}

func (e *slowReadEnv) mmapFile(b *testing.B, fd *vfs.FileDescription, off, length uint64) hostarch.Addr {
	opts := memmap.MMapOpts{
		Length:   length,
		Offset:   off,
		Private:  true,
		Perms:    hostarch.Read,
		MaxPerms: hostarch.AnyAccess,
	}
	if err := fd.ConfigureMMap(e.ctx, &opts); err != nil {
		b.Fatalf("ConfigureMMap: %v", err)
	}
	addr, err := e.mm.MMap(e.ctx, opts)
	opts.MappingIdentity.DecRef(e.ctx)
	if err != nil {
		b.Fatalf("MMap(file): %v", err)
	}
	return addr
}

// slowReadMapping is a set of cold file pages, one per address.
type slowReadMapping struct {
	addrs []hostarch.Addr
	unmap []hostarch.AddrRange
	fds   []*vfs.FileDescription
}

// mapCold maps n cold file pages. If layout is "shared", they are distinct
// pages of one file; otherwise each is in its own file.
func (e *slowReadEnv) mapCold(b *testing.B, layout string, n int) *slowReadMapping {
	m := &slowReadMapping{}
	if layout == "shared" {
		length := uint64(n) * slowReadStride
		addr := e.mmapFile(b, e.shared, e.nextOff, length)
		e.nextOff += length
		for i := 0; i < n; i++ {
			m.addrs = append(m.addrs, addr+hostarch.Addr(i*slowReadStride))
		}
		m.unmap = append(m.unmap, hostarch.AddrRange{Start: addr, End: addr + hostarch.Addr(length)})
		return m
	}
	for i := 0; i < n; i++ {
		fd := e.open(b, fmt.Sprintf("f%d", e.nextFile))
		e.nextFile++
		addr := e.mmapFile(b, fd, 0, slowReadStride)
		m.addrs = append(m.addrs, addr)
		m.unmap = append(m.unmap, hostarch.AddrRange{Start: addr, End: addr + slowReadStride})
		m.fds = append(m.fds, fd)
	}
	return m
}

func (e *slowReadEnv) release(b *testing.B, m *slowReadMapping) {
	for _, ar := range m.unmap {
		if err := e.mm.MUnmap(e.ctx, ar.Start, uint64(ar.Length())); err != nil {
			b.Fatalf("MUnmap: %v", err)
		}
	}
	for _, fd := range m.fds {
		fd.DecRef(e.ctx)
	}
}

func (e *slowReadEnv) fault(b *testing.B, addr hostarch.Addr) {
	if err := e.mm.HandleUserFault(e.ctx, addr, hostarch.Read, 0); err != nil {
		b.Errorf("HandleUserFault(%#x): %v", addr, err)
	}
}

// slowReadHist is a log-linear latency histogram with ~2% resolution.
type slowReadHist [1400]uint64

const slowReadHistBase = 1.02

func (h *slowReadHist) add(d time.Duration) {
	i := 0
	if d > 1 {
		i = int(math.Log(float64(d)) / math.Log(slowReadHistBase))
	}
	h[min(i, len(h)-1)]++
}

func (h *slowReadHist) merge(o *slowReadHist) {
	for i := range h {
		h[i] += o[i]
	}
}

func (h *slowReadHist) count() uint64 {
	var n uint64
	for _, c := range h {
		n += c
	}
	return n
}

// quantile returns the upper bound of the bucket containing quantile q.
func (h *slowReadHist) quantile(q float64) time.Duration {
	total := h.count()
	if total == 0 {
		return 0
	}
	want := uint64(math.Ceil(q * float64(total)))
	var seen uint64
	for i, c := range h {
		seen += c
		if seen >= want && c != 0 {
			return time.Duration(math.Pow(slowReadHistBase, float64(i+1)))
		}
	}
	return 0
}

func slowReadSweep(b *testing.B, f func(b *testing.B, layout string, delay time.Duration, threads int)) {
	for _, layout := range slowReadLayouts {
		for _, delay := range slowReadDelays {
			for _, threads := range slowReadThreads {
				if delay == 0 && threads != 4 {
					continue
				}
				b.Run(fmt.Sprintf("layout=%s/delay=%v/threads=%d", layout, delay, threads), func(b *testing.B) {
					f(b, layout, delay, threads)
				})
			}
		}
	}
}

// BenchmarkSlowReadParallelFaults measures the wall time for threads threads
// of one MM to each take one user fault on a distinct cold page of a gofer
// file with no host FD, with every PRead taking delay.
func BenchmarkSlowReadParallelFaults(b *testing.B) {
	slowReadSweep(b, func(b *testing.B, layout string, delay time.Duration, threads int) {
		e := newSlowReadEnv(b, delay)
		var wall time.Duration
		var preads int64
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			b.StopTimer()
			m := e.mapCold(b, layout, threads)
			before := e.conn.preads.Load()
			var wg sync.WaitGroup
			start := make(chan struct{})
			for _, addr := range m.addrs {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					e.fault(b, addr)
				}()
			}
			b.StartTimer()
			t0 := time.Now()
			close(start)
			wg.Wait()
			wall += time.Since(t0)
			b.StopTimer()
			preads += e.conn.preads.Load() - before
			e.release(b, m)
			b.StartTimer()
		}
		b.StopTimer()
		mean := wall / time.Duration(b.N)
		b.ReportMetric(float64(mean)/float64(time.Millisecond), "wall-ms")
		if delay > 0 {
			b.ReportMetric(float64(mean)/float64(delay), "wall/delay")
		}
		b.ReportMetric(float64(preads)/float64(b.N*threads), "preads/fault")
	})
}

// BenchmarkSlowReadAnonContention runs threads threads that CopyOut to
// already-faulted anonymous memory while threads other threads of the same
// MM each take slowReadContentionFaults user faults on distinct cold gofer
// pages. It reports the anonymous threads' aggregate throughput and latency
// during the faulting phase.
func BenchmarkSlowReadAnonContention(b *testing.B) {
	slowReadSweep(b, func(b *testing.B, layout string, delay time.Duration, threads int) {
		e := newSlowReadEnv(b, delay)
		anon := make([]hostarch.Addr, threads)
		for i := range anon {
			addr, err := e.mm.MMap(e.ctx, memmap.MMapOpts{
				Length:   slowReadAnonPages * uint64(hostarch.PageSize),
				Private:  true,
				Perms:    hostarch.ReadWrite,
				MaxPerms: hostarch.AnyAccess,
			})
			if err != nil {
				b.Fatalf("MMap(anonymous): %v", err)
			}
			for p := range uintptr(slowReadAnonPages) {
				if _, err := e.mm.CopyOut(e.ctx, addr+hostarch.Addr(p*hostarch.PageSize), []byte{1}, usermem.IOOpts{}); err != nil {
					b.Fatalf("CopyOut(anonymous): %v", err)
				}
			}
			anon[i] = addr
		}

		var hist slowReadHist
		var ops uint64
		var phase time.Duration
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			b.StopTimer()
			m := e.mapCold(b, layout, threads*slowReadContentionFaults)
			var stop atomicbitops.Bool
			hists := make([]slowReadHist, threads)
			var anonWG, faultWG sync.WaitGroup
			start := make(chan struct{})
			for t := 0; t < threads; t++ {
				anonWG.Add(1)
				go func() {
					defer anonWG.Done()
					buf := make([]byte, 8)
					<-start
					for p := uintptr(0); !stop.Load(); p = (p + 1) % slowReadAnonPages {
						t0 := time.Now()
						if _, err := e.mm.CopyOut(e.ctx, anon[t]+hostarch.Addr(p*hostarch.PageSize), buf, usermem.IOOpts{}); err != nil {
							b.Errorf("CopyOut(anonymous): %v", err)
							return
						}
						hists[t].add(time.Since(t0))
					}
				}()
				faultWG.Add(1)
				go func() {
					defer faultWG.Done()
					<-start
					for _, addr := range m.addrs[t*slowReadContentionFaults : (t+1)*slowReadContentionFaults] {
						e.fault(b, addr)
					}
				}()
			}
			b.StartTimer()
			t0 := time.Now()
			close(start)
			faultWG.Wait()
			phase += time.Since(t0)
			stop.Store(true)
			anonWG.Wait()
			b.StopTimer()
			for t := range hists {
				ops += hists[t].count()
				hist.merge(&hists[t])
			}
			e.release(b, m)
			b.StartTimer()
		}
		b.StopTimer()
		b.ReportMetric(float64(phase)/float64(time.Millisecond)/float64(b.N), "fault-phase-ms")
		b.ReportMetric(float64(ops)/phase.Seconds()/1e6, "anon-Mops/s")
		b.ReportMetric(float64(hist.quantile(0.5))/float64(time.Microsecond), "anon-p50-us")
		b.ReportMetric(float64(hist.quantile(0.99))/float64(time.Microsecond), "anon-p99-us")
		b.ReportMetric(float64(hist.quantile(1))/float64(time.Microsecond), "anon-max-us")
	})
}
