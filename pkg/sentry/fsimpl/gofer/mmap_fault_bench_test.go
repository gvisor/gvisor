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
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
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
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/unet"
	"gvisor.dev/gvisor/pkg/usermem"
)

const (
	// benchPages is the number of file pages faulted per round. Setup and
	// teardown between rounds are excluded from timing.
	benchPages = 4096
	// benchChunk is the size of each kernel copy, and the gofer readahead
	// limit (maxFillRange).
	benchChunk = 64 << 10
)

var (
	benchPageSize = uint64(hostarch.PageSize)
	benchSize     = benchPages * benchPageSize
)

// benchConnImpl serves a root directory containing one regular file,
// "target", of benchSize bytes. If hostFD >= 0, opening "target" donates a
// duplicate of hostFD; otherwise all reads are lisafs PReads served from
// memory without delay.
type benchConnImpl struct {
	rootStat lisafs.Statx
	fileStat lisafs.Statx
	hostFD   int
}

// +checklocksread:c.server.renameMu
// +checklocksexclude:c.fdsMu
func (s *benchConnImpl) Mount(c *lisafs.Connection, mountNode *lisafs.Node) (*lisafs.ControlFD, lisafs.Statx, int, error) {
	mountNode.IncRef()
	fd := &benchControlFD{conn: s, isRoot: true}
	fd.Init(c, mountNode, linux.ModeDirectory, fd)
	return fd.FD(), s.rootStat, -1, nil
}

func (s *benchConnImpl) MaxMessageSize() uint32 {
	return lisafs.MaxMessageSize()
}

func (s *benchConnImpl) SupportedMessages() []lisafs.MID {
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

type benchControlFD struct {
	lisafs.ControlFD
	lisafs.ControlFDImpl
	conn   *benchConnImpl
	isRoot bool
}

func (fd *benchControlFD) FD() *lisafs.ControlFD { return &fd.ControlFD }
func (fd *benchControlFD) Close()                {}

func (fd *benchControlFD) Stat() (lisafs.Statx, error) {
	if fd.isRoot {
		return fd.conn.rootStat, nil
	}
	return fd.conn.fileStat, nil
}

// +checklocksread:fd.ControlFD.conn.server.renameMu
// +checklocksexclude:fd.ControlFD.conn.fdsMu
func (fd *benchControlFD) Walk(name string) (*lisafs.ControlFD, lisafs.Statx, error) {
	if !fd.isRoot || name != "target" {
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
	child := &benchControlFD{conn: fd.conn}
	child.Init(fd.Conn(), childNode, linux.FileMode(fd.conn.fileStat.Mode), child) // +checklocksignore
	return child.FD(), fd.conn.fileStat, nil
}

func (fd *benchControlFD) WalkStat(path lisafs.StringArray, recordStat func(lisafs.Statx)) error {
	curIsRoot := fd.isRoot
	for i, comp := range path {
		if i == 0 && comp == "" {
			st, _ := fd.Stat()
			recordStat(st)
			continue
		}
		if curIsRoot && comp == "target" {
			recordStat(fd.conn.fileStat)
			curIsRoot = false
			continue
		}
		break
	}
	return nil
}

func (fd *benchControlFD) Open(flags uint32) (*lisafs.OpenFD, int, error) {
	ofd := &benchOpenFD{conn: fd.conn}
	ofd.Init(fd.FD(), flags, ofd)
	hostFD := -1
	if fd.conn.hostFD >= 0 {
		var err error
		if hostFD, err = unix.Dup(fd.conn.hostFD); err != nil {
			return nil, -1, err
		}
	}
	return &ofd.OpenFD, hostFD, nil
}

type benchOpenFD struct {
	lisafs.OpenFD
	lisafs.OpenFDImpl
	conn *benchConnImpl
}

func (fd *benchOpenFD) FD() *lisafs.OpenFD          { return &fd.OpenFD }
func (fd *benchOpenFD) Close()                      {}
func (fd *benchOpenFD) Stat() (lisafs.Statx, error) { return fd.conn.fileStat, nil }

func (fd *benchOpenFD) Read(buf []byte, off uint64) (uint64, error) {
	size := fd.conn.fileStat.Size
	if off >= size {
		return 0, nil
	}
	n := min(uint64(len(buf)), size-off)
	for i := range buf[:n] {
		buf[i] = 0x5a
	}
	return n, nil
}

// noMapPlatform wraps a platform.Platform so that its address spaces ignore
// MapFile and Unmap. This removes the cost of mapping into the stub process
// and leaves only MemoryManager and Mappable costs.
type noMapPlatform struct {
	platform.Platform
}

func (p noMapPlatform) NewAddressSpace(opts platform.AddressSpaceOptions) (platform.AddressSpace, error) {
	as, err := p.Platform.NewAddressSpace(opts)
	if err != nil {
		return nil, err
	}
	return noMapAddressSpace{as}, nil
}

type noMapAddressSpace struct {
	platform.AddressSpace
}

func (noMapAddressSpace) MapFile(hostarch.Addr, memmap.File, memmap.FileRange, hostarch.AccessType, bool) error {
	return nil
}

func (noMapAddressSpace) Unmap(hostarch.Addr, uint64) {}

// benchEnv is a gofer mount containing "target" and a MemoryManager.
type benchEnv struct {
	ctx context.Context
	m   *mm.MemoryManager
	fd  *vfs.FileDescription
	d   *dentry
}

// newBenchEnv mounts the benchmark file system, giving the file a host FD if
// hostFD is true, and creates a MemoryManager that maps faulted pages into a
// ptrace stub process if mapAS is true.
func newBenchEnv(b *testing.B, hostFD, mapAS bool) *benchEnv {
	b.Helper()
	if usage.MemoryAccounting == nil {
		// Host FD mappings account mapped host memory.
		if err := usage.Init(); err != nil {
			b.Fatalf("usage.Init: %v", err)
		}
	}
	ctx := contexttest.Context(b)
	creds := auth.CredentialsFromContext(ctx)

	connImpl := &benchConnImpl{
		rootStat: lisafs.Statx{
			Mask:     linux.STATX_TYPE | linux.STATX_MODE | linux.STATX_INO,
			Mode:     linux.S_IFDIR | 0755,
			DevMinor: 1,
			Ino:      1,
		},
		fileStat: lisafs.Statx{
			Mask:     linux.STATX_TYPE | linux.STATX_MODE | linux.STATX_INO | linux.STATX_SIZE,
			Mode:     linux.S_IFREG | 0644,
			DevMinor: 1,
			Ino:      42,
			Size:     benchSize,
		},
		hostFD: -1,
	}
	if hostFD {
		mfd, err := unix.MemfdCreate("gofer-bench", 0)
		if err != nil {
			b.Fatalf("memfd_create: %v", err)
		}
		b.Cleanup(func() { unix.Close(mfd) })
		if err := unix.Ftruncate(mfd, int64(benchSize)); err != nil {
			b.Fatalf("ftruncate: %v", err)
		}
		connImpl.hostFD = mfd
	}

	serverSock, clientSock, err := unet.SocketPair(false)
	if err != nil {
		b.Fatalf("unet.SocketPair: %v", err)
	}
	srv := lisafs.NewServer()
	b.Cleanup(func() { srv.Destroy() })
	conn, err := srv.CreateConnection(serverSock, "/", lisafs.ConnectionOpts{WalkStatSupported: true}, connImpl)
	if err != nil {
		clientSock.Close()
		serverSock.Close()
		b.Fatalf("srv.CreateConnection: %v", err)
	}
	srv.StartConnection(conn)
	b.Cleanup(func() { srv.Wait() })

	vfsObj := &vfs.VirtualFilesystem{}
	if err := vfsObj.Init(ctx); err != nil {
		clientSock.Close()
		b.Fatalf("vfsObj.Init: %v", err)
	}
	b.Cleanup(func() { vfsObj.Release(ctx) })
	vfsObj.MustRegisterFilesystemType(Name, FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserMount: true,
	})
	sockFD, err := clientSock.Release()
	if err != nil {
		b.Fatalf("clientSock.Release: %v", err)
	}
	mntns, err := vfsObj.NewMountNamespace(ctx, creds, "", Name, &vfs.MountOptions{
		GetFilesystemOptions: vfs.GetFilesystemOptions{
			Data: fmt.Sprintf("trans=fd,rfdno=%d,wfdno=%d,cache=%s", sockFD, sockFD, cacheFSCache),
		},
	}, nil)
	if err != nil {
		_ = unix.Close(sockFD)
		b.Fatalf("NewMountNamespace: %v", err)
	}
	b.Cleanup(func() { mntns.DecRef(ctx) })
	root := mntns.Root(ctx)
	b.Cleanup(func() { root.DecRef(ctx) })

	fd, err := vfsObj.OpenAt(ctx, creds, &vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse("target"),
	}, &vfs.OpenOptions{Flags: linux.O_RDONLY})
	if err != nil {
		b.Fatalf("OpenAt: %v", err)
	}
	b.Cleanup(func() { fd.DecRef(ctx) })
	d := fd.Dentry().Impl().(*dentry)
	if got := d.inode.mmapFD.Load() >= 0; got != hostFD {
		b.Fatalf("has host FD = %t, want %t", got, hostFD)
	}

	p := platform.FromContext(ctx)
	if !mapAS {
		p = noMapPlatform{p}
	}
	m, err := mm.NewMemoryManager(p, pgalloc.MemoryFileFromContext(ctx))
	if err != nil {
		b.Fatalf("NewMemoryManager: %v", err)
	}
	b.Cleanup(func() { m.DecUsers(ctx) })
	if _, err := m.SetMmapLayout(&arch.Context64{}, limits.NewLimitSet()); err != nil {
		b.Fatalf("SetMmapLayout: %v", err)
	}
	return &benchEnv{ctx: ctx, m: m, fd: fd, d: d}
}

// mmap creates a private mapping of the file, or of anonymous memory if anon
// is true.
func (e *benchEnv) mmap(b *testing.B, anon bool, opts memmap.MMapOpts) hostarch.Addr {
	opts.Private = true
	opts.MaxPerms = hostarch.AnyAccess
	if !anon {
		if err := e.fd.ConfigureMMap(e.ctx, &opts); err != nil {
			b.Fatalf("ConfigureMMap: %v", err)
		}
		defer opts.MappingIdentity.DecRef(e.ctx)
	}
	addr, err := e.m.MMap(e.ctx, opts)
	if err != nil {
		b.Fatalf("MMap(%+v): %v", opts, err)
	}
	return addr
}

// mapSparse maps each page of the file (or anonymous memory, if anon) as a
// separate vma, separated by PROT_NONE pages, so that every fault translates
// exactly one page. It returns the address of each page.
func (e *benchEnv) mapSparse(b *testing.B, anon bool) (hostarch.Addr, []hostarch.Addr) {
	base := e.mmap(b, true, memmap.MMapOpts{Length: 2 * benchSize, Perms: hostarch.NoAccess})
	addrs := make([]hostarch.Addr, benchPages)
	for i := range addrs {
		addrs[i] = base + hostarch.Addr(2*uint64(i)*benchPageSize)
		if anon {
			if err := e.m.MProtect(addrs[i], benchPageSize, hostarch.Read, false); err != nil {
				b.Fatalf("MProtect: %v", err)
			}
			continue
		}
		e.mmap(b, false, memmap.MMapOpts{
			Length: benchPageSize,
			Offset: uint64(i) * benchPageSize,
			Addr:   addrs[i],
			Fixed:  true,
			Unmap:  true,
			Perms:  hostarch.Read,
		})
	}
	return base, addrs
}

// mapContiguous maps the whole file as one vma.
func (e *benchEnv) mapContiguous(b *testing.B, perms hostarch.AccessType) hostarch.Addr {
	return e.mmap(b, false, memmap.MMapOpts{Length: benchSize, Perms: perms})
}

func (e *benchEnv) unmap(b *testing.B, addr hostarch.Addr, length uint64) {
	if err := e.m.MUnmap(e.ctx, addr, length); err != nil {
		b.Fatalf("MUnmap: %v", err)
	}
}

// pinCache fills the file's sentry page cache and keeps it mapped, so the
// MemoryFile can't evict it.
func (e *benchEnv) pinCache(b *testing.B) {
	addr := e.mapContiguous(b, hostarch.Read)
	if _, err := e.m.CopyIn(e.ctx, addr, make([]byte, benchSize), usermem.IOOpts{}); err != nil {
		b.Fatalf("CopyIn: %v", err)
	}
}

// dropCache evicts the file's sentry page cache. The file must not be mapped.
func (e *benchEnv) dropCache() {
	e.d.inode.Evict(e.ctx, pgalloc.EvictableRange{Start: 0, End: benchSize})
}

// rounds calls f(n) for batches of at most per operations until b.N
// operations have run, calling teardown and setup untimed between batches.
func rounds(b *testing.B, per int, setup func(), f func(n int), teardown func()) {
	setup()
	b.ResetTimer()
	for done := 0; done < b.N; {
		n := min(per, b.N-done)
		f(n)
		done += n
		b.StopTimer()
		teardown()
		setup()
		b.StartTimer()
	}
	b.StopTimer()
	teardown()
}

// parallel runs f(i) for i in [0, n) on threads goroutines.
func parallel(threads, n int, f func(i int)) {
	if threads == 1 {
		for i := 0; i < n; i++ {
			f(i)
		}
		return
	}
	var wg sync.WaitGroup
	for t := 0; t < threads; t++ {
		wg.Add(1)
		go func(t int) {
			defer wg.Done()
			for i := t; i < n; i += threads {
				f(i)
			}
		}(t)
	}
	wg.Wait()
}

type benchBacking struct {
	name   string
	hostFD bool
	anon   bool
	// cold evicts the page cache between rounds; otherwise it is filled once.
	cold bool
}

// benchASModes selects whether faults also map pages into a ptrace stub
// address space, as under runsc's ptrace platform.
var benchASModes = []struct {
	name  string
	mapAS bool
}{{"none", false}, {"ptrace", true}}

var faultBackings = []benchBacking{
	{name: "anon", anon: true},
	{name: "hostfd", hostFD: true},
	{name: "nohostfd-cold", cold: true},
	{name: "nohostfd-warm"},
}

// BenchmarkMMapFaultPerPage measures HandleUserFault for read faults on pages
// that each form their own vma, so every fault translates one page.
func BenchmarkMMapFaultPerPage(b *testing.B) {
	for _, as := range benchASModes {
		for _, bk := range faultBackings {
			for _, threads := range []int{1, 4} {
				b.Run(fmt.Sprintf("as=%s/%s/threads=%d", as.name, bk.name, threads), func(b *testing.B) {
					benchFaultPerPage(b, as.mapAS, bk, threads)
				})
			}
		}
	}
}

func benchFaultPerPage(b *testing.B, mapAS bool, bk benchBacking, threads int) {
	e := newBenchEnv(b, bk.hostFD, mapAS)
	var base hostarch.Addr
	var addrs []hostarch.Addr
	fault := func(i int) {
		if err := e.m.HandleUserFault(e.ctx, addrs[i], hostarch.Read, 0); err != nil {
			b.Errorf("HandleUserFault: %v", err)
		}
	}
	setup := func() { base, addrs = e.mapSparse(b, bk.anon) }
	teardown := func() {
		e.unmap(b, base, 2*benchSize)
		if bk.cold {
			e.dropCache()
		}
	}
	if !bk.anon && !bk.hostFD && !bk.cold {
		e.pinCache(b)
	}
	rounds(b, benchPages, setup, func(n int) { parallel(threads, n, fault) }, teardown)
}

// BenchmarkMMapFaultReadahead measures HandleUserFault for read faults at
// readahead (64 KiB) strides of one vma mapping the whole file, so each fault
// on a cold page cache fills one readahead window. ns/op is per fault.
func BenchmarkMMapFaultReadahead(b *testing.B) {
	for _, as := range benchASModes {
		for _, bk := range faultBackings[2:] {
			b.Run("as="+as.name+"/"+bk.name, func(b *testing.B) {
				benchFaultReadahead(b, as.mapAS, bk)
			})
		}
	}
}

func benchFaultReadahead(b *testing.B, mapAS bool, bk benchBacking) {
	e := newBenchEnv(b, bk.hostFD, mapAS)
	per := int(benchSize / benchChunk)
	var addr hostarch.Addr
	fault := func(i int) {
		if err := e.m.HandleUserFault(e.ctx, addr+hostarch.Addr(uint64(i)*benchChunk), hostarch.Read, 0); err != nil {
			b.Errorf("HandleUserFault: %v", err)
		}
	}
	setup := func() { addr = e.mapContiguous(b, hostarch.Read) }
	teardown := func() {
		e.unmap(b, addr, benchSize)
		if bk.cold {
			e.dropCache()
		}
	}
	if !bk.cold {
		e.pinCache(b)
	}
	rounds(b, per, setup, func(n int) { parallel(1, n, fault) }, teardown)
}

// BenchmarkMMapKernelCopy measures the sentry copying 64 KiB to or from a
// private mapping of the file (MemoryManager.CopyIn / CopyOut, i.e.
// withInternalMappings), each op touching a fresh 64 KiB of the mapping.
func BenchmarkMMapKernelCopy(b *testing.B) {
	for _, dir := range []string{"copyin", "copyout"} {
		for _, bk := range []benchBacking{
			{name: "hostfd", hostFD: true},
			{name: "nohostfd-cold", cold: true},
			{name: "nohostfd-warm"},
		} {
			b.Run(dir+"/"+bk.name, func(b *testing.B) {
				e := newBenchEnv(b, bk.hostFD, false /* mapAS */)
				per := int(benchSize / benchChunk)
				perms := hostarch.Read
				if dir == "copyout" {
					perms = hostarch.ReadWrite
				}
				buf := make([]byte, benchChunk)
				var addr hostarch.Addr
				cp := func(i int) {
					a := addr + hostarch.Addr(uint64(i)*benchChunk)
					var err error
					if dir == "copyin" {
						_, err = e.m.CopyIn(e.ctx, a, buf, usermem.IOOpts{})
					} else {
						_, err = e.m.CopyOut(e.ctx, a, buf, usermem.IOOpts{})
					}
					if err != nil {
						b.Errorf("%s: %v", dir, err)
					}
				}
				setup := func() { addr = e.mapContiguous(b, perms) }
				teardown := func() {
					e.unmap(b, addr, benchSize)
					if bk.cold {
						e.dropCache()
					}
				}
				if !bk.cold {
					e.pinCache(b)
				}
				b.SetBytes(benchChunk)
				rounds(b, per, setup, func(n int) { parallel(1, n, cp) }, teardown)
			})
		}
	}
}
