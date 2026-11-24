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

package gofer

import (
	"bytes"
	"fmt"
	"slices"
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
	"gvisor.dev/gvisor/pkg/sentry/ktime"
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

func TestDestroyIdempotent(t *testing.T) {
	ctx := contexttest.Context(t)
	fs := filesystem{
		mf:         pgalloc.MemoryFileFromContext(ctx),
		inoByKey:   make(map[inoKey]uint64),
		inodeByKey: make(map[inoKey]*inode),
		clock:      ktime.RealtimeClockFromContext(ctx),
		// There is no VFS to allocate device numbers from.
		devMinorByHostDev: map[uint64]uint32{0: 1},
		// Test relies on no dentry being held in the cache.
		dentryCache: &dentryCache{maxCachedDentries: 0},
		client:      &lisafs.Client{},
	}

	parentInode := lisafs.Inode{
		ControlFD: 1,
		Stat: lisafs.Statx{
			Mask: linux.STATX_TYPE | linux.STATX_MODE,
			Mode: linux.S_IFDIR | 0666,
		},
	}
	parent, err := fs.newLisafsDentry(ctx, &parentInode)
	if err != nil {
		t.Fatalf("fs.newDentry(): %v", err)
	}

	childInode := lisafs.Inode{
		ControlFD: 2,
		Stat: lisafs.Statx{
			Mask: linux.STATX_TYPE | linux.STATX_MODE | linux.STATX_SIZE,
			Mode: linux.S_IFREG | 0666,
			Size: 0,
		},
	}

	child, err := fs.newLisafsDentry(ctx, &childInode)
	if err != nil {
		t.Fatalf("fs.newDentry(): %v", err)
	}
	parent.opMu.Lock()
	parent.childrenMu.Lock()
	parent.cacheNewChildLocked(child, "child")
	parent.childrenMu.Unlock()
	parent.opMu.Unlock()

	fs.renameMu.Lock()
	defer fs.renameMu.Unlock()
	child.checkCachingLocked(ctx, true /* renameMuWriteLocked */, false /* keepRenameMu */)
	if got := child.refs.Load(); got != -1 {
		t.Fatalf("child.refs=%d, want: -1", got)
	}
	// Parent will also be destroyed when child reference is removed.
	if got := parent.refs.Load(); got != -1 {
		t.Fatalf("parent.refs=%d, want: -1", got)
	}
	child.checkCachingLocked(ctx, true /* renameMuWriteLocked */, false /* keepRenameMu */)
	child.checkCachingLocked(ctx, true /* renameMuWriteLocked */, false /* keepRenameMu */)
}

func TestStringFixedCache(t *testing.T) {
	names := []string{"a", "b", "c"}
	cache := stringFixedCache{}

	cache.init(uint64(len(names)))
	if inited := cache.isInited(); !inited {
		t.Fatalf("cache.isInited(): %v, want: true", inited)
	}
	for _, s := range names {
		victim := cache.add(s)
		if victim != "" {
			t.Fatalf("cache.add(): %v, want: \"\"", victim)
		}
	}
	for _, s := range names {
		victim := cache.add("something")
		if victim != s {
			t.Fatalf("cache.add(): %v, want: %v", victim, s)
		}
	}
}

func TestXattrCacheValues(t *testing.T) {
	ino := &inode{}

	// 1. Initial state
	if _, _, found := ino.xattrCache.get("user.foo"); found {
		t.Errorf("get(user.foo) got found=true, want false")
	}

	// 2. Cache present xattr
	ino.xattrCache.add("user.foo", "bar")
	val, negative, found := ino.xattrCache.get("user.foo")
	if !found || negative || val != "bar" {
		t.Errorf("get(user.foo) = (%q, %v, %v), want (%q, false, true)", val, negative, found, "bar")
	}

	// 3. Cache negative xattr
	ino.xattrCache.addNegative("user.neg")
	val, negative, found = ino.xattrCache.get("user.neg")
	if !found || !negative || val != "" {
		t.Errorf("get(user.neg) = (%q, %v, %v), want (%q, true, true)", val, negative, found, "")
	}

	// Overwrite negative xattr with present xattr
	ino.xattrCache.add("user.neg", "baz")
	val, negative, found = ino.xattrCache.get("user.neg")
	if !found || negative || val != "baz" {
		t.Errorf("get(user.neg) = (%q, %v, %v), want (%q, false, true)", val, negative, found, "baz")
	}

	// 4. Overlay opaque xattr
	ino.xattrCache.addNegative(xattrOverlayOpaque)
	val, negative, found = ino.xattrCache.get(xattrOverlayOpaque)
	if !found || !negative || val != "" {
		t.Errorf("get(xattrOverlayOpaque) = (%q, %v, %v), want (%q, true, true)", val, negative, found, "")
	}

	// Overwrite overlay opaque xattr with present xattr
	ino.xattrCache.add(xattrOverlayOpaque, "y")
	val, negative, found = ino.xattrCache.get(xattrOverlayOpaque)
	if !found || negative || val != "y" {
		t.Errorf("get(xattrOverlayOpaque) = (%q, %v, %v), want (%q, false, true)", val, negative, found, "y")
	}
}

func TestXattrCacheList(t *testing.T) {
	ino := &inode{}

	// 1. Initial state
	if _, found := ino.xattrCache.getList(); found {
		t.Errorf("getList() got found=true, want false")
	}

	// 2. Cache empty list
	ino.xattrCache.setList([]string{})
	list, found := ino.xattrCache.getList()
	if !found || len(list) != 0 {
		t.Errorf("getList() = (%v, %v), want ([], true)", list, found)
	}

	// 3. Cache non-empty list
	initialList := []string{"user.foo", "user.bar"}
	ino.xattrCache.setList(initialList)
	list, found = ino.xattrCache.getList()
	if !found || !slices.Equal(list, initialList) {
		t.Errorf("getList() = (%v, %v), want (%v, true)", list, found, initialList)
	}

	// 4. Cache new xattr updates list
	ino.xattrCache.add("user.baz", "val")
	wantList := []string{"user.foo", "user.bar", "user.baz"}
	list, found = ino.xattrCache.getList()
	if !found || !slices.Equal(list, wantList) {
		t.Errorf("getList() = (%v, %v), want (%v, true)", list, found, wantList)
	}

	// 5. Cache existing xattr does not duplicate in list
	ino.xattrCache.add("user.foo", "val2")
	list, found = ino.xattrCache.getList()
	if !found || !slices.Equal(list, wantList) {
		t.Errorf("getList() = (%v, %v), want (%v, true)", list, found, wantList)
	}

	// 6. Cache negative xattr removes from list
	ino.xattrCache.addNegative("user.bar")
	wantList = []string{"user.foo", "user.baz"}
	list, found = ino.xattrCache.getList()
	if !found || !slices.Equal(list, wantList) {
		t.Errorf("getList() = (%v, %v), want (%v, true)", list, found, wantList)
	}
}

type recycledInoConnImpl struct {
	mu         sync.Mutex
	rootStat   lisafs.Statx
	targetStat lisafs.Statx

	// If readGate is not nil, PRead on "target" blocks on it.
	readGate *readGate
}

// readGate holds every PRead until release is closed. started is closed when
// the first PRead arrives; reads counts PReads.
type readGate struct {
	startOnce sync.Once
	started   chan struct{}
	release   chan struct{}
	reads     atomicbitops.Int32
}

func newReadGate() *readGate {
	return &readGate{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (s *recycledInoConnImpl) getTargetStat() lisafs.Statx {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.targetStat
}

func (s *recycledInoConnImpl) setTargetStat(st lisafs.Statx) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.targetStat = st
}

// +checklocksread:c.server.renameMu
// +checklocksexclude:c.fdsMu
func (s *recycledInoConnImpl) Mount(c *lisafs.Connection, mountNode *lisafs.Node) (*lisafs.ControlFD, lisafs.Statx, int, error) {
	mountNode.IncRef()
	fd := &recycledInoControlFD{connImpl: s, isRoot: true, stat: s.rootStat}
	fd.Init(c, mountNode, linux.ModeDirectory, fd)
	return fd.FD(), s.rootStat, -1, nil
}

func (s *recycledInoConnImpl) MaxMessageSize() uint32 {
	return lisafs.MaxMessageSize()
}

func (s *recycledInoConnImpl) SupportedMessages() []lisafs.MID {
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

type recycledInoControlFD struct {
	lisafs.ControlFD
	lisafs.ControlFDImpl
	connImpl *recycledInoConnImpl
	isRoot   bool
	stat     lisafs.Statx
}

func (fd *recycledInoControlFD) FD() *lisafs.ControlFD { return &fd.ControlFD }
func (fd *recycledInoControlFD) Close()                {}

func (fd *recycledInoControlFD) Stat() (lisafs.Statx, error) {
	if fd.isRoot {
		return fd.connImpl.rootStat, nil
	}
	return fd.stat, nil
}

// +checklocksread:fd.ControlFD.conn.server.renameMu
// +checklocksexclude:fd.ControlFD.conn.fdsMu
func (fd *recycledInoControlFD) Walk(name string) (*lisafs.ControlFD, lisafs.Statx, error) {
	if !fd.isRoot || (name != "target" && name != "target_link") {
		return nil, lisafs.Statx{}, unix.ENOENT
	}
	st := fd.connImpl.getTargetStat()
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
	child := &recycledInoControlFD{connImpl: fd.connImpl, stat: st}
	// Conn returns fd.ControlFD.conn, whose server rename lock is required
	// on entry; checklocks does not retain that identity across the getter.
	child.Init(fd.Conn(), childNode, linux.FileMode(st.Mode), child) // +checklocksignore
	return child.FD(), st, nil
}

func (fd *recycledInoControlFD) WalkStat(path lisafs.StringArray, recordStat func(lisafs.Statx)) error {
	curIsRoot := fd.isRoot
	for i, comp := range path {
		if i == 0 && comp == "" {
			if curIsRoot {
				recordStat(fd.connImpl.rootStat)
			} else {
				recordStat(fd.stat)
			}
			continue
		}
		if curIsRoot && (comp == "target" || comp == "target_link") {
			recordStat(fd.connImpl.getTargetStat())
			curIsRoot = false
			continue
		}
		break
	}
	return nil
}

func (fd *recycledInoControlFD) Open(flags uint32) (*lisafs.OpenFD, int, error) {
	ofd := &recycledInoOpenFD{connImpl: fd.connImpl, stat: fd.stat}
	ofd.Init(fd.FD(), flags, ofd)
	return &ofd.OpenFD, -1, nil
}

// recycledInoFileByte is the content of every byte of "target".
const recycledInoFileByte = 0x5a

type recycledInoOpenFD struct {
	lisafs.OpenFD
	lisafs.OpenFDImpl
	connImpl *recycledInoConnImpl
	stat     lisafs.Statx
}

func (fd *recycledInoOpenFD) Read(buf []byte, off uint64) (uint64, error) {
	if g := fd.connImpl.readGate; g != nil {
		g.reads.Add(1)
		g.startOnce.Do(func() { close(g.started) })
		<-g.release
	}
	if off >= fd.stat.Size {
		return 0, nil
	}
	n := min(uint64(len(buf)), fd.stat.Size-off)
	for i := range buf[:n] {
		buf[i] = recycledInoFileByte
	}
	return n, nil
}

func (fd *recycledInoOpenFD) FD() *lisafs.OpenFD          { return &fd.OpenFD }
func (fd *recycledInoOpenFD) Close()                      {}
func (fd *recycledInoOpenFD) Stat() (lisafs.Statx, error) { return fd.stat, nil }

func mountTestLisafsFS(t *testing.T, targetStat lisafs.Statx) (context.Context, *auth.Credentials, *recycledInoConnImpl, *vfs.VirtualFilesystem, vfs.VirtualDentry) {
	t.Helper()
	return mountTestLisafsFSWithOpts(t, targetStat, "")
}

func mountTestLisafsFSWithOpts(t *testing.T, targetStat lisafs.Statx, extraOpts string) (context.Context, *auth.Credentials, *recycledInoConnImpl, *vfs.VirtualFilesystem, vfs.VirtualDentry) {
	t.Helper()
	return mountTestLisafsFSWithCache(t, cacheRemoteRevalidating, targetStat, nil /* readGate */, extraOpts)
}

// mountTestLisafsFSWithCache mounts a test lisafs filesystem with the given
// cache mode. If readGate is not nil, PRead on "target" blocks on it.
func mountTestLisafsFSWithCache(t *testing.T, cache string, targetStat lisafs.Statx, readGate *readGate, extraOpts string) (context.Context, *auth.Credentials, *recycledInoConnImpl, *vfs.VirtualFilesystem, vfs.VirtualDentry) {
	t.Helper()
	ctx := contexttest.Context(t)
	creds := auth.CredentialsFromContext(ctx)

	serverSock, clientSock, err := unet.SocketPair(false)
	if err != nil {
		t.Fatalf("unet.SocketPair: %v", err)
	}

	srv := lisafs.NewServer()
	t.Cleanup(func() { srv.Destroy() })

	connImpl := &recycledInoConnImpl{
		rootStat: lisafs.Statx{
			Mask:     linux.STATX_TYPE | linux.STATX_MODE | linux.STATX_INO,
			Mode:     linux.S_IFDIR | 0755,
			DevMajor: 0,
			DevMinor: 1,
			Ino:      1,
		},
		targetStat: targetStat,
		readGate:   readGate,
	}
	conn, err := srv.CreateConnection(serverSock, "/", lisafs.ConnectionOpts{WalkStatSupported: true}, connImpl)
	if err != nil {
		clientSock.Close()
		serverSock.Close()
		t.Fatalf("srv.CreateConnection: %v", err)
	}
	srv.StartConnection(conn)
	t.Cleanup(func() { srv.Wait() })

	vfsObj := &vfs.VirtualFilesystem{}
	if err := vfsObj.Init(ctx); err != nil {
		clientSock.Close()
		t.Fatalf("vfsObj.Init: %v", err)
	}
	t.Cleanup(func() { vfsObj.Release(ctx) })
	vfsObj.MustRegisterFilesystemType(Name, FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserMount: true,
	})

	sockFD, err := clientSock.Release()
	if err != nil {
		t.Fatalf("clientSock.Release: %v", err)
	}
	data := fmt.Sprintf("trans=fd,rfdno=%d,wfdno=%d,cache=%s", sockFD, sockFD, cache)
	if extraOpts != "" {
		data += "," + extraOpts
	}
	mntns, err := vfsObj.NewMountNamespace(ctx, creds, "", Name, &vfs.MountOptions{
		GetFilesystemOptions: vfs.GetFilesystemOptions{
			Data: data,
		},
	}, nil)
	if err != nil {
		_ = unix.Close(sockFD)
		t.Fatalf("NewMountNamespace: %v", err)
	}
	t.Cleanup(func() { mntns.DecRef(ctx) })

	root := mntns.Root(ctx)
	t.Cleanup(func() { root.DecRef(ctx) })
	return ctx, creds, connImpl, vfsObj, root
}

// TestOpenAtRecycledInoTypeChange reproduces host inode number recycling across
// file types end-to-end through vfs.VirtualFilesystem.OpenAt with zero open FDs
// held by the application.
func TestOpenAtRecycledInoTypeChange(t *testing.T) {
	ctx, creds, connImpl, vfsObj, root := mountTestLisafsFS(t, lisafs.Statx{
		Mask:     linux.STATX_TYPE | linux.STATX_MODE | linux.STATX_INO,
		Mode:     linux.S_IFSOCK | 0777,
		DevMajor: 0,
		DevMinor: 1,
		Ino:      42,
	})

	pop := vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse("target"),
	}

	// 1. Stat "/target" while it is a Unix domain socket (ino=42). Even
	// with no open FD, dcache retains the dentry and fs.inodeByKey retains
	// the socket inode.
	st, err := vfsObj.StatAt(ctx, creds, &pop, &vfs.StatOptions{Mask: linux.STATX_BASIC_STATS})
	if err != nil {
		t.Fatalf("StatAt(socket): %v", err)
	}
	if got := st.Mode & linux.S_IFMT; got != linux.S_IFSOCK {
		t.Fatalf("StatAt(socket) mode = %#o, want %#o", got, linux.S_IFSOCK)
	}

	// 2. Host unlinks "/target" and creates a regular file at "/target"
	// that reuses host st_ino=42.
	connImpl.setTargetStat(lisafs.Statx{
		Mask:     linux.STATX_TYPE | linux.STATX_MODE | linux.STATX_INO | linux.STATX_SIZE,
		Mode:     linux.S_IFREG | 0644,
		DevMajor: 0,
		DevMinor: 1,
		Ino:      42,
		Size:     64,
	})

	// 3. OpenAt("/target"): doRevalidationLisafs invalidates the old socket
	// dentry (deferring its destruction in ds until OpenAt returns), and
	// stepLocked -> newLisafsDentry immediately walks the new regular file
	// and hits the still-cached socket inode in fs.inodeByKey.
	fd, err := vfsObj.OpenAt(ctx, creds, &pop, &vfs.OpenOptions{Flags: linux.O_RDONLY})
	if err != nil {
		t.Fatalf("OpenAt(regular): %v", err)
	}
	defer fd.DecRef(ctx)

	regStat, err := fd.Stat(ctx, vfs.StatOptions{Mask: linux.STATX_BASIC_STATS})
	if err != nil {
		t.Fatalf("fd.Stat(regular): %v", err)
	}
	if got := regStat.Mode & linux.S_IFMT; got != linux.S_IFREG {
		t.Fatalf("fd.Stat(regular) mode = %#o, want %#o", got, linux.S_IFREG)
	}
	if regStat.Size != 64 {
		t.Fatalf("fd.Stat(regular) size = %d, want 64", regStat.Size)
	}

	// 4. Verify that destroying the superseded socket dentry at the end of
	// OpenAt did not evict the new regular inode from fs.inodeByKey, and
	// that walking a second hard link refreshes the shared inode's size.
	connImpl.setTargetStat(lisafs.Statx{
		Mask:     linux.STATX_TYPE | linux.STATX_MODE | linux.STATX_INO | linux.STATX_SIZE,
		Mode:     linux.S_IFREG | 0644,
		DevMajor: 0,
		DevMinor: 1,
		Ino:      42,
		Size:     256,
	})
	linkPop := vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse("target_link"),
	}
	linkFD, err := vfsObj.OpenAt(ctx, creds, &linkPop, &vfs.OpenOptions{Flags: linux.O_RDONLY})
	if err != nil {
		t.Fatalf("OpenAt(target_link): %v", err)
	}
	defer linkFD.DecRef(ctx)

	regInode := fd.Dentry().Impl().(*dentry).inode
	linkInode := linkFD.Dentry().Impl().(*dentry).inode
	if linkInode != regInode {
		t.Fatalf("hard link did not share replacement *gofer.inode")
	}
	if got := regInode.size.Load(); got != 256 {
		t.Fatalf("regInode.size = %d, want 256", got)
	}
}

type recordingMappingSpace struct {
	inv []hostarch.AddrRange
}

func (ms *recordingMappingSpace) Invalidate(ar hostarch.AddrRange, opts memmap.InvalidateOpts) {
	ms.inv = append(ms.inv, ar)
}

func TestRegularFileDirectWriteZeroLength(t *testing.T) {
	pageSize := uint64(hostarch.PageSize)
	ctx, creds, _, vfsObj, root := mountTestLisafsFS(t, lisafs.Statx{
		Mask:     linux.STATX_TYPE | linux.STATX_MODE | linux.STATX_INO | linux.STATX_SIZE,
		Mode:     linux.S_IFREG | 0666,
		DevMajor: 0,
		DevMinor: 1,
		Ino:      100,
		Size:     2 * pageSize,
	})

	pop := vfs.PathOperation{Root: root, Start: root, Path: fspath.Parse("target")}
	fd, err := vfsObj.OpenAt(ctx, creds, &pop, &vfs.OpenOptions{Flags: linux.O_RDWR | linux.O_DIRECT})
	if err != nil {
		t.Fatalf("OpenAt: %v", err)
	}
	defer fd.DecRef(ctx)
	if _, ok := fd.Impl().(*regularFileFD); !ok {
		t.Fatalf("fd.Impl() = %T, want *regularFileFD", fd.Impl())
	}

	d := fd.Dentry().Impl().(*dentry)
	mf := d.inode.fs.mf
	fr, err := mf.Allocate(2*pageSize, pgalloc.AllocOpts{})
	if err != nil {
		t.Fatalf("mf.Allocate: %v", err)
	}
	wantCacheMR := memmap.MappableRange{Start: 0, End: 2 * pageSize}
	d.inode.dataMu.Lock()
	d.inode.cache.InsertRange(wantCacheMR, fr.Start)
	d.inode.dataMu.Unlock()
	defer func() {
		d.inode.dataMu.Lock()
		d.inode.cache.DropAll(mf)
		d.inode.dataMu.Unlock()
	}()

	ms := &recordingMappingSpace{}
	mapBase := hostarch.Addr(16 * pageSize)
	mapAR := hostarch.AddrRange{Start: mapBase, End: mapBase + hostarch.Addr(2*pageSize)}
	d.inode.mapsMu.Lock()
	d.inode.mappings.AddMapping(ms, mapAR, 0, true)
	d.inode.mapsMu.Unlock()
	defer func() {
		d.inode.mapsMu.Lock()
		d.inode.mappings.RemoveMapping(ms, mapAR, 0, true)
		d.inode.mapsMu.Unlock()
	}()

	for _, offset := range []int64{0, int64(pageSize), int64(pageSize) + 128, int64(2 * pageSize)} {
		n, err := fd.PWrite(ctx, usermem.BytesIOSequence(nil), offset, vfs.WriteOptions{})
		if err != nil || n != 0 {
			t.Fatalf("PWrite(offset=%#x, len=0) = (%d, %v), want (0, nil)", offset, n, err)
		}
		if len(ms.inv) != 0 {
			t.Fatalf("PWrite(offset=%#x, len=0) triggered invalidations: %+v", offset, ms.inv)
		}
		d.inode.dataMu.RLock()
		cseg := d.inode.cache.FirstSegment()
		cacheOK := cseg.Ok() && cseg.Range() == wantCacheMR && cseg.Value() == fr.Start && !cseg.NextSegment().Ok()
		d.inode.dataMu.RUnlock()
		if !cacheOK {
			t.Fatalf("PWrite(offset=%#x, len=0) altered cache", offset)
		}
	}
}

func TestSpecialFileZeroLengthWrite(t *testing.T) {
	t.Run("regular_file", func(t *testing.T) {
		pageSize := uint64(hostarch.PageSize)
		ctx, creds, _, vfsObj, root := mountTestLisafsFSWithOpts(t, lisafs.Statx{
			Mask:     linux.STATX_TYPE | linux.STATX_MODE | linux.STATX_INO | linux.STATX_SIZE,
			Mode:     linux.S_IFREG | 0666,
			DevMajor: 0,
			DevMinor: 1,
			Ino:      101,
			Size:     2 * pageSize,
		}, moptDisableFileHandleSharing)

		pop := vfs.PathOperation{Root: root, Start: root, Path: fspath.Parse("target")}
		fd, err := vfsObj.OpenAt(ctx, creds, &pop, &vfs.OpenOptions{Flags: linux.O_RDWR})
		if err != nil {
			t.Fatalf("OpenAt: %v", err)
		}
		defer fd.DecRef(ctx)
		if _, ok := fd.Impl().(*specialFileFD); !ok {
			t.Fatalf("fd.Impl() = %T, want *specialFileFD", fd.Impl())
		}

		d := fd.Dentry().Impl().(*dentry)
		ms := &recordingMappingSpace{}
		mapBase := hostarch.Addr(16 * pageSize)
		mapAR := hostarch.AddrRange{Start: mapBase, End: mapBase + hostarch.Addr(2*pageSize)}
		d.inode.mapsMu.Lock()
		d.inode.mappings.AddMapping(ms, mapAR, 0, true)
		d.inode.mapsMu.Unlock()
		defer func() {
			d.inode.mapsMu.Lock()
			d.inode.mappings.RemoveMapping(ms, mapAR, 0, true)
			d.inode.mapsMu.Unlock()
		}()

		for _, offset := range []int64{0, int64(pageSize), int64(pageSize) + 128, int64(2 * pageSize)} {
			n, err := fd.PWrite(ctx, usermem.BytesIOSequence(nil), offset, vfs.WriteOptions{})
			if err != nil || n != 0 {
				t.Fatalf("PWrite(offset=%#x, len=0) = (%d, %v), want (0, nil)", offset, n, err)
			}
			if len(ms.inv) != 0 {
				t.Fatalf("PWrite(offset=%#x, len=0) triggered invalidations: %+v", offset, ms.inv)
			}
		}
	})

	t.Run("non_seekable_fifo", func(t *testing.T) {
		ctx, creds, _, vfsObj, root := mountTestLisafsFS(t, lisafs.Statx{
			Mask:     linux.STATX_TYPE | linux.STATX_MODE | linux.STATX_INO,
			Mode:     linux.S_IFIFO | 0666,
			DevMajor: 0,
			DevMinor: 1,
			Ino:      102,
		})

		pop := vfs.PathOperation{Root: root, Start: root, Path: fspath.Parse("target")}
		fd, err := vfsObj.OpenAt(ctx, creds, &pop, &vfs.OpenOptions{Flags: linux.O_WRONLY | linux.O_NONBLOCK})
		if err != nil {
			t.Fatalf("OpenAt(fifo): %v", err)
		}
		defer fd.DecRef(ctx)

		if n, err := fd.Write(ctx, usermem.BytesIOSequence(nil), vfs.WriteOptions{}); err != nil || n != 0 {
			t.Fatalf("Write(len=0) on FIFO = (%d, %v), want (0, nil)", n, err)
		}
	})
}

// TestEmptyWriteKeepsOffsetAndSize verifies that a write of no bytes changes
// neither the file offset nor the file size, as in Linux.
func TestEmptyWriteKeepsOffsetAndSize(t *testing.T) {
	pageSize := uint64(hostarch.PageSize)
	for _, tc := range []struct {
		name      string
		mountOpts string
		ino       uint64
	}{
		{name: "regularFileFD", ino: 103},
		{name: "specialFileFD", mountOpts: moptDisableFileHandleSharing, ino: 104},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, creds, _, vfsObj, root := mountTestLisafsFSWithOpts(t, lisafs.Statx{
				Mask:     linux.STATX_TYPE | linux.STATX_MODE | linux.STATX_INO | linux.STATX_SIZE,
				Mode:     linux.S_IFREG | 0666,
				DevMajor: 0,
				DevMinor: 1,
				Ino:      tc.ino,
				Size:     2 * pageSize,
			}, tc.mountOpts)
			pop := vfs.PathOperation{Root: root, Start: root, Path: fspath.Parse("target")}

			// With O_APPEND, the write must not move the offset to the end of
			// the file.
			appendFD, err := vfsObj.OpenAt(ctx, creds, &pop, &vfs.OpenOptions{Flags: linux.O_RDWR | linux.O_APPEND})
			if err != nil {
				t.Fatalf("OpenAt(O_APPEND): %v", err)
			}
			defer appendFD.DecRef(ctx)
			if _, err := appendFD.Seek(ctx, 1, linux.SEEK_SET); err != nil {
				t.Fatalf("Seek(1, SEEK_SET): %v", err)
			}
			if n, err := appendFD.Write(ctx, usermem.BytesIOSequence(nil), vfs.WriteOptions{}); err != nil || n != 0 {
				t.Fatalf("Write(len=0) = (%d, %v), want (0, nil)", n, err)
			}
			if off, err := appendFD.Seek(ctx, 0, linux.SEEK_CUR); err != nil || off != 1 {
				t.Errorf("after Write(len=0) with O_APPEND, Seek(0, SEEK_CUR) = (%d, %v), want (1, nil)", off, err)
			}

			// Past the end of the file, the write must not change the file
			// size.
			fd, err := vfsObj.OpenAt(ctx, creds, &pop, &vfs.OpenOptions{Flags: linux.O_RDWR})
			if err != nil {
				t.Fatalf("OpenAt: %v", err)
			}
			defer fd.DecRef(ctx)
			if n, err := fd.PWrite(ctx, usermem.BytesIOSequence(nil), int64(3*pageSize), vfs.WriteOptions{}); err != nil || n != 0 {
				t.Fatalf("PWrite(offset=%#x, len=0) = (%d, %v), want (0, nil)", 3*pageSize, n, err)
			}
			d := fd.Dentry().Impl().(*dentry)
			if got, want := d.inode.size.Load(), 2*pageSize; got != want {
				t.Errorf("after PWrite(offset=%#x, len=0), file size = %d, want %d", 3*pageSize, got, want)
			}
		})
	}
}

// mmapFaultEnv is a MemoryManager with a touched anonymous page and a private
// mapping of "target", a gofer file whose server donates no host FD and gates
// PReads.
type mmapFaultEnv struct {
	ctx      context.Context
	creds    *auth.Credentials
	vfsObj   *vfs.VirtualFilesystem
	root     vfs.VirtualDentry
	gate     *readGate
	release  func()
	m        *mm.MemoryManager
	anonAddr hostarch.Addr
	fileAddr hostarch.Addr
}

func newMMapFaultEnv(t *testing.T, pages uint64) *mmapFaultEnv {
	t.Helper()
	e := &mmapFaultEnv{gate: newReadGate()}
	e.ctx, e.creds, _, e.vfsObj, e.root = mountTestLisafsFSWithCache(t, cacheFSCache, lisafs.Statx{
		Mask:     linux.STATX_TYPE | linux.STATX_MODE | linux.STATX_INO | linux.STATX_SIZE,
		Mode:     linux.S_IFREG | 0666,
		DevMajor: 0,
		DevMinor: 1,
		Ino:      42,
		Size:     pages * uint64(hostarch.PageSize),
	}, e.gate, "" /* extraOpts */)
	ctx := e.ctx

	m, err := mm.NewMemoryManager(platform.FromContext(ctx), pgalloc.MemoryFileFromContext(ctx))
	if err != nil {
		t.Fatalf("NewMemoryManager: %v", err)
	}
	t.Cleanup(func() { m.DecUsers(ctx) })
	if _, err := m.SetMmapLayout(arch.New(arch.Host), limits.NewLimitSet()); err != nil {
		t.Fatalf("SetMmapLayout: %v", err)
	}
	e.m = m

	// Map and touch an anonymous page.
	e.anonAddr, err = m.MMap(ctx, memmap.MMapOpts{
		Length:   uint64(hostarch.PageSize),
		Private:  true,
		Perms:    hostarch.ReadWrite,
		MaxPerms: hostarch.AnyAccess,
	})
	if err != nil {
		t.Fatalf("MMap(anonymous): %v", err)
	}
	if _, err := m.CopyOut(ctx, e.anonAddr, []byte{1}, usermem.IOOpts{}); err != nil {
		t.Fatalf("CopyOut(anonymous): %v", err)
	}

	// Map the file, which has no host FD.
	fd, err := e.open(linux.O_RDONLY)
	if err != nil {
		t.Fatalf("OpenAt: %v", err)
	}
	t.Cleanup(func() { fd.DecRef(ctx) })
	if got := fd.Dentry().Impl().(*dentry).inode.mmapFD.Load(); got >= 0 {
		t.Fatalf("mmapFD = %d, want none", got)
	}
	opts := memmap.MMapOpts{
		Length:   pages * uint64(hostarch.PageSize),
		Private:  true,
		Perms:    hostarch.Read,
		MaxPerms: hostarch.AnyAccess,
	}
	if err := fd.ConfigureMMap(ctx, &opts); err != nil {
		t.Fatalf("ConfigureMMap: %v", err)
	}
	e.fileAddr, err = m.MMap(ctx, opts)
	opts.MappingIdentity.DecRef(ctx)
	if err != nil {
		t.Fatalf("MMap(file): %v", err)
	}

	// Release the gate before tearing down, so that no fault is still
	// blocked in PRead.
	var releaseOnce sync.Once
	e.release = func() { releaseOnce.Do(func() { close(e.gate.release) }) }
	t.Cleanup(e.release)
	return e
}

func (e *mmapFaultEnv) open(flags uint32) (*vfs.FileDescription, error) {
	return e.vfsObj.OpenAt(e.ctx, e.creds, &vfs.PathOperation{
		Root:  e.root,
		Start: e.root,
		Path:  fspath.Parse("target"),
	}, &vfs.OpenOptions{Flags: flags})
}

// userFault takes a read fault on addr, then reads the page.
func userFault(ctx context.Context, m *mm.MemoryManager, addr hostarch.Addr) ([]byte, error) {
	if err := m.HandleUserFault(ctx, addr, hostarch.Read, 0); err != nil {
		return nil, err
	}
	buf := make([]byte, hostarch.PageSize)
	_, err := m.CopyIn(ctx, addr, buf, usermem.IOOpts{})
	return buf, err
}

// kernelCopy reads the page at addr without a prior user fault.
func kernelCopy(ctx context.Context, m *mm.MemoryManager, addr hostarch.Addr) ([]byte, error) {
	buf := make([]byte, hostarch.PageSize)
	_, err := m.CopyIn(ctx, addr, buf, usermem.IOOpts{})
	return buf, err
}

type faultResult struct {
	buf []byte
	err error
}

func (e *mmapFaultEnv) goFault(fault func(context.Context, *mm.MemoryManager, hostarch.Addr) ([]byte, error), addr hostarch.Addr) <-chan faultResult {
	done := make(chan faultResult, 1)
	go func() {
		buf, err := fault(e.ctx, e.m, addr)
		done <- faultResult{buf, err}
	}()
	return done
}

func checkFaultResult(t *testing.T, r faultResult) {
	t.Helper()
	if r.err != nil {
		t.Errorf("fault: %v", r.err)
		return
	}
	if want := bytes.Repeat([]byte{recycledInoFileByte}, len(r.buf)); !bytes.Equal(r.buf, want) {
		t.Errorf("file mapping contents = %x..., want %x...", r.buf[:8], want[:8])
	}
}

// checkAnonCopyOut checks that a CopyOut to the anonymous page completes while
// PReads are gated. If it doesn't, the returned function waits for it after
// the gate is released.
func (e *mmapFaultEnv) checkAnonCopyOut(t *testing.T, blocker string) (finish func()) {
	t.Helper()
	copied := make(chan error, 1)
	go func() {
		_, err := e.m.CopyOut(e.ctx, e.anonAddr, []byte{2}, usermem.IOOpts{})
		copied <- err
	}()
	select {
	case err := <-copied:
		if err != nil {
			t.Errorf("CopyOut(anonymous): %v", err)
		}
		return func() {}
	case <-time.After(10 * time.Second):
		t.Errorf("CopyOut(anonymous) blocked behind %s", blocker)
		return func() {
			if err := <-copied; err != nil {
				t.Errorf("CopyOut(anonymous): %v", err)
			}
		}
	}
}

// TestMMapFaultWithoutHostFDReleasesMM checks that while a fault on a mapped
// gofer file waits for a PRead (the server donated no host FD), other threads
// can still access their already-mapped memory.
func TestMMapFaultWithoutHostFDReleasesMM(t *testing.T) {
	for _, tc := range []struct {
		name  string
		fault func(context.Context, *mm.MemoryManager, hostarch.Addr) ([]byte, error)
	}{
		{"user fault", userFault},
		{"kernel copy", kernelCopy},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newMMapFaultEnv(t, 1)
			done := e.goFault(tc.fault, e.fileAddr)
			select {
			case <-e.gate.started:
			case r := <-done:
				t.Fatalf("fault completed without reading the file: %v", r.err)
			}

			// The fault is now blocked in PRead. Accessing the anonymous
			// page must not wait for it.
			finish := e.checkAnonCopyOut(t, "the file fault's PRead")
			e.release()
			checkFaultResult(t, <-done)
			finish()
		})
	}
}

// TestMMapFaultSameFileReleasesMM checks that a fault on a gofer file whose
// page cache another fault is filling waits for that fill without MM locks,
// and then reads none of the pages the other fill cached. In "handle upgrade",
// another thread opening the file for writing waits for the first fill, and
// the second fault must also wait behind it without MM locks.
func TestMMapFaultSameFileReleasesMM(t *testing.T) {
	// blockedDelay is how long a goroutine is given to reach the lock it
	// blocks on.
	const blockedDelay = 100 * time.Millisecond
	for _, tc := range []struct {
		name       string
		openWriter bool
	}{
		{"page cache fill", false},
		{"handle upgrade", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// One vma of two pages, so the first fault's readahead covers
			// the page of the second.
			e := newMMapFaultEnv(t, 2)
			first := e.goFault(userFault, e.fileAddr)
			select {
			case <-e.gate.started:
			case r := <-first:
				t.Fatalf("first fault completed without reading the file: %v", r.err)
			}

			// The first fault is now blocked in PRead, holding the file's
			// locks but not MM's.
			var opened chan error
			if tc.openWriter {
				opened = make(chan error, 1)
				go func() {
					fd, err := e.open(linux.O_RDWR)
					if err == nil {
						fd.DecRef(e.ctx)
					}
					opened <- err
				}()
				time.Sleep(blockedDelay)
				select {
				case err := <-opened:
					t.Fatalf("OpenAt(O_RDWR) completed while the first fault's PRead was blocked: %v", err)
				default:
				}
			}
			second := e.goFault(userFault, e.fileAddr+hostarch.Addr(hostarch.PageSize))
			time.Sleep(blockedDelay)

			finish := e.checkAnonCopyOut(t, "a fault waiting for the same file")
			var secondResult *faultResult
			select {
			case r := <-second:
				secondResult = &r
				t.Errorf("second fault completed while the first fault's PRead was blocked: %v", r.err)
			default:
			}

			e.release()
			checkFaultResult(t, <-first)
			if secondResult == nil {
				r := <-second
				secondResult = &r
			}
			checkFaultResult(t, *secondResult)
			finish()
			if opened != nil {
				if err := <-opened; err != nil {
					t.Errorf("OpenAt(O_RDWR): %v", err)
				}
			}
			if got := e.gate.reads.Load(); got != 1 {
				t.Errorf("PReads = %d, want 1", got)
			}
		})
	}
}
