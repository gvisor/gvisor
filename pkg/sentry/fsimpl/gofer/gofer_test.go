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
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/lisafs"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/overlay"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/tmpfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/ktime"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
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
	write      func([]byte, uint64) (uint64, error)
	targetSync func() error
	mu         sync.Mutex
	rootStat   lisafs.Statx
	targetStat lisafs.Statx
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
		lisafs.MknodAt,
		lisafs.OpenAt,
		lisafs.Close,
		lisafs.Flush,
		lisafs.FSync,
		lisafs.PRead,
		lisafs.PWrite,
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

func (*recycledInoControlFD) Mknod(linux.FileMode, lisafs.UID, lisafs.GID, string, uint32, uint32) (*lisafs.ControlFD, lisafs.Statx, error) {
	return nil, lisafs.Statx{}, unix.EPERM
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
	ofd := &recycledInoOpenFD{stat: fd.stat, write: fd.connImpl.write}
	if !fd.isRoot {
		ofd.onSync = fd.connImpl.targetSync
	}
	ofd.Init(fd.FD(), flags, ofd)
	return &ofd.OpenFD, -1, nil
}

type recycledInoOpenFD struct {
	write  func([]byte, uint64) (uint64, error)
	onSync func() error
	lisafs.OpenFD
	lisafs.OpenFDImpl
	stat lisafs.Statx
}

func (fd *recycledInoOpenFD) FD() *lisafs.OpenFD          { return &fd.OpenFD }
func (fd *recycledInoOpenFD) Close()                      {}
func (fd *recycledInoOpenFD) Stat() (lisafs.Statx, error) { return fd.stat, nil }

func (fd *recycledInoOpenFD) Sync() error {
	if fd.onSync != nil {
		return fd.onSync()
	}
	return nil
}
func (fd *recycledInoOpenFD) Read(buf []byte, off uint64) (uint64, error) {
	clear(buf)
	return uint64(len(buf)), nil
}
func (fd *recycledInoOpenFD) Write(buf []byte, off uint64) (uint64, error) {
	return fd.write(buf, off)
}

func mountTestLisafsFS(t *testing.T, targetStat lisafs.Statx) (context.Context, *auth.Credentials, *recycledInoConnImpl, *vfs.VirtualFilesystem, vfs.VirtualDentry) {
	t.Helper()
	return mountTestLisafsFSWithOpts(t, targetStat, "")
}

func mountTestLisafsFSWithOpts(t *testing.T, targetStat lisafs.Statx, extraOpts string) (context.Context, *auth.Credentials, *recycledInoConnImpl, *vfs.VirtualFilesystem, vfs.VirtualDentry) {
	t.Helper()
	options := "cache=remote_revalidating"
	if extraOpts != "" {
		options += "," + extraOpts
	}
	return mountTestVolumeFS(t, targetStat, options, nil)
}

func mountTestVolumeFS(t *testing.T, targetStat lisafs.Statx, options string, syncFS func() error) (context.Context, *auth.Credentials, *recycledInoConnImpl, *vfs.VirtualFilesystem, vfs.VirtualDentry) {
	t.Helper()
	connImpl := &recycledInoConnImpl{
		rootStat: lisafs.Statx{
			Mask:     linux.STATX_TYPE | linux.STATX_MODE | linux.STATX_INO,
			Mode:     linux.S_IFDIR | 0755,
			DevMajor: 0,
			DevMinor: 1,
			Ino:      1,
		},
		targetStat: targetStat,
	}
	ctx, creds, vfsObj, root := mountTestConnection(t, connImpl, "/", options, lisafs.ConnectionOpts{SyncFSDevice: 1, SyncFS: syncFS})
	return ctx, creds, connImpl, vfsObj, root
}

func mountTestConnection(t *testing.T, impl lisafs.ConnectionImpl, path, options string, opts lisafs.ConnectionOpts) (context.Context, *auth.Credentials, *vfs.VirtualFilesystem, vfs.VirtualDentry) {
	t.Helper()
	ctx := contexttest.Context(t)
	creds := auth.CredentialsFromContext(ctx)

	serverSock, clientSock, err := unet.SocketPair(false)
	if err != nil {
		t.Fatalf("unet.SocketPair: %v", err)
	}

	srv := lisafs.NewServer()
	t.Cleanup(func() { srv.Destroy() })

	opts.WalkStatSupported = true
	conn, err := srv.CreateConnection(serverSock, path, opts, impl)
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
	mntns, err := vfsObj.NewMountNamespace(ctx, creds, "", Name, &vfs.MountOptions{
		GetFilesystemOptions: vfs.GetFilesystemOptions{
			Data: fmt.Sprintf("trans=fd,rfdno=%d,wfdno=%d,%s", sockFD, sockFD, options),
		},
	}, nil)
	if err != nil {
		_ = unix.Close(sockFD)
		t.Fatalf("NewMountNamespace: %v", err)
	}
	t.Cleanup(func() { mntns.DecRef(ctx) })

	root := mntns.Root(ctx)
	t.Cleanup(func() { root.DecRef(ctx) })
	return ctx, creds, vfsObj, root
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

func TestFilesystemSyncUsesExportBarrier(t *testing.T) {
	for _, tc := range []struct {
		name   string
		result error
	}{
		{"success", nil},
		{"storage error", unix.EIO},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := make(chan struct{}, 1)
			ctx, _, _, _, root := mountTestVolumeFS(t, lisafs.Statx{}, "cache=remote_revalidating", func() error {
				called <- struct{}{}
				return tc.result
			})
			if err := root.Mount().Filesystem().Impl().Sync(ctx, vfs.FilesystemSyncOptions{}); err != tc.result {
				t.Fatalf("Sync returned %v, want %v", err, tc.result)
			}
			select {
			case <-called:
			default:
				t.Fatal("Sync returned without calling the export barrier")
			}
		})
	}
}

func TestSyncBeforeMountRootIsReady(t *testing.T) {
	ctx, _, _, _, root := mountTestVolumeFS(t, lisafs.Statx{}, "cache=remote_revalidating", func() error {
		t.Error("synced the volume before its root was ready")
		return nil
	})
	fs := root.Mount().Filesystem().Impl().(*filesystem)
	// VFS can call Sync after the mount RPC returns but before GetFilesystem publishes the root.
	mounting := &filesystem{opts: fs.opts, client: fs.client}
	if err := mounting.Sync(ctx, vfs.FilesystemSyncOptions{}); err != nil {
		t.Fatalf("Sync during mount: %v", err)
	}
}

func TestSyncFSReportsExportErrorPerOpenDescription(t *testing.T) {
	fail := make(chan error, 1)
	impl := &recycledInoConnImpl{
		rootStat:   lisafs.Statx{Mask: linux.STATX_BASIC_STATS, Mode: linux.S_IFDIR | 0777, Ino: 1, DevMinor: 1},
		targetStat: lisafs.Statx{Mask: linux.STATX_BASIC_STATS, Mode: linux.S_IFDIR | 0777, Ino: 2, DevMinor: 2},
	}
	ctx, creds, vfsObj, root := mountTestConnection(t, impl, "/", "cache=remote_revalidating", lisafs.ConnectionOpts{SyncFSDevice: 1, SyncFS: func() error {
		select {
		case err := <-fail:
			return err
		default:
			return nil
		}
	}})
	open := func() *vfs.FileDescription {
		t.Helper()
		fd, err := vfsObj.OpenAt(ctx, creds, &vfs.PathOperation{Root: root, Start: root, Path: fspath.Parse(".")}, &vfs.OpenOptions{Flags: linux.O_RDONLY})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { fd.DecRef(ctx) })
		return fd
	}
	check := func(fd *vfs.FileDescription, want error) {
		t.Helper()
		if got := fd.SyncFS(ctx); got != want {
			t.Fatalf("SyncFS = %v, want %v", got, want)
		}
	}
	first, second := open(), open()
	fifoPath := &vfs.PathOperation{Root: root, Start: root, Path: fspath.Parse("fifo")}
	if err := vfsObj.MknodAt(ctx, creds, fifoPath, &vfs.MknodOptions{Mode: linux.S_IFIFO | 0600}); err != nil {
		t.Fatal(err)
	}
	fifo, err := vfsObj.OpenAt(ctx, creds, fifoPath, &vfs.OpenOptions{Flags: linux.O_RDWR})
	if err != nil {
		t.Fatal(err)
	}
	defer fifo.DecRef(ctx)
	crossDevice := &vfs.PathOperation{Root: root, Start: root, Path: fspath.Parse("target/fifo")}
	if err := vfsObj.RenameAt(ctx, creds, fifoPath, crossDevice, &vfs.RenameOptions{}); !linuxerr.Equals(linuxerr.EXDEV, err) {
		t.Fatalf("renaming open FIFO across backing devices: got %v, want EXDEV", err)
	}
	fail <- unix.EIO
	check(first, unix.EIO)
	check(fifo, unix.EIO)
	check(fifo, nil)
	late := open()
	check(late, nil)
	check(second, unix.EIO)
	check(first, nil)
	check(second, nil)

	fail <- unix.ENOSPC
	if err := root.Mount().Filesystem().Impl().Sync(ctx, vfs.FilesystemSyncOptions{}); err != unix.ENOSPC {
		t.Fatalf("filesystem Sync = %v, want ENOSPC", err)
	}
	afterSync := open()
	check(afterSync, unix.ENOSPC)
	check(open(), nil)
	fail <- unix.EAGAIN
	check(first, unix.EAGAIN)
	check(first, unix.ENOSPC)
	check(second, unix.ENOSPC)
	check(late, unix.ENOSPC)
	check(late, nil)

	fail <- unix.EREMOTEIO
	check(first, unix.EREMOTEIO)
	check(second, unix.EREMOTEIO)
	check(first, nil)
	check(second, nil)

	fs := root.Mount().Filesystem().Impl().(*filesystem)
	// The same errno from a rejected request and from the disk have distinct origins.
	if wb, err := fs.client.SyncFilesystem(ctx, 2); wb != 0 || err != unix.EOPNOTSUPP {
		t.Fatalf("ungranted barrier = (%v, %v), want (0, EOPNOTSUPP)", wb, err)
	}
	check(first, nil)
	fail <- unix.EOPNOTSUPP
	check(first, unix.EOPNOTSUPP)
	check(second, unix.EOPNOTSUPP)
	check(first, nil)
	fail <- unix.EIO
	fs.exportSyncMu.Lock()
	got := fs.syncVolume(ctx, unix.EAGAIN, nil)
	fs.exportSyncMu.Unlock()
	if got != unix.EIO {
		t.Fatalf("simultaneous active file EAGAIN and host EIO: got %v, want EIO", got)
	}
	check(first, unix.EIO)
	check(second, unix.EIO)
	check(first, nil)
}

func TestSyncAfterEvictedWritebackError(t *testing.T) {
	pageSize := uint64(hostarch.PageSize)
	for _, tc := range []struct {
		name            string
		barrier         func() error
		pageEviction    bool
		failBarrierOnce bool
	}{
		{name: "inode/per-handle"},
		{name: "inode/export", barrier: func() error { return nil }},
		{name: "inode/export-retry", failBarrierOnce: true},
		{name: "pages/per-handle", pageEviction: true},
		{name: "pages/export", barrier: func() error { return nil }, pageEviction: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wrote := make(chan struct{}, 1)
			impl := &recycledInoConnImpl{
				rootStat:   lisafs.Statx{Mask: linux.STATX_BASIC_STATS, Mode: linux.S_IFDIR | 0755, Ino: 1},
				targetStat: lisafs.Statx{Mask: linux.STATX_BASIC_STATS, Mode: linux.S_IFREG | 0666, Ino: 2, Size: pageSize},
				write: func(buf []byte, off uint64) (uint64, error) {
					wrote <- struct{}{}
					return 0, unix.ENOSPC
				},
			}
			barrier := tc.barrier
			if tc.failBarrierOnce {
				var once sync.Once
				barrier = func() (err error) {
					once.Do(func() { err = unix.EIO })
					return
				}
			}
			ctx, creds, vfsObj, root := mountTestConnection(t, impl, "/", "cache=fscache,force_page_cache,dcache=0", lisafs.ConnectionOpts{SyncFS: barrier})
			pop := &vfs.PathOperation{Root: root, Start: root, Path: fspath.Parse("target")}
			fd, err := vfsObj.OpenAt(ctx, creds, pop, &vfs.OpenOptions{Flags: linux.O_RDWR})
			if err != nil {
				t.Fatal(err)
			}
			func() {
				defer fd.DecRef(ctx)
				d := fd.Dentry().Impl().(*dentry)
				page := memmap.MappableRange{End: pageSize}
				if _, err := d.Translate(ctx, page, page, hostarch.Read); err != nil {
					t.Fatal(err)
				}
				n, err := fd.PWrite(ctx, usermem.BytesIOSequence([]byte{1}), 0, vfs.WriteOptions{})
				if err != nil || n != 1 {
					t.Fatalf("buffered write = %d, %v", n, err)
				}
				select {
				case <-wrote:
					t.Fatal("backend received the write before eviction")
				default:
				}
				if tc.pageEviction {
					d.inode.Evict(ctx, pgalloc.EvictableRange{End: pageSize})
				}
			}()
			select {
			case <-wrote:
			default:
				t.Fatal("eviction did not attempt writeback")
			}
			fs := root.Mount().Filesystem().Impl()
			if barrier == nil {
				if err := vfsObj.SyncAllFilesystems(ctx); err != nil {
					t.Fatalf("global sync after eviction: %v", err)
				}
			}
			if tc.failBarrierOnce {
				if err := fs.Sync(ctx, vfs.FilesystemSyncOptions{}); err != unix.EIO {
					t.Fatalf("Sync after storage barrier failure = %v, want EIO", err)
				}
			}
			if err := fs.Sync(ctx, vfs.FilesystemSyncOptions{}); err != unix.ENOSPC {
				t.Fatalf("Sync after final writeback failure = %v, want ENOSPC", err)
			}
			if err := fs.Sync(ctx, vfs.FilesystemSyncOptions{}); err != nil {
				t.Fatalf("Sync after errors were reported = %v", err)
			}
		})
	}
}

func TestGlobalSyncRetainsUngrantedUpperError(t *testing.T) {
	failures := make(chan error, 2)
	impl := &recycledInoConnImpl{
		rootStat:   lisafs.Statx{Mask: linux.STATX_BASIC_STATS, Mode: linux.S_IFDIR | 0755, Ino: 1},
		targetStat: lisafs.Statx{Mask: linux.STATX_BASIC_STATS, Mode: linux.S_IFREG | 0666, Ino: 2},
		targetSync: func() error {
			select {
			case err := <-failures:
				return err
			default:
				return nil
			}
		},
	}
	ctx, creds, vfsObj, root := mountTestConnection(t, impl, "/", "cache=remote_revalidating,"+moptDisableFileHandleSharing, lisafs.ConnectionOpts{})
	pop := &vfs.PathOperation{Root: root, Start: root, Path: fspath.Parse("target")}
	open := func() *vfs.FileDescription {
		t.Helper()
		fd, err := vfsObj.OpenAt(ctx, creds, pop, &vfs.OpenOptions{Flags: linux.O_RDWR})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { fd.DecRef(ctx) })
		return fd
	}
	fd := open()
	open()

	vfsObj.MustRegisterFilesystemType(tmpfs.Name, tmpfs.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true})
	lower, err := vfsObj.MountDisconnected(ctx, creds, "", tmpfs.Name, &vfs.MountOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer lower.DecRef(ctx)
	ofs, od, err := (overlay.FilesystemType{}).GetFilesystem(ctx, vfsObj, creds, "", vfs.GetFilesystemOptions{
		InternalData: overlay.FilesystemOptions{UpperRoot: root, LowerRoots: []vfs.VirtualDentry{vfs.MakeVirtualDentry(lower, lower.Root())}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ofs.DecRef(ctx)
	defer od.DecRef(ctx)

	failures <- unix.EAGAIN
	failures <- unix.EIO
	if err := vfsObj.SyncAllFilesystems(ctx); err != unix.EIO {
		t.Fatalf("global flush = %v, want backend EIO", err)
	}
	if err := fd.SyncFS(ctx); err != unix.EIO {
		t.Fatalf("syncfs after global flush = %v, want EIO", err)
	}
	if err := fd.SyncFS(ctx); err != nil {
		t.Fatalf("repeated syncfs = %v", err)
	}
}

func TestSyncFSTargetsCallingDevice(t *testing.T) {
	for _, virtual := range []bool{false, true} {
		t.Run(fmt.Sprintf("virtualInodes=%t", virtual), func(t *testing.T) {
			var parentCalls, fileSyncs atomic.Int32
			var failFileSync atomic.Bool
			opts := lisafs.ConnectionOpts{SyncFSDevice: 1, SyncFS: func() error { parentCalls.Add(1); return nil }}
			mountOpts := "cache=remote_revalidating,dcache=0"
			if virtual {
				mountOpts += ",virtual_inode_numbers"
			}
			impl := &recycledInoConnImpl{
				rootStat:   lisafs.Statx{Mask: linux.STATX_BASIC_STATS, Mode: linux.S_IFDIR | 0755, Ino: 1, DevMinor: 1},
				targetStat: lisafs.Statx{Mask: linux.STATX_BASIC_STATS, Mode: linux.S_IFREG | 0666, Ino: 7, DevMinor: 2},
				targetSync: func() error {
					fileSyncs.Add(1)
					if failFileSync.Load() {
						return unix.EIO
					}
					return nil
				},
			}
			ctx, creds, vfsObj, root := mountTestConnection(t, impl, "/", mountOpts, opts)
			open := func(path string, flags uint32) *vfs.FileDescription {
				fd, err := vfsObj.OpenAt(ctx, creds, &vfs.PathOperation{Root: root, Start: root, Path: fspath.Parse(path)}, &vfs.OpenOptions{Flags: flags})
				if err != nil {
					t.Fatal(err)
				}
				return fd
			}
			parent := open(".", linux.O_RDONLY)
			defer parent.DecRef(ctx)
			fs := root.Mount().Filesystem().Impl().(*filesystem)
			func() {
				child := open("target", linux.O_RDWR)
				defer child.DecRef(ctx)
				failFileSync.Store(true)
				if err := child.SyncFS(ctx); err != unix.EOPNOTSUPP || parentCalls.Load() != 0 || fileSyncs.Load() != 0 {
					t.Fatalf("child sync = %v, parent calls = %d", err, parentCalls.Load())
				}
				failFileSync.Store(false)
				if err := parent.SyncFS(ctx); err != nil || parentCalls.Load() != 1 {
					t.Fatalf("parent sync = %v, parent calls = %d", err, parentCalls.Load())
				}
				if err := vfsObj.SyncAllFilesystems(ctx); err != nil || fileSyncs.Load() != 1 {
					t.Fatalf("aggregate sync = %v, child file syncs = %d", err, fileSyncs.Load())
				}
			}()
			open("target", linux.O_RDONLY).DecRef(ctx)
			if err := vfsObj.SyncAllFilesystems(ctx); err != nil || parentCalls.Load() != 3 || fileSyncs.Load() != 1 {
				t.Fatalf("after eviction: sync = %v, parent/file calls = %d/%d", err, parentCalls.Load(), fileSyncs.Load())
			}
			if err := fs.Sync(ctx, vfs.FilesystemSyncOptions{}); err != unix.EOPNOTSUPP {
				t.Fatalf("whole-export sync after nested eviction = %v, want EOPNOTSUPP", err)
			}
			fs.iopts.UniqueID.Path = "/test"
			if err := fs.PrepareSave(ctx, vfs.PrepareSaveOptions{}); err != unix.EOPNOTSUPP {
				t.Fatalf("PrepareSave after nested device eviction = %v, want EOPNOTSUPP", err)
			}
		})
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

func TestValidateRestoredFileType(t *testing.T) {
	for _, test := range []struct {
		name         string
		savedMode    uint32
		savedRdev    [2]uint32 // major, minor
		restoredMode uint32
		restoredRdev [2]uint32 // major, minor
		wantErr      bool
	}{
		{
			name:         "RegularFile",
			savedMode:    linux.S_IFREG | 0644,
			restoredMode: linux.S_IFREG | 0600,
		},
		{
			name:         "Directory",
			savedMode:    linux.S_IFDIR | 0755,
			restoredMode: linux.S_IFDIR | 0755,
		},
		{
			name:         "CharDevice",
			savedMode:    linux.S_IFCHR | 0666,
			savedRdev:    [2]uint32{1, 3},
			restoredMode: linux.S_IFCHR | 0666,
			restoredRdev: [2]uint32{1, 3},
		},
		{
			name:         "RegularFileReplacedByDirectory",
			savedMode:    linux.S_IFREG | 0644,
			restoredMode: linux.S_IFDIR | 0755,
			wantErr:      true,
		},
		{
			name:         "DirectoryReplacedBySymlink",
			savedMode:    linux.S_IFDIR | 0755,
			restoredMode: linux.S_IFLNK | 0777,
			wantErr:      true,
		},
		{
			name:         "FIFOReplacedByCharDevice",
			savedMode:    linux.S_IFIFO | 0644,
			restoredMode: linux.S_IFCHR | 0666,
			restoredRdev: [2]uint32{1, 3},
			wantErr:      true,
		},
		{
			name:         "RegularFileReplacedByBlockDevice",
			savedMode:    linux.S_IFREG | 0644,
			restoredMode: linux.S_IFBLK | 0660,
			restoredRdev: [2]uint32{8, 0},
			wantErr:      true,
		},
		{
			name:         "BlockDevice",
			savedMode:    linux.S_IFBLK | 0660,
			savedRdev:    [2]uint32{8, 0},
			restoredMode: linux.S_IFBLK | 0660,
			restoredRdev: [2]uint32{8, 0},
			wantErr:      true,
		},
		{
			name:         "CharDeviceMajorChanged",
			savedMode:    linux.S_IFCHR | 0666,
			savedRdev:    [2]uint32{1, 3},
			restoredMode: linux.S_IFCHR | 0666,
			restoredRdev: [2]uint32{4, 3},
			wantErr:      true,
		},
		{
			name:         "CharDeviceMinorChanged",
			savedMode:    linux.S_IFCHR | 0666,
			savedRdev:    [2]uint32{1, 3},
			restoredMode: linux.S_IFCHR | 0666,
			restoredRdev: [2]uint32{1, 5},
			wantErr:      true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			i := &inode{
				fs:        &filesystem{},
				mode:      atomicbitops.FromUint32(test.savedMode),
				rdevMajor: test.savedRdev[0],
				rdevMinor: test.savedRdev[1],
			}
			d := &dentry{inode: i}
			err := i.validateRestoredFileType(test.restoredMode, test.restoredRdev[0], test.restoredRdev[1], d)
			if !test.wantErr {
				if err != nil {
					t.Errorf("validateRestoredFileType(%#o, %d, %d) = %v, want nil", test.restoredMode, test.restoredRdev[0], test.restoredRdev[1], err)
				}
				return
			}
			var corruption vfs.ErrCorruption
			if !errors.As(err, &corruption) {
				t.Errorf("validateRestoredFileType(%#o, %d, %d) = %v, want vfs.ErrCorruption", test.restoredMode, test.restoredRdev[0], test.restoredRdev[1], err)
			}
		})
	}
}

func TestCompleteRestoreDirectFSNoProcSelfFD(t *testing.T) {
	prev := procSelfFD
	defer func() { procSelfFD = prev }()
	procSelfFD = -1

	ctx := contexttest.Context(t)
	var fs filesystem
	fs.opts.directfs.enabled = true
	err := fs.CompleteRestore(ctx, vfs.CompleteRestoreOptions{})
	if err == nil || !strings.Contains(err.Error(), "SetProcSelfFD") {
		t.Fatalf("CompleteRestore() = %v, want SetProcSelfFD error", err)
	}
}
