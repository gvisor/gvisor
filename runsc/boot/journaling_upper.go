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

package boot

import (
	"errors"
	"fmt"
	"os"
	"slices"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/checkpoint"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/overlay"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/tmpfs"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/tmpfs/journal"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/runsc/boot/sentryapi"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/specutils"
	"gvisor.dev/gvisor/runsc/version"
)

func journalingUpperOpts(conf *config.Config, imageID string) journal.Options {
	return journal.Options{
		BuildID:    version.Version(),
		ImageID:    imageID,
		RegionSize: conf.TestOnlyJournalingRootfsUpperRegionSize,
	}
}

// configureOverlayFilestore initializes tmpfsOpts.MemoryFile (and any journal
// options) from filestore. It takes ownership of filestore and, for a
// journaled or imported rootfs upper, consumes c.rootfsJournalFD. It returns an
// optional post-mount callback (for journal activation or unjournaled-import
// invalidation) and an optional cleanup callback that the caller must invoke if
// mounting fails before the post-mount callback runs.
func (c *containerMounter) configureOverlayFilestore(conf *config.Config, dst string, filestore *os.File, hasTar bool, tmpfsOpts *tmpfs.FilesystemOpts) (onMount func(context.Context, *vfs.Filesystem) error, cleanupOnErr func(), err error) {
	resourceID := checkpoint.ResourceID{ContainerName: c.containerName, Path: dst}
	cu := cleanup.Make(func() { _ = filestore.Close() })
	defer cu.Clean()

	var (
		jcfg        specutils.JournalingRootfsUpperConfig
		journalFile *os.File
	)
	if dst == "/" {
		jcfg, err = specutils.JournalingRootfsUpper(c.spec, conf)
		if err != nil {
			return nil, nil, err
		}
		if jcfg.Enabled || jcfg.ImportPath != "" {
			if c.rootfsJournalFD == nil || c.rootfsJournalFD.FD() < 0 {
				return nil, nil, fmt.Errorf("no journal file for the journaling rootfs upper")
			}
			journalFile = c.rootfsJournalFD.ReleaseToFile("overlay-journal")
			cu.Add(func() { _ = journalFile.Close() })
		}
	}

	populate := c.l.fsRestore != nil || hasTar
	if jcfg.ImportPath != "" {
		if populate {
			return nil, nil, fmt.Errorf("journaling rootfs upper import cannot be used with filesystem restore or rootfs upper tar")
		}
		cu.Release()
		mf, j, st, err := openImportedJournalingUpper(filestore, journalFile, conf, jcfg, resourceID)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to import journaling rootfs upper: %w", err)
		}
		tmpfsOpts.MemoryFile = mf
		tmpfsOpts.Journal = j
		tmpfsOpts.JournalState = st
		if !jcfg.Enabled {
			// Defer journal invalidation until the overlay mount succeeds so a
			// failed mount leaves the imported journal and filestore intact;
			// once mounted, invalidate the journal so in-place mutations and
			// exit teardown cannot leave a stale valid journal on disk.
			return func(context.Context, *vfs.Filesystem) error {
				defer journalFile.Close()
				if err := journal.Invalidate(journalFile); err != nil {
					return fmt.Errorf("failed to invalidate imported journal: %w", err)
				}
				return nil
			}, func() { _ = journalFile.Close() }, nil
		}
		return nil, nil, nil
	}
	if jcfg.Enabled && !populate {
		cu.Release()
		mf, j, err := createJournalingUpper(filestore, journalFile, conf, jcfg, resourceID)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create journaling rootfs upper: %w", err)
		}
		tmpfsOpts.MemoryFile = mf
		tmpfsOpts.Journal = j
		return nil, nil, nil
	}

	// createPrivateMemoryFile takes ownership of filestore.
	cu.Release()
	mfCu := cleanup.Make(func() {
		if journalFile != nil {
			_ = journalFile.Close()
		}
	})
	defer mfCu.Clean()
	mf, loaded, err := createPrivateMemoryFile(filestore, resourceID, c.containerID, c.l.fsRestore, jcfg.Enabled)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create memory file for overlay: %v", err)
	}
	mfCu.Add(func() { mf.Destroy() })
	sourceTar, err := c.l.fsRestore.tmpfsSourceTar(resourceID, c.containerID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get tar archive from filesystem checkpoint: %w", err)
	}
	mfCu.Release()
	tmpfsOpts.MemoryFile = mf
	if sourceTar != nil {
		log.Infof("Loading filesystem checkpoint tree for %q", resourceID)
		tmpfsOpts.SourceTar = sourceTar
		tmpfsOpts.SourceTarFSCheckpoint = true
	}
	if !jcfg.Enabled {
		return nil, nil, nil
	}
	l, cid, imageID := c.l, c.containerID, jcfg.ImageID
	closeJournal := func() { _ = journalFile.Close() }
	if loaded {
		fsr := l.fsRestore
		return func(ctx context.Context, upper *vfs.Filesystem) error {
			c.pendingJournalActivations = append(c.pendingJournalActivations, l.newJournalingUpperActivation(ctx, conf, cid, upper, imageID, journalFile, func() error { return fsr.wait(cid) }))
			return nil
		}, closeJournal, nil
	}
	return func(ctx context.Context, upper *vfs.Filesystem) error {
		if err := l.activateJournalingUpper(ctx, conf, cid, upper, imageID, journalFile, false /* pause */); err != nil {
			return fmt.Errorf("failed to activate the journaling rootfs upper journal: %w", err)
		}
		return nil
	}, closeJournal, nil
}

// createJournalingUpper initializes a fresh MemoryFile on filestore and a
// fresh journal in journalFile. It takes ownership of filestore and
// journalFile.
func createJournalingUpper(filestore, journalFile *os.File, conf *config.Config, jcfg specutils.JournalingRootfsUpperConfig, resourceID checkpoint.ResourceID) (*pgalloc.MemoryFile, *journal.Journal, error) {
	cu := cleanup.Make(func() { _ = journalFile.Close() })
	defer cu.Clean()
	mf, err := pgalloc.NewMemoryFile(filestore, journalingMemoryFileOpts(resourceID, false /* keepContents */))
	if err != nil {
		_ = filestore.Close()
		return nil, nil, err
	}
	cu.Add(func() { mf.Destroy() })
	j, err := journal.Create(journalFile, journalingUpperOpts(conf, jcfg.ImageID))
	if err != nil {
		return nil, nil, err
	}
	cu.Release()
	log.Infof("Created journaling rootfs upper for %v", resourceID)
	return mf, j, nil
}

// openImportedJournalingUpper replays the imported journal in journalFile and
// adopts the filestore pages that it references into a new MemoryFile. If
// jcfg.Enabled is true, it also returns an open Journal that takes ownership
// of journalFile. If jcfg.Enabled is false, the caller keeps ownership of
// journalFile on success. It always takes ownership of filestore, and closes
// journalFile on error.
func openImportedJournalingUpper(filestore, journalFile *os.File, conf *config.Config, jcfg specutils.JournalingRootfsUpperConfig, resourceID checkpoint.ResourceID) (*pgalloc.MemoryFile, *journal.Journal, *journal.State, error) {
	cu := cleanup.Make(func() { _ = journalFile.Close() })
	defer cu.Clean()
	mf, err := pgalloc.NewMemoryFile(filestore, journalingMemoryFileOpts(resourceID, true /* keepContents */))
	if err != nil {
		_ = filestore.Close()
		return nil, nil, nil, err
	}
	cu.Add(func() { mf.Destroy() })
	j, st, err := journal.Open(mf, journalFile, journalingUpperOpts(conf, jcfg.ImageID), jcfg.Enabled)
	if err != nil {
		if errors.Is(err, journal.ErrIncomplete) {
			return nil, nil, nil, fmt.Errorf("imported rootfs upper journal at %q is incomplete: %w", jcfg.ImportPath, err)
		}
		return nil, nil, nil, err
	}
	cu.Release()
	log.Infof("Imported journaling rootfs upper %q (keepJournal=%t) with %d inodes and %d filestore ranges", jcfg.ImportPath, jcfg.Enabled, len(st.Inodes), len(st.UsedRanges()))
	return mf, j, st, nil
}

// journalingMemoryFileOpts returns the options of a MemoryFile that backs a
// journaled or imported rootfs upper, with DecommitOnDestroy false so pages
// survive sandbox exit.
func journalingMemoryFileOpts(resourceID checkpoint.ResourceID, keepContents bool) pgalloc.MemoryFileOpts {
	return pgalloc.MemoryFileOpts{
		DiskBackedFile:          true,
		KeepFileContents:        keepContents,
		DisableMemoryAccounting: true,
		DisableIMAWorkAround:    true,
		ResourceID:              resourceID,
	}
}

// activateJournalingUpper creates a journal in journalFile and starts
// journaling on upper after a restore, filesystem restore, or tar archive
// populated it. It takes ownership of journalFile.
func (l *Loader) activateJournalingUpper(ctx context.Context, conf *config.Config, cid string, upper *vfs.Filesystem, imageID string, journalFile *os.File, pause bool) error {
	mf := tmpfs.MemoryFileOf(upper)
	if mf == nil {
		journalFile.Close()
		return fmt.Errorf("journaling rootfs upper is not a tmpfs filesystem")
	}
	if err := mf.AwaitLoadAll(); err != nil {
		journalFile.Close()
		return fmt.Errorf("failed to load journaling rootfs upper pages: %w", err)
	}
	if l.isJournalingUpperDestroyed() {
		journalFile.Close()
		return nil
	}
	if pause {
		// Serialize with Loader.saveWithOpts so journal activation and
		// journalCompactor startup cannot race with PrepareSave / SaveTo.
		l.saveMu.Lock()
		defer l.saveMu.Unlock()
		l.k.Pause()
		defer l.k.Unpause()
	}
	j, err := journal.CreateIncomplete(journalFile, journalingUpperOpts(conf, imageID))
	if err != nil {
		journalFile.Close()
		return err
	}
	if conf.TestOnlyJournalingRootfsUpperFault == "activation" {
		j.Close()
		return fmt.Errorf("activation failure injected by --TESTONLY-journaling-rootfs-upper-fault")
	}
	if err := tmpfs.ActivateJournal(upper, j); err != nil {
		return err
	}
	log.Infof("Activated journaling rootfs upper journal for container %q", cid)
	return nil
}

// syncSelfFilestoreWhiteout hides this sandbox's self-backed filestore (and,
// if journaled is true, its journal file) in upperFS without altering
// upperFS's root directory timestamps, and removes any imported self-filestore
// whiteouts from earlier sandboxes that do not exist on lowerRootVD.
func syncSelfFilestoreWhiteout(ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, upperFS *vfs.Filesystem, lowerRootVD vfs.VirtualDentry, sandboxID string, journaled bool) error {
	selfNames := []string{sentryapi.SelfFilestoreName(sandboxID)}
	if journaled {
		selfNames = append(selfNames, sentryapi.SelfJournalName(sandboxID))
	}
	var remove []string
	if lowerRootVD.Ok() {
		for _, name := range tmpfs.SelfFilestoreWhiteouts(upperFS) {
			if slices.Contains(selfNames, name) {
				continue
			}
			d, err := vfsObj.GetDentryAt(ctx, creds, &vfs.PathOperation{
				Root:  lowerRootVD,
				Start: lowerRootVD,
				Path:  fspath.Parse(name),
			}, &vfs.GetDentryOptions{})
			if err == nil {
				d.DecRef(ctx)
				continue
			}
			if linuxerr.Equals(linuxerr.ENOENT, err) {
				remove = append(remove, name)
			}
		}
	}
	return tmpfs.SyncSelfFilestoreWhiteouts(ctx, upperFS, selfNames, remove)
}

type restoredJournalingUpper struct {
	conf    *config.Config
	cid     string
	upper   *vfs.Filesystem
	imageID string

	// journalFile is the journal file of upper, or nil after activation
	// took ownership of it.
	journalFile *os.File
}

type restoredJournalingUppers struct {
	l       *Loader
	targets []restoredJournalingUpper
	once    sync.Once
}

func (r *restoredJournalingUppers) release(ctx context.Context) {
	if r == nil {
		return
	}
	r.once.Do(func() {
		for _, t := range r.targets {
			if t.journalFile != nil {
				t.journalFile.Close()
			}
			t.upper.DecRef(ctx)
			r.l.journalingUpperWG.Done()
		}
	})
}

func (r *restoredJournalingUppers) activate(ctx context.Context) error {
	if r == nil {
		return nil
	}
	defer r.release(ctx)
	for i := range r.targets {
		t := &r.targets[i]
		journalFile := t.journalFile
		t.journalFile = nil
		if err := r.l.activateJournalingUpper(ctx, t.conf, t.cid, t.upper, t.imageID, journalFile, true /* pause */); err != nil {
			return fmt.Errorf("container %q: %w", t.cid, err)
		}
	}
	return nil
}

// prepareJournalingUppersForRestore validates journaling settings and hides
// self-backed filestores before restored tasks start running, returning a
// handle whose activate method completes journal creation once background page
// loading finishes.
func (l *Loader) prepareJournalingUppersForRestore(ctx context.Context, containers []*containerInfo) (*restoredJournalingUppers, error) {
	res := &restoredJournalingUppers{l: l}
	cu := cleanup.Make(func() { res.release(ctx) })
	defer cu.Clean()
	for _, cont := range containers {
		if l.noRootContainer.enabled && cont.cid == l.root.cid {
			continue
		}
		if len(cont.goferMountConfs) == 0 || !cont.goferMountConfs[0].IsFilestorePresent() {
			continue
		}
		jcfg, err := specutils.JournalingRootfsUpper(cont.spec, cont.conf)
		if err != nil {
			return nil, fmt.Errorf("container %q: %w", cont.cid, err)
		}
		if !jcfg.Enabled {
			continue
		}

		journalFile := l.takeRestoredJournalFile(cont.cid)
		if journalFile == nil {
			return nil, fmt.Errorf("container %q: no journal file for the journaling rootfs upper", cont.cid)
		}
		itemCu := cleanup.Make(func() { _ = journalFile.Close() })
		upperVD, err := l.containerRootUpperVD(ctx, cont.cid)
		if err != nil {
			itemCu.Clean()
			return nil, err
		}
		itemCu.Add(func() { upperVD.DecRef(ctx) })
		upperFS := upperVD.Mount().Filesystem()
		if cont.goferMountConfs[0].IsSelfBacked() {
			creds := auth.NewRootCredentials(l.k.RootUserNamespace())
			if err := syncSelfFilestoreWhiteout(ctx, l.k.VFS(), creds, upperFS, vfs.VirtualDentry{}, l.sandboxID, true /* journaled */); err != nil {
				itemCu.Clean()
				return nil, fmt.Errorf("container %q: failed to create self-filestore whiteout: %w", cont.cid, err)
			}
		}
		upperFS.IncRef()
		upperVD.DecRef(ctx)
		itemCu.Release()
		l.journalingUpperWG.Add(1)
		res.targets = append(res.targets, restoredJournalingUpper{
			conf:        cont.conf,
			cid:         cont.cid,
			upper:       upperFS,
			imageID:     jcfg.ImageID,
			journalFile: journalFile,
		})
	}
	cu.Release()
	if len(res.targets) == 0 {
		return nil, nil
	}
	return res, nil
}

// containerRootUpperVD returns a VirtualDentry for the root of the upper layer
// of container cid's root overlay, with a reference.
func (l *Loader) containerRootUpperVD(ctx context.Context, cid string) (vfs.VirtualDentry, error) {
	l.mu.Lock()
	ep := l.processes[execID{cid: cid}]
	var tg *kernel.ThreadGroup
	if ep != nil {
		tg = ep.tg
	}
	l.mu.Unlock()
	if tg == nil {
		return vfs.VirtualDentry{}, fmt.Errorf("container %q has no init process", cid)
	}
	mntns := tg.Leader().GetMountNamespace()
	if mntns == nil {
		return vfs.VirtualDentry{}, fmt.Errorf("container %q has no mount namespace", cid)
	}
	defer mntns.DecRef(ctx)
	root := mntns.Root(ctx)
	defer root.DecRef(ctx)
	upperVD := overlay.UpperRoot(root.Mount().Filesystem())
	if !upperVD.Ok() {
		return vfs.VirtualDentry{}, fmt.Errorf("rootfs of container %q is not an overlay with an upper layer", cid)
	}
	upperVD.IncRef()
	return upperVD, nil
}

// newJournalingUpperActivation creates an activation callback that takes
// ownership of journalFile and holds a reference on upper and
// l.journalingUpperWG until executed (or canceled with cancel=true).
func (l *Loader) newJournalingUpperActivation(ctx context.Context, conf *config.Config, cid string, upper *vfs.Filesystem, imageID string, journalFile *os.File, waitFn func() error) func(cancel bool) {
	upper.IncRef()
	l.journalingUpperWG.Add(1)
	return func(cancel bool) {
		defer l.journalingUpperWG.Done()
		defer upper.DecRef(ctx)
		if cancel {
			_ = journalFile.Close()
			return
		}
		if err := waitFn(); err != nil {
			_ = journalFile.Close()
			if !l.isJournalingUpperDestroyed() {
				l.killForJournalingUpper(fmt.Errorf("container %q: populating the upper failed: %w", cid, err))
			}
			return
		}
		if l.isJournalingUpperDestroyed() {
			_ = journalFile.Close()
			return
		}
		if err := l.activateJournalingUpper(ctx, conf, cid, upper, imageID, journalFile, true /* pause */); err != nil {
			if !l.isJournalingUpperDestroyed() {
				l.killForJournalingUpper(fmt.Errorf("container %q: %w", cid, err))
			}
		}
	}
}

// scheduleJournalingUpperActivation runs run in the background if the kernel
// has already started, queues it until startJournalingUpperActivations
// otherwise, or cancels it immediately if Loader.Destroy has started.
func (l *Loader) scheduleJournalingUpperActivation(run func(cancel bool)) {
	l.journalingUpperMu.Lock()
	if l.journalingUpperDestroyed {
		l.journalingUpperMu.Unlock()
		run(true)
		return
	}
	if l.journalingUpperKernelStarted {
		l.journalingUpperMu.Unlock()
		go run(false)
		return
	}
	l.journalingUpperActivations = append(l.journalingUpperActivations, run)
	l.journalingUpperMu.Unlock()
}

func (l *Loader) isJournalingUpperDestroyed() bool {
	l.journalingUpperMu.Lock()
	defer l.journalingUpperMu.Unlock()
	return l.journalingUpperDestroyed
}

// startJournalingUpperActivations starts activations scheduled before the
// kernel started.
func (l *Loader) startJournalingUpperActivations() {
	l.journalingUpperMu.Lock()
	if l.journalingUpperDestroyed {
		l.journalingUpperMu.Unlock()
		return
	}
	fns := l.journalingUpperActivations
	l.journalingUpperActivations = nil
	l.journalingUpperKernelStarted = true
	l.journalingUpperMu.Unlock()
	for _, fn := range fns {
		go fn(false)
	}
}

func (l *Loader) cancelJournalingUpperActivations() {
	l.journalingUpperMu.Lock()
	l.journalingUpperDestroyed = true
	fns := l.journalingUpperActivations
	l.journalingUpperActivations = nil
	restoredFiles := l.restoredJournalFiles
	l.restoredJournalFiles = nil
	l.journalingUpperMu.Unlock()
	for _, fn := range fns {
		fn(true)
	}
	for _, f := range restoredFiles {
		f.Close()
	}
}

func (l *Loader) awaitJournalingUppersOnCleanExit(ws uint32) uint32 {
	if linux.WaitStatus(ws).Exited() {
		l.journalingUpperWG.Wait()
		if l.journalingUpperFailed.Load() {
			return uint32(linux.WaitStatusTerminationSignal(linux.SIGKILL))
		}
	}
	return ws
}

func (l *Loader) killForJournalingUpper(err error) {
	log.Warningf("Killing the sandbox: failed to activate a journaling rootfs upper journal: %v.", err)
	l.journalingUpperFailed.Store(true)
	l.k.Kill(linux.WaitStatusTerminationSignal(linux.SIGKILL))
	l.stopIfKilled()
}

// stashRestoredJournalFile saves the journal file of the journaling rootfs
// upper of container cid until its journal is activated after restore.
func (l *Loader) stashRestoredJournalFile(cid string, f *os.File) {
	l.journalingUpperMu.Lock()
	defer l.journalingUpperMu.Unlock()
	if l.restoredJournalFiles == nil {
		l.restoredJournalFiles = make(map[string]*os.File)
	}
	if old := l.restoredJournalFiles[cid]; old != nil {
		old.Close()
	}
	l.restoredJournalFiles[cid] = f
}

// takeRestoredJournalFile returns the journal file saved by
// stashRestoredJournalFile for container cid, or nil. The caller takes
// ownership of the file.
func (l *Loader) takeRestoredJournalFile(cid string) *os.File {
	l.journalingUpperMu.Lock()
	defer l.journalingUpperMu.Unlock()
	f := l.restoredJournalFiles[cid]
	delete(l.restoredJournalFiles, cid)
	return f
}
