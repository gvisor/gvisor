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

	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/checkpoint"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/tmpfs"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/tmpfs/journal"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
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
	mf, _, err := createPrivateMemoryFile(filestore, resourceID, c.containerID, c.l.fsRestore, jcfg.Enabled)
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
	_ = journalFile.Close()
	return nil, nil, fmt.Errorf("populated journaling rootfs upper is not yet supported")
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
