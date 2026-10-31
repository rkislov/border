// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/rkislov/border/internal/store"
)

// FileDestination is configured by the OS administrator. Directory must be on
// an explicitly mounted network filesystem; the worker never mounts a share.
type FileDestination struct{ ID, Directory, MountPoint string }

func DownloadTarget(dir string) string {
	if dir == "" {
		return ""
	}
	h := sha256.Sum256([]byte("download\x00" + dir))
	return hex.EncodeToString(h[:])
}
func (d FileDestination) target() string {
	h := sha256.Sum256([]byte("network\x00" + d.ID + "\x00" + d.Directory + "\x00" + d.MountPoint))
	return hex.EncodeToString(h[:])
}
func cleanAbs(p string) bool { return filepath.IsAbs(p) && filepath.Clean(p) == p && p != "/" }
func (c Config) validateFileExports() error {
	dirs := []string{}
	if c.DownloadDir != "" {
		dirs = append(dirs, c.DownloadDir)
	}
	if c.FileExport != nil {
		d := c.FileExport
		if !tenantID.MatchString(d.ID) || !cleanAbs(d.MountPoint) || !inside(d.Directory, d.MountPoint) {
			return errors.New("file export needs an ID, absolute MountPoint and Directory inside it")
		}
		dirs = append(dirs, d.Directory)
	}
	for _, dir := range dirs {
		if !cleanAbs(dir) {
			return errors.New("export directories must be clean absolute paths")
		}
		for _, source := range append([]string{c.RootDB, c.TenantDir, c.ConfigDir, c.Binary, c.OutputDir, c.IdentityFile}, c.ExtraFiles...) {
			if inside(source, dir) || inside(dir, source) {
				return errors.New("export directories must not overlap backup sources, archives or identity")
			}
		}
	}
	if len(dirs) == 2 && (inside(dirs[0], dirs[1]) || inside(dirs[1], dirs[0])) {
		return errors.New("download and network export directories must not overlap")
	}
	return nil
}

// Only the worker publishes this non-secret configuration summary to the API.
func syncFileConfiguration(ctx context.Context, s *store.Store, c Config) error {
	target, label := "", ""
	if c.FileExport != nil {
		target = c.FileExport.target()
		label = c.FileExport.ID
	}
	return s.Exec(ctx, "UPDATE backup_control SET file_enabled=CASE WHEN file_target=? THEN file_enabled ELSE 0 END,file_target=?,file_label=?,download_target=? WHERE id=1", target, target, label, DownloadTarget(c.DownloadDir))
}

const destinationMarker = ".border-backup-target"

func openNetwork(d FileDestination, check func(FileDestination) error) (*os.Root, error) {
	if err := check(d); err != nil {
		return nil, err
	}
	r, err := os.OpenRoot(d.Directory)
	if err != nil {
		return nil, err
	}
	i, err := r.Lstat(destinationMarker)
	if err != nil || !i.Mode().IsRegular() {
		r.Close()
		return nil, errors.New("network backup target marker is not a regular file")
	}
	if err = check(d); err != nil {
		r.Close()
		return nil, err
	}
	f, err := r.Open(destinationMarker)
	if err != nil {
		r.Close()
		return nil, err
	}
	b, err := io.ReadAll(io.LimitReader(f, 256))
	f.Close()
	if err != nil || strings.TrimSpace(string(b)) != d.ID {
		r.Close()
		return nil, errors.New("network backup target marker missing or different")
	}
	return r, nil
}

// InitFileExport binds an existing network directory to this target ID. It does
// not mount anything or replace an existing marker, archive or credential.
func InitFileExport(c Config) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if c.FileExport == nil {
		return errors.New("FileExport is not configured")
	}
	d := *c.FileExport
	if err := checkNetworkMount(d); err != nil {
		return err
	}
	r, err := os.OpenRoot(d.Directory)
	if err != nil {
		return err
	}
	defer r.Close()
	f, err := r.OpenFile(destinationMarker, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(f, d.ID)
	if err == nil {
		err = f.Sync()
	}
	return errors.Join(err, f.Close())
}

// The web process can read encrypted downloads but cannot alter them. The
// worker uses the database's group, never a group/path supplied in an API call.
func downloadGroup(c Config) (int, error) {
	i, e := os.Stat(c.RootDB)
	if e != nil {
		return 0, e
	}
	st, ok := i.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("database ownership unavailable")
	}
	return int(st.Gid), nil
}
func openDownloads(c Config) (*os.Root, int, error) {
	if c.DownloadDir == "" {
		return nil, 0, errors.New("downloads not configured")
	}
	gid, e := downloadGroup(c)
	if e != nil {
		return nil, 0, e
	}
	parent, e := os.Stat(filepath.Dir(c.DownloadDir))
	if e != nil {
		return nil, 0, e
	}
	ps, ok := parent.Sys().(*syscall.Stat_t)
	if !ok || int(ps.Uid) != os.Geteuid() || parent.Mode().Perm()&0022 != 0 {
		return nil, 0, errors.New("download parent directory must be owned by the worker and not writable by other users")
	}
	if e = os.MkdirAll(c.DownloadDir, 0750); e != nil {
		return nil, 0, e
	}
	i, e := os.Lstat(c.DownloadDir)
	if e != nil {
		return nil, 0, e
	}
	st, ok := i.Sys().(*syscall.Stat_t)
	if !i.IsDir() || !ok || int(st.Uid) != os.Geteuid() || i.Mode().Perm()&0027 != 0 {
		return nil, 0, errors.New("download directory must be owned by the worker and have mode 0750 or stricter")
	}
	f, e := os.Open(c.DownloadDir)
	if e != nil {
		return nil, 0, e
	}
	defer f.Close()
	if e = f.Chown(-1, gid); e != nil {
		return nil, 0, e
	}
	if e = f.Chmod(0750); e != nil {
		return nil, 0, e
	}
	r, e := os.OpenRoot(c.DownloadDir)
	return r, gid, e
}
