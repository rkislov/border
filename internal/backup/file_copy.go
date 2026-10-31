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
	"path"

	"github.com/google/uuid"
)

var errFileIntegrity = errors.New("export checksum mismatch")
var errFileConflict = errors.New("destination contains different data")

func bundleName(j FileJob) string {
	if j.Kind == "network" {
		return "backup-" + j.BackupID
	}
	return j.ID
}
func partialName(j FileJob) string { return fmt.Sprintf(".partial-%s-%d", j.ID, j.Attempts) }
func validFileJob(j FileJob) error {
	if _, e := uuid.Parse(j.ID); e != nil || len(j.ID) != 36 {
		return errors.New("invalid transfer ID")
	}
	if _, e := archiveName(j.BackupID); e != nil {
		return e
	}
	if j.Kind != "download" && j.Kind != "network" {
		return errors.New("invalid transfer kind")
	}
	if j.Attempts < 0 || j.Attempts > 6 {
		return errors.New("invalid attempt count")
	}
	return nil
}
func hashReader(ctx context.Context, r io.Reader) (string, int64, error) {
	h := sha256.New()
	n, e := io.Copy(h, contextReader{ctx, r})
	return hex.EncodeToString(h.Sum(nil)), n, e
}
func validFileDigest(hash string, size int64) error {
	b, e := hex.DecodeString(hash)
	if e != nil || len(b) != sha256.Size || size <= 0 || size > 1<<40 {
		return errFileIntegrity
	}
	return nil
}
func verifyBundle(ctx context.Context, r *os.Root, dir, name, expected string, size int64) error {
	if e := validFileDigest(expected, size); e != nil {
		return e
	}
	f, e := r.Open(path.Join(dir, name))
	if e != nil {
		return e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil {
		return e
	}
	if !info.Mode().IsRegular() || info.Size() != size {
		return errFileIntegrity
	}
	h, n, e := hashReader(ctx, io.LimitReader(f, size+1))
	if e != nil {
		return e
	}
	if h != expected || n != size {
		return errFileIntegrity
	}
	f2, e := r.Open(path.Join(dir, name+".sha256"))
	if e != nil {
		return e
	}
	defer f2.Close()
	b, e := io.ReadAll(io.LimitReader(f2, 256))
	if e != nil {
		return e
	}
	if string(b) != expected+"  "+name+"\n" {
		return errFileIntegrity
	}
	return nil
}

// Publish a directory containing the archive and its checksum. Renaming a
// complete directory works on NFS/SMB without relying on hard-link support.
// Existing network bundles are never overwritten; a retry reads them back.
func copyFileBundle(ctx context.Context, r *os.Root, source string, j FileJob, gid int) error {
	if e := validFileJob(j); e != nil {
		return e
	}
	if e := validFileDigest(j.SHA256, j.Bytes); e != nil {
		return e
	}
	name, e := archiveName(j.BackupID)
	if e != nil {
		return e
	}
	bundle := bundleName(j)
	if _, e = r.Lstat(bundle); e == nil {
		if e = verifyBundle(ctx, r, bundle, name, j.SHA256, j.Bytes); e != nil {
			if j.Kind != "download" {
				return errFileConflict
			}
			// A requested download can be prepared again from the verified source.
			// Only this job's disposable staging bundle is replaced.
			if e = r.RemoveAll(bundle); e != nil {
				return e
			}
		} else {
			return nil
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	stage := partialName(j)
	if e = r.RemoveAll(stage); e != nil {
		return e
	}
	if e = r.Mkdir(stage, 0700); e != nil {
		return e
	}
	defer r.RemoveAll(stage)
	src, e := regularFile(source)
	if e != nil {
		return e
	}
	defer src.Close()
	out, e := r.OpenFile(path.Join(stage, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	h := sha256.New()
	n, e := io.Copy(io.MultiWriter(out, h), io.LimitReader(contextReader{ctx, src}, j.Bytes+1))
	if e == nil {
		e = out.Sync()
	}
	if e == nil && gid >= 0 {
		e = out.Chown(-1, gid)
		if e == nil {
			e = out.Chmod(0640)
		}
	}
	e = errors.Join(e, out.Close())
	if e != nil {
		return e
	}
	if n != j.Bytes || hex.EncodeToString(h.Sum(nil)) != j.SHA256 {
		return errFileIntegrity
	}
	checksum, e := r.OpenFile(path.Join(stage, name+".sha256"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	_, e = fmt.Fprintf(checksum, "%s  %s\n", j.SHA256, name)
	if e == nil {
		e = checksum.Sync()
	}
	if e == nil && gid >= 0 {
		e = checksum.Chown(-1, gid)
		if e == nil {
			e = checksum.Chmod(0640)
		}
	}
	e = errors.Join(e, checksum.Close())
	if e != nil {
		return e
	}
	// Read the staged file from storage, not from the sender's copy buffer.
	if e = verifyBundle(ctx, r, stage, name, j.SHA256, j.Bytes); e != nil {
		return e
	}
	if gid >= 0 {
		d, e := r.Open(stage)
		if e != nil {
			return e
		}
		e = d.Chown(-1, gid)
		if e == nil {
			e = d.Chmod(0750)
		}
		e = errors.Join(e, d.Close())
		if e != nil {
			return e
		}
	}
	if e = r.Rename(stage, bundle); e != nil {
		if exists := verifyBundle(ctx, r, bundle, name, j.SHA256, j.Bytes); exists == nil {
			return nil
		}
		return e
	}
	return verifyBundle(ctx, r, bundle, name, j.SHA256, j.Bytes)
}

// OpenDownload verifies the encrypted staging copy before HTTP delivery. It
// never opens the root-only archive directory or the age identity.
func OpenDownload(ctx context.Context, dir string, j FileJob) (*os.File, error) {
	if e := validFileJob(j); e != nil {
		return nil, e
	}
	if e := validFileDigest(j.SHA256, j.Bytes); e != nil {
		return nil, e
	}
	if j.Kind != "download" || j.Target != DownloadTarget(dir) || j.State != "succeeded" {
		return nil, errors.New("download unavailable")
	}
	r, e := os.OpenRoot(dir)
	if e != nil {
		return nil, e
	}
	defer r.Close()
	name, e := archiveName(j.BackupID)
	if e != nil {
		return nil, e
	}
	p := path.Join(j.ID, name)
	i, e := r.Lstat(p)
	if e != nil {
		return nil, e
	}
	if !i.Mode().IsRegular() {
		return nil, errors.New("invalid download file")
	}
	f, e := r.Open(p)
	if e != nil {
		return nil, e
	}
	h, n, e := hashReader(ctx, io.LimitReader(f, j.Bytes+1))
	if e != nil || n != j.Bytes || h != j.SHA256 {
		f.Close()
		return nil, errFileIntegrity
	}
	if _, e = f.Seek(0, io.SeekStart); e != nil {
		f.Close()
		return nil, e
	}
	return f, nil
}
