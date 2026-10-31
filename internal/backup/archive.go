// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package backup

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"filippo.io/age"
)

type File struct {
	Path   string
	Source string
	SHA256 string
	Size   int64
	Mode   uint32
	Kind   string
	Tenant string
}
type Manifest struct {
	Format     int
	StartedAt  int64
	CapturedAt int64
	EnvFile    string
	CertDir    string
	Binary     string
	Files      []File
}
type Report struct {
	VerifiedAt int64
	Databases  int
	Tenants    int
	Files      int
	Secrets    int
	Bytes      int64
	StartedAt  int64
	CapturedAt int64
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

func sourceFiles(c Config) ([]string, error) {
	set := map[string]bool{}
	for _, p := range append([]string{c.ConfigDir, c.Binary}, c.ExtraFiles...) {
		err := filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.Type()&os.ModeSymlink != 0 {
				return fmt.Errorf("symlink not allowed in backup sources: %s", path)
			}
			if d.IsDir() {
				return nil
			}
			if !d.Type().IsRegular() {
				return fmt.Errorf("special file not allowed: %s", path)
			}
			if path == c.IdentityFile {
				return errors.New("backup identity cannot be archived")
			}
			set[path] = true
			if len(set) > 10000 {
				return errors.New("too many backup files")
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out, nil
}

func digestFile(ctx context.Context, p string) (string, int64, error) {
	f, err := regularFile(p)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, contextReader{ctx, f})
	return hex.EncodeToString(h.Sum(nil)), n, err
}

func stagedFile(ctx context.Context, dir, src, path, kind, tenant string, max int64) (File, error) {
	v := File{Path: path, Source: src, Kind: kind, Tenant: tenant}
	dst := filepath.Join(dir, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
		return v, err
	}
	if kind == "database" {
		if err := snapshot(ctx, src, dst, max); err != nil {
			return v, err
		}
		v.Mode = 0600
	} else {
		f, err := regularFile(src)
		if err != nil {
			return v, err
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil {
			return v, err
		}
		v.Mode = uint32(info.Mode().Perm())
		if info.Size() > max {
			return v, errors.New("backup size limit exceeded")
		}
		out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return v, err
		}
		n, e := io.Copy(out, io.LimitReader(contextReader{ctx, f}, max+1))
		err = errors.Join(e, out.Close())
		if err != nil {
			return v, err
		}
		if n > max {
			return v, errors.New("backup size limit exceeded")
		}
	}
	var err error
	v.SHA256, v.Size, err = digestFile(ctx, dst)
	if v.Size > max {
		return v, errors.New("backup size limit exceeded")
	}
	return v, err
}

// Create returns only after a separate decryption, extraction and recovery check.
// Failed archives are never promoted to the final name or eligible for retention.
func Create(ctx context.Context, c Config, destination string) (Report, error) {
	var report Report
	if err := c.Validate(); err != nil {
		return report, err
	}
	if err := checkSourceEnvironment(c); err != nil {
		return report, err
	}
	if filepath.Dir(destination) != c.OutputDir {
		return report, errors.New("archive must be in OutputDir")
	}
	if err := privateDir(c.OutputDir); err != nil {
		return report, err
	}
	id, err := identity(c.IdentityFile)
	if err != nil {
		return report, err
	}
	stage, err := os.MkdirTemp(c.OutputDir, ".capture-")
	if err != nil {
		return report, err
	}
	defer os.RemoveAll(stage)
	m := Manifest{Format: 1, StartedAt: time.Now().Unix(), EnvFile: c.EnvFile, CertDir: c.CertDir, Binary: c.Binary}
	var total int64
	add := func(src, path, kind, tenant string) error {
		v, e := stagedFile(ctx, stage, src, path, kind, tenant, c.MaxBytes-total)
		if e == nil {
			m.Files = append(m.Files, v)
			total += v.Size
		}
		return e
	}
	// The captured catalog determines membership; tenant creation commits its catalog entry last.
	if err = add(c.RootDB, "databases/root.db", "database", ""); err != nil {
		return report, err
	}
	ids, err := tenants(ctx, filepath.Join(stage, "databases/root.db"))
	if err != nil {
		return report, err
	}
	for _, id := range ids {
		if err = add(filepath.Join(c.TenantDir, id+".db"), "databases/tenants/"+id+".db", "database", id); err != nil {
			return report, err
		}
	}
	sources, err := sourceFiles(c)
	if err != nil {
		return report, err
	}
	keyInfo, err := os.Stat(c.IdentityFile)
	if err != nil {
		return report, err
	}
	for _, src := range sources {
		info, e := os.Stat(src)
		if e != nil {
			return report, e
		}
		if os.SameFile(keyInfo, info) {
			return report, errors.New("backup identity cannot be archived through an alias")
		}
		if err = add(src, "files/"+strings.TrimPrefix(filepath.ToSlash(src), "/"), "file", ""); err != nil {
			return report, err
		}
	}
	// A key/configuration rotation during capture must fail, not produce a mixed recovery set.
	again, err := sourceFiles(c)
	if err != nil {
		return report, err
	}
	if strings.Join(sources, "\n") != strings.Join(again, "\n") {
		return report, errors.New("backup source list changed during capture")
	}
	for _, v := range m.Files {
		if v.Kind == "file" {
			sum, n, e := digestFile(ctx, v.Source)
			if e != nil {
				return report, e
			}
			if sum != v.SHA256 || n != v.Size {
				return report, errors.New("configuration changed during capture; retry backup")
			}
		}
	}
	m.CapturedAt = time.Now().Unix()
	partial := destination + ".partial"
	f, err := os.OpenFile(partial, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return report, err
	}
	defer os.Remove(partial)
	err = writeArchive(ctx, f, id.Recipient(), stage, m)
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return report, err
	}
	report, err = Verify(ctx, partial, c.IdentityFile, c.OutputDir, c.MaxBytes)
	if err != nil {
		return report, err
	}
	// Link is an atomic, no-clobber promotion on the same filesystem.
	if err = os.Link(partial, destination); err != nil {
		return report, err
	}
	if err = syncDir(c.OutputDir); err != nil {
		return report, err
	}
	info, err := os.Stat(destination)
	if err == nil {
		report.Bytes = info.Size()
	}
	return report, err
}

func writeArchive(ctx context.Context, out io.Writer, recipient age.Recipient, stage string, m Manifest) (err error) {
	e, err := age.Encrypt(out, recipient)
	if err != nil {
		return err
	}
	g := gzip.NewWriter(e)
	t := tar.NewWriter(g)
	defer func() { err = errors.Join(err, t.Close(), g.Close(), e.Close()) }()
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if len(b) > 4<<20 {
		return errors.New("backup manifest too large")
	}
	if err = t.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0600, Size: int64(len(b)), Typeflag: tar.TypeReg}); err != nil {
		return err
	}
	if _, err = t.Write(b); err != nil {
		return err
	}
	for _, v := range m.Files {
		if err = t.WriteHeader(&tar.Header{Name: v.Path, Mode: 0600, Size: v.Size, Typeflag: tar.TypeReg}); err != nil {
			return err
		}
		f, e := regularFile(filepath.Join(stage, filepath.FromSlash(v.Path)))
		if e != nil {
			return e
		}
		_, err = io.Copy(t, contextReader{ctx, f})
		err = errors.Join(err, f.Close())
		if err != nil {
			return err
		}
	}
	return nil
}

func syncDir(path string) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}

func Verify(ctx context.Context, archive, key, tempDir string, maxBytes int64) (Report, error) {
	var r Report
	if maxBytes < 1<<20 || maxBytes > 1<<40 {
		return r, errors.New("invalid expanded size limit")
	}
	dir, err := os.MkdirTemp(tempDir, ".verify-")
	if err != nil {
		return r, err
	}
	defer os.RemoveAll(dir)
	return extractAndVerify(ctx, archive, key, dir, maxBytes)
}

// Restore creates a NEW directory. It never replaces a live database or starts services.
func Restore(ctx context.Context, archive, key, destination string, maxBytes int64) (r Report, err error) {
	if maxBytes < 1<<20 || maxBytes > 1<<40 {
		return r, errors.New("invalid expanded size limit")
	}
	if !filepath.IsAbs(destination) {
		return r, errors.New("restore destination must be absolute")
	}
	if err = os.Mkdir(destination, 0700); err != nil {
		return r, err
	}
	defer func() {
		if err != nil {
			os.RemoveAll(destination)
		}
	}()
	return extractAndVerify(ctx, archive, key, destination, maxBytes)
}

func extractAndVerify(ctx context.Context, archive, key, dir string, maxBytes int64) (Report, error) {
	var r Report
	root, err := os.OpenRoot(dir)
	if err != nil {
		return r, err
	}
	defer root.Close()
	id, err := identity(key)
	if err != nil {
		return r, err
	}
	f, err := regularFile(archive)
	if err != nil {
		return r, err
	}
	defer f.Close()
	a, err := age.Decrypt(contextReader{ctx, f}, id)
	if err != nil {
		return r, err
	}
	g, err := gzip.NewReader(a)
	if err != nil {
		return r, err
	}
	defer g.Close()
	// Bound expanded bytes including metadata/padding, not just declared file sizes.
	limited := &io.LimitedReader{R: g, N: maxBytes + (8 << 20)}
	t := tar.NewReader(limited)
	h, err := t.Next()
	if err != nil {
		return r, err
	}
	if h.Name != "manifest.json" || h.Typeflag != tar.TypeReg || h.Size > 4<<20 {
		return r, errors.New("invalid backup manifest")
	}
	b, err := io.ReadAll(t)
	if err != nil {
		return r, err
	}
	var m Manifest
	if err = json.Unmarshal(b, &m); err != nil {
		return r, err
	}
	if m.Format != 1 || len(m.Files) == 0 || len(m.Files) > 10065 {
		return r, errors.New("unsupported backup format")
	}
	if err = root.WriteFile("manifest.json", b, 0600); err != nil {
		return r, err
	}
	seen := map[string]bool{}
	var total int64
	for _, v := range m.Files {
		if !fs.ValidPath(v.Path) || strings.Contains(v.Path, "\\") || v.Path == "manifest.json" || seen[v.Path] || v.Size < 0 || v.Size > maxBytes-total {
			return r, errors.New("unsafe backup entry")
		}
		if v.Kind != "file" && v.Kind != "database" {
			return r, errors.New("unknown backup entry kind")
		}
		seen[v.Path] = true
		total += v.Size
		h, err = t.Next()
		if err != nil {
			return r, err
		}
		if h.Name != v.Path || h.Size != v.Size || h.Typeflag != tar.TypeReg {
			return r, errors.New("archive differs from manifest")
		}
		p := filepath.FromSlash(v.Path)
		if err = root.MkdirAll(filepath.Dir(p), 0700); err != nil {
			return r, err
		}
		out, e := root.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return r, e
		}
		sum := sha256.New()
		_, err = io.Copy(io.MultiWriter(out, sum), t)
		if err == nil {
			err = out.Sync()
		}
		err = errors.Join(err, out.Close())
		if err != nil {
			return r, err
		}
		if hex.EncodeToString(sum.Sum(nil)) != v.SHA256 {
			return r, errors.New("backup checksum mismatch")
		}
	}
	if _, err = t.Next(); err != io.EOF {
		return r, errors.New("unexpected trailing archive entry")
	}
	// Read through gzip checksum AND age's final authenticated chunk; a truncated tail is failure.
	if _, err = io.Copy(io.Discard, limited); err != nil {
		return r, err
	}
	if limited.N == 0 {
		return r, errors.New("expanded archive exceeds limit")
	}
	if _, err = io.Copy(io.Discard, a); err != nil {
		return r, err
	}
	r, err = checkRecovery(ctx, dir, m)
	if err != nil {
		return r, err
	}
	r.VerifiedAt = time.Now().Unix()
	r.StartedAt = m.StartedAt
	r.CapturedAt = m.CapturedAt
	info, err := f.Stat()
	if err == nil {
		r.Bytes = info.Size()
	}
	return r, err
}
