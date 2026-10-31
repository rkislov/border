// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
// Package backup implements encrypted, independently verified SQLite recovery sets.
package backup

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"filippo.io/age"
)

// Config is installed by the host administrator, never accepted by the web API.
// IdentityFile MUST live outside all captured directories and OutputDir.
type Config struct {
	RootDB       string
	TenantDir    string
	ConfigDir    string
	EnvFile      string
	CertDir      string
	Binary       string
	ExtraFiles   []string
	OutputDir    string
	IdentityFile string
	MaxBytes     int64
}

func LoadConfig(path string) (Config, error) {
	var c Config
	f, err := regularFile(path)
	if err != nil {
		return c, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return c, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Geteuid() || info.Mode().Perm()&0077 != 0 {
		return c, errors.New("backup configuration must be owned by the worker user with mode 0600")
	}
	d := json.NewDecoder(io.LimitReader(f, 65537))
	d.DisallowUnknownFields()
	if err = d.Decode(&c); err != nil {
		return c, fmt.Errorf("backup configuration: %w", err)
	}
	if err = d.Decode(new(any)); err != io.EOF {
		return c, errors.New("trailing backup configuration")
	}
	return c, c.Validate()
}

func inside(path, dir string) bool {
	r, err := filepath.Rel(dir, path)
	return err == nil && r != ".." && !strings.HasPrefix(r, ".."+string(filepath.Separator))
}

func (c *Config) Validate() error {
	for _, p := range append([]string{c.RootDB, c.TenantDir, c.ConfigDir, c.EnvFile, c.CertDir, c.Binary, c.OutputDir, c.IdentityFile}, c.ExtraFiles...) {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p || p == "/" {
			return errors.New("backup paths must be clean absolute paths")
		}
	}
	if !inside(c.EnvFile, c.ConfigDir) || !inside(c.CertDir, c.ConfigDir) {
		return errors.New("environment and TLS certificates must be inside ConfigDir")
	}
	for _, p := range append([]string{c.ConfigDir, c.TenantDir, c.OutputDir, c.RootDB, c.Binary}, c.ExtraFiles...) {
		if inside(c.IdentityFile, p) {
			return errors.New("backup identity must be outside all captured paths and OutputDir")
		}
	}
	for _, p := range append([]string{c.ConfigDir, c.TenantDir, c.RootDB, c.Binary}, c.ExtraFiles...) {
		if inside(c.OutputDir, p) || inside(p, c.OutputDir) {
			return errors.New("backup output must not overlap captured directories")
		}
	}
	if c.MaxBytes == 0 {
		c.MaxBytes = 4 << 30
	}
	if c.MaxBytes < 1<<20 || c.MaxBytes > 1<<40 {
		return errors.New("MaxBytes must be between 1 MiB and 1 TiB")
	}
	return nil
}

func regularFile(path string) (*os.File, error) {
	i, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !i.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular file: %s", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	a, err := f.Stat()
	if err != nil || !os.SameFile(i, a) {
		f.Close()
		return nil, errors.New("file changed while opening")
	}
	return f, nil
}

func privateDir(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	i, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !i.IsDir() || i.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("directory must be private (0700): %s", path)
	}
	if st, ok := i.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("private directory must be owned by the worker user: %s", path)
	}
	return nil
}

func InitIdentity(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("identity path must be absolute")
	}
	if err := privateDir(filepath.Dir(path)); err != nil {
		return err
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = fmt.Fprintln(f, id.String()); err != nil {
		return err
	}
	return errors.Join(f.Sync(), syncDir(filepath.Dir(path)))
}

func identity(path string) (*age.X25519Identity, error) {
	f, err := regularFile(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	i, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if i.Mode().Perm()&0077 != 0 {
		return nil, errors.New("backup identity must have mode 0600")
	}
	b, err := io.ReadAll(io.LimitReader(f, 1024))
	if err != nil {
		return nil, err
	}
	defer clear(b)
	return age.ParseX25519Identity(strings.TrimSpace(string(b)))
}
