//go:build linux

// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package backup

import (
	"errors"
	"os"
	"path/filepath"
)

func checkNetworkMount(d FileDestination) error {
	real, e := filepath.EvalSymlinks(d.Directory)
	if e != nil {
		return e
	}
	mount, e := filepath.EvalSymlinks(d.MountPoint)
	if e != nil {
		return e
	}
	if real != d.Directory || mount != d.MountPoint {
		return errors.New("network export paths must not contain symlinks")
	}
	b, e := os.ReadFile("/proc/self/mountinfo")
	if e != nil {
		return e
	}
	return networkMountInfo(string(b), d.MountPoint, d.Directory)
}
