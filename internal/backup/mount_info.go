// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package backup

import (
	"errors"
	"strings"
)

func networkMountInfo(info, mount, directory string) error {
	decode := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	found := false
	effectiveNetwork := false
	deepest := -1
	for _, line := range strings.Split(info, "\n") {
		parts := strings.SplitN(line, " - ", 2)
		if len(parts) != 2 {
			continue
		}
		left, right := strings.Fields(parts[0]), strings.Fields(parts[1])
		if len(left) < 6 || len(right) < 3 {
			continue
		}
		// ProtectSystem/ReadWritePaths can create local bind mounts. They must not
		// masquerade as an off-host destination when the real share is absent.
		fs := right[0]
		isNetwork := fs == "nfs" || fs == "nfs4" || fs == "cifs" || fs == "smb3" || fs == "fuse.sshfs" || fs == "fuse.rclone" || fs == "fuse.davfs"
		if strings.Contains(","+left[5]+",", ",ro,") {
			isNetwork = false
		}
		point := decode.Replace(left[4])
		if point == mount {
			found = isNetwork
		}
		if inside(directory, point) && len(point) >= deepest {
			deepest = len(point)
			effectiveNetwork = isNetwork
		}
	}
	if !found || !effectiveNetwork {
		return errors.New("configured writable network mount is unavailable")
	}
	return nil
}
