//go:build !linux

// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package backup

import "errors"

func checkNetworkMount(FileDestination) error {
	return errors.New("automatic network-folder exports require the Linux worker")
}
