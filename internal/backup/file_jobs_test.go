// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package backup

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rkislov/border/internal/store"
)

func testFiles(t *testing.T) (Config, *store.Store, string) {
	t.Helper()
	c, s := fixture(t)
	c.DownloadDir = filepath.Join(filepath.Dir(c.RootDB), "downloads")
	j, e := Process(t.Context(), c, true)
	if e != nil {
		t.Fatal(e)
	}
	if j.Report.SHA256 == "" {
		t.Fatal("archive checksum not recorded")
	}
	return c, s, j.ID
}
func noMountCheck(FileDestination) error { return nil }
func networkFixture(t *testing.T, c *Config, s *store.Store) {
	t.Helper()
	dir := t.TempDir()
	c.FileExport = &FileDestination{ID: "offsite", Directory: dir, MountPoint: dir}
	if e := os.WriteFile(filepath.Join(dir, destinationMarker), []byte("offsite\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := syncFileConfiguration(t.Context(), s, *c); e != nil {
		t.Fatal(e)
	}
	if e := SaveFileExportEnabled(t.Context(), s, true); e != nil {
		t.Fatal(e)
	}
}

func TestPrepareDownloadChecksumExpiryAndRetry(t *testing.T) {
	c, s, id := testFiles(t)
	ctx := t.Context()
	job, e := RequestDownload(ctx, s, id, c.DownloadDir, "admin")
	if e != nil {
		t.Fatal(e)
	}
	again, e := RequestDownload(ctx, s, id, c.DownloadDir, "admin")
	if e != nil || again != job {
		t.Fatal("duplicate download", again, e)
	}
	if _, e = Process(ctx, c, false); e != nil {
		t.Fatal(e)
	}
	j, e := FileJobByID(ctx, s, job)
	if e != nil || j.State != "succeeded" || j.Attempts != 1 || j.ExpiresAt <= time.Now().Unix() {
		t.Fatal("not ready", j, e)
	}
	f, e := OpenDownload(ctx, c.DownloadDir, j)
	if e != nil {
		t.Fatal(e)
	}
	h, n, e := hashReader(ctx, f)
	f.Close()
	if e != nil || h != j.SHA256 || n != j.Bytes {
		t.Fatal("incorrect downloaded content", e)
	}
	name, _ := archiveName(id)
	if _, e = os.Stat(filepath.Join(c.DownloadDir, job, name+".sha256")); e != nil {
		t.Fatal(e)
	}
	if e = s.Exec(ctx, "UPDATE backup_file_jobs SET expires_at=1 WHERE id=?", job); e != nil {
		t.Fatal(e)
	}
	if _, e = Process(ctx, c, false); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Join(c.DownloadDir, job)); !os.IsNotExist(e) {
		t.Fatal("expired encrypted staging remains", e)
	}
	if _, e = RequestDownload(ctx, s, id, c.DownloadDir, "admin"); e != nil {
		t.Fatal(e)
	}
	if _, e = Process(ctx, c, false); e != nil {
		t.Fatal(e)
	}
	j, _ = FileJobByID(ctx, s, job)
	if j.State != "succeeded" {
		t.Fatal(j)
	}
	os.WriteFile(filepath.Join(c.DownloadDir, job, name), []byte("corrupt"), 0640)
	if f, e = OpenDownload(ctx, c.DownloadDir, j); e == nil {
		f.Close()
		t.Fatal("corrupt download served")
	}
	if e = ChangeFileJob(ctx, s, job, "retry", c.DownloadDir); e != nil {
		t.Fatal(e)
	}
	if _, e = Process(ctx, c, false); e != nil {
		t.Fatal(e)
	}
	j, _ = FileJobByID(ctx, s, job)
	if f, e = OpenDownload(ctx, c.DownloadDir, j); e != nil {
		t.Fatal("could not repair download", e)
	} else {
		f.Close()
	}
}

func TestNetworkRetriesHoldLocalArchivesAndDedupe(t *testing.T) {
	c, s, id := testFiles(t)
	ctx := t.Context()
	networkFixture(t, &c, s)
	if e := processFileQueue(ctx, s, c, func(FileDestination) error { return errors.New("offline") }); e == nil {
		t.Fatal("network outage ignored")
	}
	status, e := ReadFileStatus(ctx, s)
	if e != nil || len(status.Jobs) != 1 {
		t.Fatal(status, e)
	}
	j := status.Jobs[0]
	if j.State != "retrying" || j.Attempts != 1 || j.NextAttempt <= time.Now().Unix() {
		t.Fatal("no backoff", j)
	}
	if e = processFileQueue(ctx, s, c, noMountCheck); e != nil {
		t.Fatal(e)
	}
	same, _ := FileJobByID(ctx, s, j.ID)
	if same.Attempts != 1 {
		t.Fatal("backoff bypassed")
	}
	// Two newer backups do not evict an archive whose off-host transfer is pending.
	cNoTarget := c
	cNoTarget.FileExport = nil
	s.Exec(ctx, "UPDATE backup_control SET keep_count=2")
	s.Exec(ctx, "UPDATE backup_jobs SET finished_at=1 WHERE id=?", id)
	for i := 0; i < 2; i++ {
		if _, e = Process(ctx, cNoTarget, true); e != nil {
			t.Fatal(e)
		}
	}
	name, _ := archiveName(id)
	if _, e = os.Stat(filepath.Join(c.OutputDir, name)); e != nil {
		t.Fatal("pending export lost its source", e)
	}
	if e = syncFileConfiguration(ctx, s, c); e != nil {
		t.Fatal(e)
	}
	if e = SaveFileExportEnabled(ctx, s, true); e != nil {
		t.Fatal(e)
	}
	if e = ChangeFileJob(ctx, s, j.ID, "retry", c.DownloadDir); e != nil {
		t.Fatal(e)
	}
	s.Exec(ctx, "UPDATE backup_file_jobs SET updated_at=1 WHERE id=?", j.ID)
	if e = processFileQueue(ctx, s, c, noMountCheck); e != nil {
		t.Fatal(e)
	}
	j, _ = FileJobByID(ctx, s, j.ID)
	if j.State != "succeeded" {
		t.Fatal(j)
	}
	r, e := os.OpenRoot(c.FileExport.Directory)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	if e = verifyBundle(ctx, r, bundleName(j), name, j.SHA256, j.Bytes); e != nil {
		t.Fatal(e)
	}
	var n int
	s.Row(ctx, "SELECT COUNT(*) FROM backup_file_jobs WHERE backup_id=? AND kind='network'", id).Scan(&n)
	if n != 1 {
		t.Fatal("duplicate external job", n)
	}
}

func TestFinalBundleCrashRecoveryAndConflict(t *testing.T) {
	c, s, id := testFiles(t)
	ctx := t.Context()
	networkFixture(t, &c, s)
	if e := enqueueAutomaticFiles(ctx, s, c); e != nil {
		t.Fatal(e)
	}
	v, _ := ReadFileStatus(ctx, s)
	j := v.Jobs[0]
	src := filepath.Join(c.OutputDir, "backup-"+id+".tar.gz.age")
	hash, size, e := digestFile(ctx, src)
	if e != nil {
		t.Fatal(e)
	}
	j.Attempts = 1
	j.SHA256 = hash
	j.Bytes = size
	r, e := os.OpenRoot(c.FileExport.Directory)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	if e = copyFileBundle(ctx, r, src, j, -1); e != nil {
		t.Fatal(e)
	}
	// Crash after publish but before DB acknowledgement: the next attempt verifies
	// the existing bundle, without rewriting it or creating another copy.
	if e = s.Exec(ctx, "UPDATE backup_file_jobs SET state='running',attempts=1,sha256=?,bytes=? WHERE id=?", hash, size, j.ID); e != nil {
		t.Fatal(e)
	}
	if e = processFileQueue(ctx, s, c, noMountCheck); e != nil {
		t.Fatal(e)
	}
	s.Exec(ctx, "UPDATE backup_file_jobs SET next_attempt=0 WHERE id=?", j.ID)
	if e = processFileQueue(ctx, s, c, noMountCheck); e != nil {
		t.Fatal(e)
	}
	j, _ = FileJobByID(ctx, s, j.ID)
	if j.State != "succeeded" || j.Attempts != 2 {
		t.Fatal(j)
	}
	name, _ := archiveName(id)
	if e = os.WriteFile(filepath.Join(c.FileExport.Directory, bundleName(j), name), []byte("foreign data"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = copyFileBundle(ctx, r, src, j, -1); !errors.Is(e, errFileConflict) {
		t.Fatal("foreign content overwritten", e)
	}
	content, _ := os.ReadFile(filepath.Join(c.FileExport.Directory, bundleName(j), name))
	if string(content) != "foreign data" {
		t.Fatal("destination overwritten")
	}
}

func TestDownloadCancellationAndNetworkTargetChange(t *testing.T) {
	c, s, id := testFiles(t)
	ctx := t.Context()
	job, e := RequestDownload(ctx, s, id, c.DownloadDir, "admin")
	if e != nil {
		t.Fatal(e)
	}
	if e = ChangeFileJob(ctx, s, job, "cancel", c.DownloadDir); e != nil {
		t.Fatal(e)
	}
	if _, e = Process(ctx, c, false); e != nil {
		t.Fatal(e)
	}
	j, _ := FileJobByID(ctx, s, job)
	if j.State != "expired" {
		t.Fatal("cancelled download not cleared", j)
	}
	networkFixture(t, &c, s)
	if e = enqueueAutomaticFiles(ctx, s, c); e != nil {
		t.Fatal(e)
	}
	c.FileExport.ID = "different"
	if e = syncFileConfiguration(ctx, s, c); e != nil {
		t.Fatal(e)
	}
	v, _ := ReadFileStatus(ctx, s)
	if v.Enabled {
		t.Fatal("new destination enabled implicitly")
	}
	if e = processFileQueue(ctx, s, c, noMountCheck); e != nil {
		t.Fatal(e)
	}
	v, _ = ReadFileStatus(ctx, s)
	for _, j := range v.Jobs {
		if j.Kind == "network" {
			if j.State != "paused" {
				t.Fatal("job retargeted", j)
			}
			if e = ChangeFileJob(ctx, s, j.ID, "retry", c.DownloadDir); e == nil {
				t.Fatal("old job redirected to new destination")
			}
		}
	}
}

func TestRetryLimitAndPinnedArchiveHash(t *testing.T) {
	c, s, id := testFiles(t)
	ctx := t.Context()
	networkFixture(t, &c, s)
	for attempt := 1; attempt <= 6; attempt++ {
		if e := processFileQueue(ctx, s, c, func(FileDestination) error { return errors.New("offline") }); e == nil {
			t.Fatal("outage ignored")
		}
		v, _ := ReadFileStatus(ctx, s)
		j := v.Jobs[0]
		if j.Attempts != attempt {
			t.Fatal(j)
		}
		if attempt < 6 && j.State != "retrying" {
			t.Fatal(j)
		}
		if attempt == 6 && j.State != "failed" {
			t.Fatal(j)
		}
		s.Exec(ctx, "UPDATE backup_file_jobs SET next_attempt=0")
	}
	v, _ := ReadFileStatus(ctx, s)
	j := v.Jobs[0]
	s.Exec(ctx, "UPDATE backup_file_jobs SET sha256=? WHERE id=?", strings.Repeat("0", 64), j.ID)
	if e := ChangeFileJob(ctx, s, j.ID, "retry", c.DownloadDir); e != nil {
		t.Fatal(e)
	}
	if e := processFileQueue(ctx, s, c, noMountCheck); e == nil {
		t.Fatal("changed archive allowed")
	}
	j, _ = FileJobByID(ctx, s, j.ID)
	if j.ErrorCode != "source_changed" || j.State != "failed" {
		t.Fatal(j)
	}
	if _, e := RequestDownload(ctx, s, "../"+uuid.NewString(), c.DownloadDir, "admin"); e == nil {
		t.Fatal("traversal allowed")
	}
	if _, e := os.Stat(filepath.Join(c.FileExport.Directory, "backup-"+id)); !os.IsNotExist(e) {
		t.Fatal("changed archive reached target")
	}
}

func TestFileConfigurationRejectsSecretAndLocalOverlap(t *testing.T) {
	c, _ := fixture(t)
	c.DownloadDir = c.ConfigDir
	if e := c.Validate(); e == nil {
		t.Fatal("configuration directory exposed")
	}
	c.DownloadDir = ""
	c.FileExport = &FileDestination{ID: "target", Directory: c.OutputDir, MountPoint: filepath.Dir(c.OutputDir)}
	if e := c.Validate(); e == nil {
		t.Fatal("local archive configured as external")
	}
}

func TestFileQueueRetentionBeforeEnqueueAndDownloadCapacity(t *testing.T) {
	c, s, id := testFiles(t)
	ctx := t.Context()
	networkFixture(t, &c, s)
	// Enabled destinations also protect archives not yet reached by a queue batch.
	var safe int
	if e := s.Row(ctx, "SELECT COUNT(*) FROM backup_jobs WHERE id=? AND "+fileRetentionGuard, id).Scan(&safe); e != nil || safe != 0 {
		t.Fatal("archive prunable before enqueue", safe, e)
	}
	job, e := RequestDownload(ctx, s, id, c.DownloadDir, "admin")
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Exec(ctx, "UPDATE backup_file_jobs SET state='expired' WHERE id=?", job); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 10; i++ {
		b := uuid.NewString()
		if e = s.Exec(ctx, "INSERT INTO backup_jobs(id,kind,state,request_key,actor,created_at,verification_state) VALUES(?,'backup','succeeded',?,'test',1,'ok')", b, b); e != nil {
			t.Fatal(e)
		}
		if _, e = RequestDownload(ctx, s, b, c.DownloadDir, "admin"); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = RequestDownload(ctx, s, id, c.DownloadDir, "admin"); e == nil {
		t.Fatal("expired request bypassed capacity")
	}
	if e = ChangeFileJob(ctx, s, job, "retry", c.DownloadDir); e == nil {
		t.Fatal("retry bypassed capacity")
	}
}
