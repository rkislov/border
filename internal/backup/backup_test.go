// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package backup

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rkislov/border/internal/auth"
	"github.com/rkislov/border/internal/pki"
	"github.com/rkislov/border/internal/store"
	"golang.org/x/sys/unix"
)

func fixture(t *testing.T) (Config, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	c := Config{RootDB: filepath.Join(dir, "root.db"), TenantDir: filepath.Join(dir, "tenants"), ConfigDir: filepath.Join(dir, "etc"), EnvFile: filepath.Join(dir, "etc", "border.env"), CertDir: filepath.Join(dir, "etc", "certs"), Binary: filepath.Join(dir, "radiusd"), OutputDir: filepath.Join(dir, "archives"), IdentityFile: filepath.Join(dir, "key", "identity"), MaxBytes: 32 << 20}
	for _, p := range []string{c.TenantDir, c.ConfigDir, c.OutputDir} {
		if e := os.MkdirAll(p, 0700); e != nil {
			t.Fatal(e)
		}
	}
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	if e := os.WriteFile(c.EnvFile, []byte("BORDER_MASTER_KEY='"+base64.StdEncoding.EncodeToString(key)+"'\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(c.Binary, []byte("fixture executable"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := pki.Generate(c.CertDir, "localhost"); e != nil {
		t.Fatal(e)
	}
	if e := InitIdentity(c.IdentityFile); e != nil {
		t.Fatal(e)
	}
	s, e := store.Open("sqlite", c.RootDB)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.DB.Close() })
	if e = s.Migrate(t.Context()); e != nil {
		t.Fatal(e)
	}
	tenant, e := store.Open("sqlite", filepath.Join(c.TenantDir, "lab.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { tenant.DB.Close() })
	if e = tenant.Migrate(t.Context()); e != nil {
		t.Fatal(e)
	}
	if e = s.Exec(t.Context(), "INSERT INTO tenant_instances VALUES('lab','Lab',1)"); e != nil {
		t.Fatal(e)
	}
	h := hmac.New(sha256.New, key)
	h.Write([]byte("Border tenant master v1\x00lab"))
	for i, db := range []*store.Store{s, tenant} {
		k := key
		if i == 1 {
			k = h.Sum(nil)
		}
		v, _ := auth.NewVault(k)
		if e = db.Exec(t.Context(), "INSERT INTO identities(username,email,totp_secret) VALUES('alice','alice@example.test',?)", v.Seal([]byte("totp-test-secret"), "totp:alice")); e != nil {
			t.Fatal(e)
		}
	}
	return c, s
}

func TestEncryptedRecoveryIncludesAllTenantsAndKeys(t *testing.T) {
	c, s := fixture(t)
	// Disabling browser notifications intentionally clears the encrypted destination.
	if e := s.Exec(t.Context(), "INSERT INTO policy_notification_targets(id,username,channel,scope,destination,enabled,revision) VALUES('admin:push','admin','push','default','',0,1)"); e != nil {
		t.Fatal(e)
	}
	p := filepath.Join(c.OutputDir, "test.age")
	r, e := Create(t.Context(), c, p)
	if e != nil {
		t.Fatal(e)
	}
	if r.Databases != 2 || r.Tenants != 1 || r.Secrets != 2 || r.VerifiedAt == 0 {
		t.Fatalf("report: %+v", r)
	}
	content, e := os.ReadFile(p)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(content), "BORDER_MASTER_KEY") || strings.Contains(string(content), "fixture executable") {
		t.Fatal("plaintext archive")
	}
	dest := filepath.Join(t.TempDir(), "restored")
	if _, e = Restore(t.Context(), p, c.IdentityFile, dest, c.MaxBytes); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(filepath.Join(dest, "files", strings.TrimPrefix(c.Binary, "/")))
	if e != nil || string(b) != "fixture executable" {
		t.Fatal("binary missing", e)
	}
	if _, e = Restore(t.Context(), p, c.IdentityFile, dest, c.MaxBytes); e == nil {
		t.Fatal("restore overwrote existing directory")
	}
	if e = InitIdentity(c.IdentityFile); e == nil {
		t.Fatal("identity overwritten")
	}
	if _, e = Create(t.Context(), c, p); e == nil {
		t.Fatal("archive overwritten")
	}
}

func TestCorruptionWrongKeyAndMissingTenantFail(t *testing.T) {
	c, _ := fixture(t)
	p := filepath.Join(c.OutputDir, "good.age")
	if _, e := Create(t.Context(), c, p); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(p)
	if e != nil {
		t.Fatal(e)
	}
	for _, mode := range []string{"truncated", "tampered"} {
		t.Run(mode, func(t *testing.T) {
			bad := append([]byte{}, b...)
			if mode == "truncated" {
				bad = bad[:len(bad)-8]
			} else {
				bad[len(bad)-1] ^= 1
			}
			file := filepath.Join(c.OutputDir, mode+".age")
			os.WriteFile(file, bad, 0600)
			dest := filepath.Join(t.TempDir(), "bad-restore")
			if _, e := Restore(t.Context(), file, c.IdentityFile, dest, c.MaxBytes); e == nil {
				t.Fatal("damaged archive accepted")
			}
			if _, e := os.Stat(dest); !os.IsNotExist(e) {
				t.Fatal("failed restore left secrets behind")
			}
		})
	}
	other := filepath.Join(t.TempDir(), "key", "id")
	if e = InitIdentity(other); e != nil {
		t.Fatal(e)
	}
	if _, e = Verify(t.Context(), p, other, c.OutputDir, c.MaxBytes); e == nil {
		t.Fatal("wrong key accepted")
	}
	if e = os.Remove(filepath.Join(c.TenantDir, "lab.db")); e != nil {
		t.Fatal(e)
	}
	missing := filepath.Join(c.OutputDir, "missing.age")
	if _, e = Create(t.Context(), c, missing); e == nil {
		t.Fatal("missing tenant silently omitted")
	}
	if _, e = os.Stat(missing); !os.IsNotExist(e) {
		t.Fatal("failed backup promoted")
	}
}

func TestRecoveryValidatesArchivedMasterKey(t *testing.T) {
	c, _ := fixture(t)
	wrong := base64.StdEncoding.EncodeToString(make([]byte, 32))
	os.WriteFile(c.EnvFile, []byte("BORDER_MASTER_KEY="+wrong), 0600)
	if _, e := Create(t.Context(), c, filepath.Join(c.OutputDir, "wrong-master.age")); e == nil || !strings.Contains(e.Error(), "decrypt") {
		t.Fatal("wrong archived master accepted", e)
	}
}

func TestStaleDatabaseConfigurationIsRejected(t *testing.T) {
	c, _ := fixture(t)
	original, e := os.ReadFile(c.EnvFile)
	if e != nil {
		t.Fatal(e)
	}
	for _, entry := range []string{"BORDER_DB_DRIVER=pgx", "BORDER_DB=/different/database.db", "BORDER_TENANT_DIR=/different/tenants"} {
		if e = os.WriteFile(c.EnvFile, append(append([]byte{}, original...), []byte(entry+"\n")...), 0600); e != nil {
			t.Fatal(e)
		}
		if _, e = Create(t.Context(), c, filepath.Join(c.OutputDir, "stale.age")); e == nil {
			t.Fatal("stale source configuration accepted", entry)
		}
	}
}

func TestSnapshotIncludesUncheckpointedWALAndDoesNotClobber(t *testing.T) {
	d := t.TempDir()
	s, e := store.Open("sqlite", filepath.Join(d, "live.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	for _, q := range []string{"PRAGMA wal_autocheckpoint=0", "CREATE TABLE pair(a INTEGER,b INTEGER)", "INSERT INTO pair VALUES(42,42)"} {
		if e = s.Exec(t.Context(), q); e != nil {
			t.Fatal(e)
		}
	}
	if i, e := os.Stat(filepath.Join(d, "live.db-wal")); e != nil || i.Size() == 0 {
		t.Fatal("test requires WAL data", e)
	}
	dst := filepath.Join(d, "copy.db")
	if e = Snapshot(t.Context(), filepath.Join(d, "live.db"), dst); e != nil {
		t.Fatal(e)
	}
	db, e := openDB(dst)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	var a, b int
	if e = db.QueryRow("SELECT a,b FROM pair").Scan(&a, &b); e != nil || a != 42 || b != 42 {
		t.Fatal("WAL changes lost", a, b, e)
	}
	if e = Snapshot(t.Context(), filepath.Join(d, "live.db"), dst); e == nil {
		t.Fatal("overwrote snapshot")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if e = Snapshot(ctx, filepath.Join(d, "live.db"), filepath.Join(d, "cancelled.db")); e == nil {
		t.Fatal("ignored cancellation")
	}
}

func TestSnapshotDuringWritesIsTransactionallyConsistent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "live.db")
	s, e := store.Open("sqlite", path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	if e = s.Exec(t.Context(), "CREATE TABLE pair(a INTEGER,b INTEGER)"); e != nil {
		t.Fatal(e)
	}
	if e = s.Exec(t.Context(), "INSERT INTO pair VALUES(0,0)"); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		for {
			select {
			case <-ctx.Done():
				done <- nil
				return
			default:
			}
			tx, e := s.DB.BeginTx(ctx, nil)
			if e != nil {
				if ctx.Err() != nil {
					done <- nil
				} else {
					done <- e
				}
				return
			}
			_, e = tx.ExecContext(ctx, "UPDATE pair SET a=a+1")
			if e == nil {
				_, e = tx.ExecContext(ctx, "UPDATE pair SET b=b+1")
			}
			if e == nil {
				e = tx.Commit()
			} else {
				tx.Rollback()
			}
			if e != nil {
				if ctx.Err() != nil {
					done <- nil
				} else {
					done <- e
				}
				return
			}
		}
	}()
	defer func() {
		cancel()
		if e := <-done; e != nil {
			t.Error(e)
		}
	}()
	for i := 0; i < 3; i++ {
		dst := filepath.Join(dir, uuid.NewString()+".db")
		if e = Snapshot(t.Context(), path, dst); e != nil {
			t.Fatal(e)
		}
		db, e := openDB(dst)
		if e != nil {
			t.Fatal(e)
		}
		var a, b int
		e = db.QueryRow("SELECT a,b FROM pair").Scan(&a, &b)
		db.Close()
		if e != nil || a != b {
			t.Fatal("partial transaction captured", a, b, e)
		}
	}
}

func TestUnsafePathsSymlinksAndSizeLimits(t *testing.T) {
	c, _ := fixture(t)
	os.Symlink(c.IdentityFile, filepath.Join(c.ConfigDir, "secret-link"))
	if _, e := Create(t.Context(), c, filepath.Join(c.OutputDir, "symlink.age")); e == nil {
		t.Fatal("symlink accepted")
	}
	os.Remove(filepath.Join(c.ConfigDir, "secret-link"))
	c.IdentityFile = filepath.Join(c.ConfigDir, "key")
	if e := c.Validate(); e == nil {
		t.Fatal("identity could be archived")
	}
}

func TestTraversalAndExtraDatabaseRejected(t *testing.T) {
	c, _ := fixture(t)
	p := filepath.Join(c.OutputDir, "original.age")
	if _, e := Create(t.Context(), c, p); e != nil {
		t.Fatal(e)
	}
	stage := filepath.Join(t.TempDir(), "restored")
	if _, e := Restore(t.Context(), p, c.IdentityFile, stage, c.MaxBytes); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(filepath.Join(stage, "manifest.json"))
	if e != nil {
		t.Fatal(e)
	}
	var original Manifest
	if e = json.Unmarshal(b, &original); e != nil {
		t.Fatal(e)
	}
	for _, mode := range []string{"traversal", "tenant-missing", "checksum"} {
		t.Run(mode, func(t *testing.T) {
			m := original
			m.Files = append([]File{}, original.Files...)
			switch mode {
			case "traversal":
				m.Files[0].Path = "../escaped.db"
			case "tenant-missing":
				m.Files = append(m.Files[:1], m.Files[2:]...)
			case "checksum":
				m.Files[0].SHA256 = strings.Repeat("0", 64)
			}
			// Traversal path is needed only as an archive source, never as a restore target.
			if mode == "traversal" {
				data, _ := os.ReadFile(filepath.Join(stage, "databases/root.db"))
				os.WriteFile(filepath.Join(stage, "../escaped.db"), data, 0600)
			}
			bad := filepath.Join(c.OutputDir, mode+".age")
			f, _ := os.Create(bad)
			id, _ := identity(c.IdentityFile)
			e := writeArchive(t.Context(), f, id.Recipient(), stage, m)
			f.Close()
			if e != nil {
				t.Fatal(e)
			}
			if _, e = Verify(t.Context(), bad, c.IdentityFile, c.OutputDir, c.MaxBytes); e == nil {
				t.Fatal("invalid recovery set accepted")
			}
		})
	}
}

func TestWorkerQueueScheduleRetentionAndRecovery(t *testing.T) {
	c, s := fixture(t)
	ctx := t.Context()
	if e := SaveSchedule(ctx, s, Schedule{Time: "03:30", Timezone: "Europe/Moscow", Keep: 2}); e != nil {
		t.Fatal(e)
	}
	requestID := uuid.NewString()
	id, e := Request(ctx, s, "backup", "", requestID, "admin")
	if e != nil {
		t.Fatal(e)
	}
	again, e := Request(ctx, s, "backup", "", requestID, "admin")
	if e != nil || again != id {
		t.Fatal("duplicate request", again, e)
	}
	first, e := Process(ctx, c, false)
	if e != nil || first == nil || first.ID != id || first.State != "succeeded" {
		t.Fatal("worker", first, e)
	}
	if _, e = Request(ctx, s, "verify", id, uuid.NewString(), "admin"); e != nil {
		t.Fatal(e)
	}
	verified, e := Process(ctx, c, false)
	if e != nil || verified.Kind != "verify" || verified.Report.Databases != 2 {
		t.Fatal("verification", verified, e)
	}
	// Final archive survives a crash between promotion and recording success.
	if e = s.Exec(ctx, "UPDATE backup_jobs SET state='running' WHERE id=?", id); e != nil {
		t.Fatal(e)
	}
	if _, e = Process(ctx, c, false); e != nil {
		t.Fatal(e)
	}
	var recovered string
	s.Row(ctx, "SELECT state FROM backup_jobs WHERE id=?", id).Scan(&recovered)
	if recovered != "succeeded" {
		t.Fatal("promoted archive not reconciled", recovered)
	}
	keyBytes, e := os.ReadFile(c.IdentityFile)
	if e != nil {
		t.Fatal(e)
	}
	os.WriteFile(c.IdentityFile, []byte("invalid key"), 0600)
	if _, e = Process(ctx, c, true); e == nil {
		t.Fatal("invalid backup key accepted")
	}
	nameBefore, _ := archiveName(id)
	if _, e = os.Stat(filepath.Join(c.OutputDir, nameBefore)); e != nil {
		t.Fatal("failed backup deleted last good archive", e)
	}
	os.WriteFile(c.IdentityFile, keyBytes, 0600)
	// Timestamps order retention deterministically even with multiple fast runs in one second.
	s.Exec(ctx, "UPDATE backup_jobs SET finished_at=1 WHERE id=?", id)
	for i := 0; i < 2; i++ {
		j, e := Process(ctx, c, true)
		if e != nil || j.State != "succeeded" {
			t.Fatal("backup", j, e)
		}
	}
	var state string
	if e = s.Row(ctx, "SELECT state FROM backup_jobs WHERE id=?", id).Scan(&state); e != nil || state != "pruned" {
		t.Fatal("retention", state, e)
	}
	name, _ := archiveName(id)
	if _, e = os.Stat(filepath.Join(c.OutputDir, name)); !os.IsNotExist(e) {
		t.Fatal("old archive retained")
	}
	// A dead worker is marked failed; unverified staging is discarded, never promoted.
	s.Exec(ctx, "INSERT INTO backup_jobs(id,kind,request_key,actor,state,created_at) VALUES('interrupted','backup','old','cli','running',1)")
	os.Mkdir(filepath.Join(c.OutputDir, ".capture-abandoned"), 0700)
	if _, e = Process(ctx, c, false); e != nil {
		t.Fatal(e)
	}
	s.Row(ctx, "SELECT state FROM backup_jobs WHERE id='interrupted'").Scan(&state)
	if state != "failed" {
		t.Fatal("crash not recovered")
	}
	lock, e := os.OpenFile(filepath.Join(c.OutputDir, ".worker.lock"), os.O_RDWR, 0600)
	if e != nil {
		t.Fatal(e)
	}
	defer lock.Close()
	unix.Flock(int(lock.Fd()), unix.LOCK_EX)
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	if _, e = Process(ctx, c, true); e == nil {
		t.Fatal("concurrent worker allowed")
	}
}

func TestScheduleNoDuplicatesOrOldCatchup(t *testing.T) {
	_, s := fixture(t)
	ctx := t.Context()
	v := Schedule{Enabled: true, Time: "03:30", Timezone: "Europe/Moscow", Keep: 2}
	now := time.Date(2026, 10, 31, 1, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		if e := scheduleDue(ctx, s, v, now); e != nil {
			t.Fatal(e)
		}
	}
	var n int
	s.Row(ctx, "SELECT COUNT(*) FROM backup_jobs").Scan(&n)
	if n != 1 {
		t.Fatal("duplicate schedule", n)
	}
	s.Exec(ctx, "UPDATE backup_jobs SET state='failed'")
	if e := scheduleDue(ctx, s, v, now.Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	s.Row(ctx, "SELECT COUNT(*) FROM backup_jobs").Scan(&n)
	if n != 1 {
		t.Fatal("failed job automatically duplicated")
	}
	if e := scheduleDue(ctx, s, v, now.Add(35*time.Hour)); e != nil {
		t.Fatal(e)
	}
	s.Row(ctx, "SELECT COUNT(*) FROM backup_jobs").Scan(&n)
	if n != 1 {
		t.Fatal("old schedule caught up")
	}
	if e := scheduleDue(ctx, s, v, now.Add(24*time.Hour)); e != nil {
		t.Fatal(e)
	}
	s.Row(ctx, "SELECT COUNT(*) FROM backup_jobs").Scan(&n)
	if n != 2 {
		t.Fatal("next day not scheduled")
	}
	if (Schedule{Time: "25:00", Timezone: "Local", Keep: 1}).Validate() == nil {
		t.Fatal("invalid schedule")
	}
}

func TestRecoveryVerifiesAdminMFASecrets(t *testing.T) {
	c, s := fixture(t)
	ctx := t.Context()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	v, _ := auth.NewVault(key)
	if e := s.Admin(ctx, "admin", "test-password-123", false); e != nil {
		t.Fatal(e)
	}
	if e := s.Exec(ctx, "UPDATE admins SET mfa_secret=?,mfa_pending=? WHERE username='admin'", v.Seal([]byte("active"), "admin-totp:admin"), v.Seal([]byte("pending"), "admin-totp:admin")); e != nil {
		t.Fatal(e)
	}
	report, e := Create(ctx, c, filepath.Join(c.OutputDir, "admin-mfa.age"))
	if e != nil {
		t.Fatal(e)
	}
	if report.Secrets != 4 {
		t.Fatal(report)
	}
	if e = s.Exec(ctx, "UPDATE admins SET mfa_secret=? WHERE username='admin'", v.Seal([]byte("wrong-context"), "admin-totp:someone-else")); e != nil {
		t.Fatal(e)
	}
	if _, e = Create(ctx, c, filepath.Join(c.OutputDir, "invalid-mfa.age")); e == nil {
		t.Fatal("undecryptable MFA backup accepted")
	}
}

func TestRecoveryVerifiesGuestOIDCSecret(t *testing.T) {
	c, s := fixture(t)
	ctx := t.Context()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	v, _ := auth.NewVault(key)
	if e := s.Exec(ctx, "INSERT INTO guest_oidc_providers(scope,id,config,secret,revision) VALUES('tenant','oidc','{}',?,'rev1')", v.Seal([]byte("client-secret"), "guest-oidc:tenant:oidc")); e != nil {
		t.Fatal(e)
	}
	report, e := Create(ctx, c, filepath.Join(c.OutputDir, "guest-oidc.age"))
	if e != nil {
		t.Fatal(e)
	}
	if report.Secrets != 3 {
		t.Fatal(report)
	}
	if e = s.Exec(ctx, "UPDATE guest_oidc_providers SET secret=?", v.Seal([]byte("wrong-context"), "guest-oidc:other:oidc")); e != nil {
		t.Fatal(e)
	}
	if _, e = Create(ctx, c, filepath.Join(c.OutputDir, "invalid-oidc.age")); e == nil {
		t.Fatal("undecryptable OIDC secret accepted")
	}
}
