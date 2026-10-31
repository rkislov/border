// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package web

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/rkislov/border/internal/backup"
)

func (a *app) backupRoutes(m *http.ServeMux) {
	// A tenant administrator cannot export the platform master key or other tenants.
	if a.platform == nil {
		return
	}
	downloadDir := ""
	if p, ok := a.platform.(interface{ BackupDownloadDirectory() string }); ok {
		downloadDir = p.BackupDownloadDirectory()
	}
	if !filepath.IsAbs(downloadDir) || filepath.Clean(downloadDir) != downloadDir || downloadDir == "/" {
		downloadDir = ""
	}
	downloadSlots := make(chan struct{}, 2)
	m.HandleFunc("GET /api/backups", func(w http.ResponseWriter, r *http.Request) {
		v, e := backup.ReadStatus(r.Context(), a.s)
		if e != nil {
			http.Error(w, "backup status unavailable", 503)
			return
		}
		v.Files.DownloadsReady = downloadDir != "" && v.Files.DownloadTarget == backup.DownloadTarget(downloadDir)
		reply(w, v)
	})
	m.HandleFunc("POST /api/backups/downloads", func(w http.ResponseWriter, r *http.Request) {
		var v struct{ BackupID string }
		if !decode(w, r, &v) {
			return
		}
		id, e := backup.RequestDownload(r.Context(), a.s, v.BackupID, downloadDir, requestAccount(r).Username)
		if e != nil {
			http.Error(w, e.Error(), 400)
			return
		}
		reply(w, map[string]string{"ID": id})
	})
	m.HandleFunc("POST /api/backups/file-export", func(w http.ResponseWriter, r *http.Request) {
		var v struct{ Enabled bool }
		if !decode(w, r, &v) {
			return
		}
		if e := backup.SaveFileExportEnabled(r.Context(), a.s, v.Enabled); e != nil {
			http.Error(w, e.Error(), 400)
			return
		}
		a.finish(w, r, nil, "update backup file export")
	})
	m.HandleFunc("POST /api/backups/file-jobs/action", func(w http.ResponseWriter, r *http.Request) {
		var v struct{ ID, Action string }
		if !decode(w, r, &v) {
			return
		}
		if e := backup.ChangeFileJob(r.Context(), a.s, v.ID, v.Action, downloadDir); e != nil {
			http.Error(w, e.Error(), 400)
			return
		}
		a.finish(w, r, nil, "backup file transfer "+v.Action+" "+v.ID)
	})
	m.HandleFunc("GET /api/backups/downloads/{id}", func(w http.ResponseWriter, r *http.Request) {
		j, e := backup.FileJobByID(r.Context(), a.s, r.PathValue("id"))
		if e != nil || downloadDir == "" || j.Kind != "download" || j.State != "succeeded" || j.Target != backup.DownloadTarget(downloadDir) || j.ExpiresAt <= time.Now().Unix() {
			http.Error(w, "download unavailable or expired", 404)
			return
		}
		select {
		case downloadSlots <- struct{}{}:
			defer func() { <-downloadSlots }()
		default:
			http.Error(w, "too many downloads", 429)
			return
		}
		// Override the normal 15-second API write deadline only for archive streaming.
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(30 * time.Minute))
		f, e := backup.OpenDownload(r.Context(), downloadDir, j)
		if e != nil {
			http.Error(w, "archive integrity check failed; prepare the download again", 409)
			return
		}
		defer f.Close()
		name := "backup-" + j.BackupID + ".tar.gz.age"
		w.Header().Set("Cache-Control", "private, no-store")
		w.Header().Set("ETag", `"`+j.SHA256+`"`)
		if r.URL.Query().Get("checksum") == "1" {
			name += ".sha256"
			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			http.ServeContent(w, r, name, time.Unix(j.VerifiedAt, 0), strings.NewReader(j.SHA256+"  "+strings.TrimSuffix(name, ".sha256")+"\n"))
			return
		}
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
		w.Header().Set("Content-Type", "application/octet-stream")
		digest, e := hex.DecodeString(j.SHA256)
		if e != nil {
			http.Error(w, "invalid archive checksum", 500)
			return
		}
		w.Header().Set("Repr-Digest", "sha-256=:"+base64.StdEncoding.EncodeToString(digest)+":")
		w.Header().Set("X-Archive-SHA256", j.SHA256)
		http.ServeContent(w, r, name, time.Unix(j.VerifiedAt, 0), f)
	})
	m.HandleFunc("POST /api/backups/schedule", func(w http.ResponseWriter, r *http.Request) {
		var v backup.Schedule
		if !decode(w, r, &v) {
			return
		}
		if e := backup.SaveSchedule(r.Context(), a.s, v); e != nil {
			http.Error(w, e.Error(), 400)
			return
		}
		a.finish(w, r, nil, "update backup schedule")
	})
	m.HandleFunc("POST /api/backups/jobs", func(w http.ResponseWriter, r *http.Request) {
		var v struct{ Kind, SourceID, RequestID string }
		if !decode(w, r, &v) {
			return
		}
		id, e := backup.Request(r.Context(), a.s, v.Kind, v.SourceID, v.RequestID, requestAccount(r).Username)
		if e != nil {
			http.Error(w, e.Error(), 400)
			return
		}
		reply(w, map[string]string{"ID": id})
	})
}
