package web

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/guard"
	"qnapfilemanager/internal/platform"
)

// guardRead enforces the guard's READ denials on the REQUESTED (cleaned) path
// before a read handler dispatches, so the file manager's own installation
// config (which holds the break-glass password hash) and its logs (the audit
// trail) — declared as OpRead|OpTraverse denials in guard/rules.go — cannot be
// read back through the ordinary list/stat/text/download endpoints (standard P2).
// Any guard denial maps to 403 protected. A nil guard (read-only fixtures) is a
// no-op, and on a normal path Check(OpRead/OpTraverse) returns nil, so ordinary
// reads are untouched.
//
// Reads deliberately check the requested path ONLY — no Resolve round-trip — so
// the read path stays fast. Alias-bypass on reads (reaching a protected read
// region through a symlink whose resolved target the requested spelling hides) is
// an ACCEPTED low-severity residual: only a root-admin session runs as a
// principal that could open those files at all, and a root admin can read them
// over SSH regardless, so this closes no access a root admin does not already
// have. See PLAN.md (accepted safety residuals, M1).
func (s *Server) guardRead(w http.ResponseWriter, r *http.Request, p string, op guard.Op) bool {
	if s.guard == nil {
		return true
	}
	if err := s.guard.Check(op, p); err != nil {
		s.fail(w, r, "protected", "This location is protected and cannot be read.", p, "")
		return false
	}
	return true
}

func requestPath(r *http.Request) (string, error) {
	q := r.URL.Query()
	p := q.Get("path")
	if q.Has("pathB64") {
		raw, err := base64.RawURLEncoding.DecodeString(q.Get("pathB64"))
		if err != nil {
			raw, err = base64.StdEncoding.DecodeString(q.Get("pathB64"))
		}
		if err != nil {
			return "", fmt.Errorf("invalid pathB64: %w", fsx.ErrBadName)
		}
		p = string(raw)
	}
	for _, component := range strings.Split(p, "/") {
		if component == "." || component == ".." {
			return "", fmt.Errorf("path contains a dot component: %w", fsx.ErrBadName)
		}
	}
	return fsx.Clean(p)
}

func (s *Server) path(w http.ResponseWriter, r *http.Request) (string, bool) {
	p, err := requestPath(r)
	if err != nil {
		s.fail(w, r, "bad_request", "Supply an absolute path or a valid pathB64.", "", err.Error())
		return "", false
	}
	return p, true
}

func intQuery(r *http.Request, key string, def, max int) (int, error) {
	raw := r.URL.Query().Get(key)
	if raw == "" {
		return def, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 || (key != "offset" && n == 0) {
		return 0, fsx.ErrBadName
	}
	if n > max {
		n = max
	}
	return n, nil
}

func boolQuery(r *http.Request, key string) (bool, error) {
	raw := r.URL.Query().Get(key)
	if raw == "" {
		return false, nil
	}
	return strconv.ParseBool(raw)
}

func (s *Server) list(w http.ResponseWriter, r *http.Request, sess *session) {
	p, ok := s.path(w, r)
	if !ok {
		return
	}
	if !s.guardRead(w, r, p, guard.OpTraverse) {
		return
	}
	max := s.cfg.Limits.ListMax
	if max < 1 || max > fsx.MaxListLimit {
		max = fsx.MaxListLimit
	}
	offset, e1 := intQuery(r, "offset", 0, int(^uint(0)>>1))
	limit, e2 := intQuery(r, "limit", min(500, max), max)
	hidden, e3 := boolQuery(r, "hidden")
	volumes, e4 := boolQuery(r, "volumes")
	desc, e5 := boolQuery(r, "desc")
	sort := r.URL.Query().Get("sort")
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil || !fsx.ValidSortKey(sort) {
		s.fail(w, r, "bad_request", "Invalid listing options.", p, "")
		return
	}
	listing, err := s.backend.List(r.Context(), sess.who, p, fsx.ListOptions{Offset: offset, Limit: limit, Sort: sort, Desc: desc, ShowHidden: hidden, ShowVolumeRoots: volumes, ResolveLinks: true})
	if err != nil {
		s.backendError(w, r, p, err)
		return
	}
	listing.Class = s.class(p)
	if listing.Entries == nil {
		listing.Entries = []fsx.Entry{}
	}
	for i := range listing.Entries {
		listing.Entries[i].Class = s.class(listing.Entries[i].Path)
	}
	if p == "/share" && s.ramShare() {
		listing.Notes = append(listing.Notes, "/share is a RAM disk. Store files in a shared folder, not directly here; files here disappear on reboot.")
	}
	writeJSON(w, struct {
		fsx.Listing
		Limit int `json:"limit"`
	}{Listing: listing, Limit: limit})
}

func (s *Server) ramShare() bool {
	m, ok := s.platform.MountFor("/share")
	return ok && m.MountPoint == "/share" && m.FSType == "tmpfs"
}

// Display hints only. M1's guard will own enforcement and richer classification.
func (s *Server) class(p string) string {
	for _, prefix := range []string{"/proc", "/sys", "/dev", "/etc", "/bin", "/sbin", "/lib", "/lib64", "/usr", "/var", "/root"} {
		if fsx.IsWithin(p, prefix) {
			return "protected"
		}
	}
	if fsx.IsWithin(p, "/mnt") || p == "/share" && s.ramShare() {
		return "warn"
	}
	return "normal"
}

func (s *Server) stat(w http.ResponseWriter, r *http.Request, sess *session) {
	p, ok := s.path(w, r)
	if !ok {
		return
	}
	if !s.guardRead(w, r, p, guard.OpRead) {
		return
	}
	entry, err := s.backend.Stat(r.Context(), sess.who, p)
	if err != nil {
		s.backendError(w, r, p, err)
		return
	}
	entry.Class = s.class(p)
	writeJSON(w, entry)
}

func (s *Server) roots(w http.ResponseWriter, r *http.Request, sess *session) {
	entries := []fsx.Entry{}
	seen := map[string]bool{}
	add := func(e fsx.Entry) {
		if !seen[e.Path] {
			e.Class = s.class(e.Path)
			entries = append(entries, e)
			seen[e.Path] = true
		}
	}
	for _, p := range []string{"/", "/share"} {
		add(fsx.Entry{Name: p, Path: p, Type: "dir"})
	}
	for offset := 0; ; {
		page, err := s.backend.List(r.Context(), sess.who, "/share", fsx.ListOptions{Offset: offset, Limit: 500, ShowHidden: true, ShowVolumeRoots: true, ResolveLinks: true, Sort: "name"})
		if err != nil {
			break
		} // Fixed jumps remain useful when /share is inaccessible.
		for _, e := range page.Entries {
			if e.IsSymlink || e.Type == "symlink" {
				e.ShareLink = true
				add(e)
			}
		}
		offset += len(page.Entries)
		if len(page.Entries) == 0 || offset >= page.Total {
			break
		}
	}
	for _, m := range s.platform.VolumeRoots() {
		add(fsx.Entry{Name: fsx.Base(m.MountPoint), Path: m.MountPoint, Type: "dir", MountPoint: true, VolumeRoot: true})
	}
	for _, p := range []string{"/etc", "/etc/config"} {
		add(fsx.Entry{Name: p, Path: p, Type: "dir"})
	}
	writeJSON(w, entries)
}

func (s *Server) download(w http.ResponseWriter, r *http.Request, sess *session) {
	p, ok := s.path(w, r)
	if !ok {
		return
	}
	if !s.guardRead(w, r, p, guard.OpRead) {
		return
	}
	f, e, err := s.backend.OpenRead(r.Context(), sess.who, p)
	if err != nil {
		s.backendError(w, r, p, err)
		return
	}
	defer f.Close()
	name := fsx.Base(p)
	ascii := strings.Map(func(c rune) rune {
		if c < 32 || c > 126 || c == '"' || c == '\\' || c == ';' {
			return '_'
		}
		return c
	}, name)
	if ascii == "" {
		ascii = "download"
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+ascii+`"; filename*=UTF-8''`+strings.ReplaceAll(url.QueryEscape(strings.ToValidUTF8(name, "_")), "+", "%20"))
	// procfs/sysfs may report zero or misleading lengths, or reject SEEK_END.
	stream := pseudoFilesystem(f) || e.Size == 0
	if !stream {
		size, seekErr := f.Seek(0, io.SeekEnd)
		stream = seekErr != nil || size != e.Size
		// A failed SEEK_END on an unseekable descriptor leaves its offset alone.
		// A successful one must be rewound before either response path reads it.
		if _, resetErr := f.Seek(0, io.SeekStart); resetErr != nil && seekErr == nil {
			s.backendError(w, r, p, resetErr)
			return
		}
	}
	if stream {
		if r.Method != http.MethodHead {
			streamFile, err := prepareDownloadStream(f)
			if err != nil {
				s.backendError(w, r, p, err)
				return
			}
			f = streamFile
			defer f.Close()
		}
		w.WriteHeader(http.StatusOK) // Ignore Range for streams of unknown length.
		// Flush headers so net/http cannot infer Content-Length for a short body.
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		if r.Method == http.MethodHead {
			return
		}
		ctx := r.Context()
		copyDone := make(chan struct{})
		defer close(copyDone)
		go func() {
			select {
			case <-ctx.Done():
				// Close wakes reads registered with the runtime poller.
				_ = f.Close()
			case <-copyDone:
			}
		}()
		_, _ = io.Copy(w, downloadReader{ctx: ctx, reader: f})
		return
	}
	http.ServeContent(w, r, name, e.MTime, f)
}

// Hide WriterTo so every copy read checks cancellation, including regular files.
type downloadReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r downloadReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

func (s *Server) text(w http.ResponseWriter, r *http.Request, sess *session) {
	p, ok := s.path(w, r)
	if !ok {
		return
	}
	if !s.guardRead(w, r, p, guard.OpRead) {
		return
	}
	limit := s.cfg.Limits.MaxTextBytes
	if limit < 1 {
		limit = 2 << 20
	}
	if raw := r.URL.Query().Get("max"); raw != "" {
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || n < 1 {
			s.fail(w, r, "bad_request", "Invalid text limit.", p, "")
			return
		}
		limit = min(limit, n)
	}
	f, e, err := s.backend.OpenRead(r.Context(), sess.who, p)
	if err != nil {
		s.backendError(w, r, p, err)
		return
	}
	defer f.Close()
	streamFile, err := prepareDownloadStream(f)
	if err != nil {
		s.backendError(w, r, p, err)
		return
	}
	defer streamFile.Close()
	ctx := r.Context()
	readDone, closed := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(closed)
		select {
		case <-ctx.Done():
		case <-readDone:
		}
		// Wake a blocked pollable read on cancellation, and release the stream
		// as soon as EOF or the byte cap ends the read.
		_ = streamFile.Close()
	}()
	// Probe at least 8 KiB even when the requested preview is smaller.
	data, err := io.ReadAll(io.LimitReader(downloadReader{ctx: ctx, reader: streamFile}, max(limit+1, 8192)))
	close(readDone)
	<-closed
	interrupted := ctx.Err() != nil
	if err != nil && !interrupted {
		s.backendError(w, r, p, err)
		return
	}
	binary := bytes.IndexByte(data[:min(len(data), 8192)], 0) >= 0
	truncated := int64(len(data)) > limit || interrupted
	content := data[:min(int64(len(data)), limit)]
	etag := fmt.Sprintf(`W/"%x"`, sha256.Sum256([]byte(fmt.Sprintf("%s:%d:%d", p, e.Size, e.MTime.UnixNano()))))
	writeJSON(w, map[string]any{"content": string(content), "bytes": len(content), "truncated": truncated, "binary": binary, "mode": e.Mode, "mtime": e.MTime, "etag": etag})
}

func (s *Server) identities(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Query().Get("kind") {
	case "users":
		writeJSON(w, s.ids.Users())
	case "groups":
		writeJSON(w, s.ids.Groups())
	default:
		s.fail(w, r, "bad_request", "Choose kind=users or kind=groups.", "", "")
	}
}

func (s *Server) isQTS() bool {
	return s.platform.Family == platform.FamilyQTS || s.platform.Family == platform.FamilyHero
}

func (s *Server) status(w http.ResponseWriter, r *http.Request, sess *session) {
	if err := s.backend.Ping(r.Context(), sess.who); err != nil {
		s.backendError(w, r, "", err)
		return
	}
	writeJSON(w, map[string]any{"version": s.version, "readOnly": s.readOnly(), "rootMode": false, "isQTS": s.isQTS(), "family": s.platform.Family, "qtsVersion": s.platform.Firmware})
}

func (s *Server) diag(w http.ResponseWriter, r *http.Request, sess *session) {
	if !sess.admin {
		s.fail(w, r, "permission", "Administrator access is required.", "", "")
		return
	}
	d := map[string]any{"platform": s.platform.Diag(), "pinnedPrincipal": s.pinned, "principal": sess.who, "version": s.version, "adminNote": sess.note}
	if b, ok := s.backend.(interface{ Stats() any }); ok {
		d["backend"] = b.Stats()
	}
	writeJSON(w, d)
}
