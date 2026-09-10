package web

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"

	"qnapfilemanager/internal/audit"
	"qnapfilemanager/internal/config"
)

// requireAdmin gates the settings and audit routes. A non-admin session gets
// 403; the check is the same one /api/diag uses.
func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request, sess *session) bool {
	if sess == nil || !sess.admin {
		s.fail(w, r, "permission", "Administrator access is required.", "", "")
		return false
	}
	return true
}

// getSettings returns the settings the UI can render and change. For M1 that is
// the global read-only switch.
func (s *Server) getSettings(w http.ResponseWriter, r *http.Request, sess *session) {
	if !s.requireAdmin(w, r, sess) {
		return
	}
	writeJSON(w, map[string]any{"readOnly": s.readOnly()})
}

// postSettings toggles read-only mode. Turning it OFF is the moment writes
// become possible on a root daemon, so it is admin-only and always audited as a
// milestone (mirrored to QuLog). The new value drives the guard immediately and
// is persisted to the config file when one is known.
func (s *Server) postSettings(w http.ResponseWriter, r *http.Request, sess *session) {
	if !s.requireAdmin(w, r, sess) {
		return
	}
	var body struct {
		ReadOnly *bool `json:"readOnly"`
	}
	if !s.decodeBody(w, r, &body) {
		return
	}
	if body.ReadOnly == nil {
		s.fail(w, r, "bad_request", "Supply readOnly as true or false.", "", "")
		return
	}
	newVal := *body.ReadOnly

	// Persist first, then flip the live guard, so a save failure leaves the
	// running state and the file agreeing. Serialised so two toggles cannot
	// interleave their read-modify-write of the config.
	if s.ConfigPath != "" {
		s.cfgMu.Lock()
		c := s.cfg
		c.ReadOnly = newVal
		err := config.Save(s.ConfigPath, c)
		if err == nil {
			s.cfg.ReadOnly = newVal
		}
		s.cfgMu.Unlock()
		if err != nil {
			s.fail(w, r, "internal", "The setting could not be saved.", "", err.Error())
			return
		}
	}
	if s.guard != nil {
		s.guard.SetReadOnly(newVal)
	}
	if s.auditor != nil {
		s.auditor.Write(audit.Event{
			Actor: sess.who.User, UID: sess.who.UID, Admin: sess.admin, Root: sess.who.Root,
			IP: ClientIP(r), Op: "readonly", Phase: "result", Result: "ok",
			Detail: fmt.Sprintf("readOnly=%v", newVal), ForceMilestone: true,
		})
	}
	writeJSON(w, map[string]any{"readOnly": newVal})
}

// auditTail returns the last n audit events (default 200, capped at 1000) as
// JSON, newest last, for the settings audit-log view. Admin only.
func (s *Server) auditTail(w http.ResponseWriter, r *http.Request, sess *session) {
	if !s.requireAdmin(w, r, sess) {
		return
	}
	n := 200
	if raw := r.URL.Query().Get("n"); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil || v < 1 {
			s.fail(w, r, "bad_request", "n must be a positive integer.", "", "")
			return
		}
		n = v
	}
	if n > 1000 {
		n = 1000
	}
	events := []audit.Event{}
	if s.auditor != nil {
		got, err := s.auditor.Tail(n)
		if err != nil {
			s.fail(w, r, "internal", "The audit log could not be read.", "", err.Error())
			return
		}
		if got != nil {
			events = got
		}
	}
	writeJSON(w, events)
}

// auditExport streams the raw JSON-lines audit file as a download. Admin only.
func (s *Server) auditExport(w http.ResponseWriter, r *http.Request, sess *session) {
	if !s.requireAdmin(w, r, sess) {
		return
	}
	var f *os.File
	if s.AuditPath != "" {
		opened, err := os.Open(s.AuditPath)
		if err != nil && !os.IsNotExist(err) {
			s.fail(w, r, "internal", "The audit log could not be opened.", "", err.Error())
			return
		}
		f = opened // nil when the file does not exist yet: an empty download.
	}
	w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="audit.jsonl"`)
	w.Header().Set("Cache-Control", "no-store")
	if f == nil {
		return
	}
	defer f.Close()
	_, _ = io.Copy(w, f)
}
