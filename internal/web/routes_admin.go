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
//
// PLAN decision 7 called for a password challenge before read-only may be
// disabled. That decision predates the QTS-session identity model (decision 3),
// under which this app has no password of its own — an admin is authenticated by
// their live QTS desktop session, not by a credential we hold. There is nothing
// to re-challenge against, so the deliberate deviation here is: admin session +
// CSRF + Origin + a forced milestone audit line gate the toggle instead. A
// break-glass password exists only on the separate TLS listener (decision 3),
// not on this route.
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

	// The ENTIRE read-only transition is serialised under cfgMu and the lock is
	// never released mid-transition (standard P1 / adv 1/8). The order is fixed:
	//
	//  1. record the toggle INTENT durably, BEFORE any write becomes possible;
	//  2. persist the new value (config.Save);
	//  3. apply it to the live guard;
	//  4. record the result durably.
	//
	// So the moment writes become possible on a root daemon can never precede a
	// durable record of it (a crash in between still leaves the intent), and two
	// concurrent admin toggles cannot interleave: whichever takes the lock runs the
	// whole transition to completion before the other begins, so the persisted
	// value, the live guard and the audited result always agree. Rollback (step 4
	// failure) uses prevVal captured inside this same held lock — never a stale
	// snapshot read after the lock was dropped — and reports its own persistence
	// error rather than ignoring it.
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	prevVal := s.cfg.ReadOnly
	if s.guard != nil {
		prevVal = s.guard.ReadOnly()
	}

	auditResult := func(result, code, detail string) error {
		if s.auditor == nil {
			return nil
		}
		return s.auditor.WriteSync(r.Context(), audit.Event{
			Actor: sess.who.User, UID: sess.who.UID, Admin: sess.admin, Root: sess.who.Root,
			IP: ClientIP(r), Op: "readonly", Phase: "result", Result: result, Code: code,
			Detail: detail, ForceMilestone: true,
		})
	}

	// 1. Durably record the INTENT before enabling any write. If it cannot be
	//    persisted, refuse and change nothing (adv 1).
	if s.auditor != nil {
		if err := s.auditor.WriteSync(r.Context(), audit.Event{
			Actor: sess.who.User, UID: sess.who.UID, Admin: sess.admin, Root: sess.who.Root,
			IP: ClientIP(r), Op: "readonly", Phase: "intent",
			Detail: fmt.Sprintf("readOnly=%v", newVal), ForceMilestone: true,
		}); err != nil {
			s.fail(w, r, "audit_unavailable", "The change was refused: its audit record could not be saved.", "", err.Error())
			return
		}
	}

	// 2. Persist. Nothing is applied yet, so a save failure leaves the live guard
	//    and the file untouched; record the failure durably (adv 10) and refuse.
	if s.ConfigPath != "" {
		c := s.cfg
		c.ReadOnly = newVal
		if err := config.Save(s.ConfigPath, c); err != nil {
			_ = auditResult("error", "internal", fmt.Sprintf("save failed: %v", err))
			s.fail(w, r, "internal", "The setting could not be saved.", "", err.Error())
			return
		}
		s.cfg.ReadOnly = newVal
	}

	// 3. Apply to the live guard, now that the intent is durable and the file
	//    written.
	if s.guard != nil {
		s.guard.SetReadOnly(newVal)
	}

	// 4. Record the result durably. If even this fails, revert everything to
	//    prevVal (captured under this same still-held lock) and refuse, so the
	//    file, the live guard and the audit trail still agree that the change did
	//    not take effect. A rollback save error is logged, not swallowed.
	if err := auditResult("ok", "", fmt.Sprintf("readOnly=%v", newVal)); err != nil {
		if s.guard != nil {
			s.guard.SetReadOnly(prevVal)
		}
		if s.ConfigPath != "" {
			c := s.cfg
			c.ReadOnly = prevVal
			if serr := config.Save(s.ConfigPath, c); serr != nil {
				s.logger.Printf("settings rollback: could not restore readOnly=%v after an audit failure: %v", prevVal, serr)
			} else {
				s.cfg.ReadOnly = prevVal
			}
		}
		s.fail(w, r, "audit_unavailable", "The change was refused: its audit record could not be saved.", "", err.Error())
		return
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
