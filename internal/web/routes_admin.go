package web

import (
	"context"
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
// reconcileReadOnly decides the value the live guard (and in-memory config) must
// take after a settings-toggle rollback whose config.Save returned saveErr. It
// exists so the guard and the persisted config can never disagree in ANY failure
// combination (round-7/8 reviews):
//
//   - saveErr == nil: the file now holds `want` (prevVal); use it.
//   - saveErr != nil: "save failed" does NOT imply "file unchanged" — config.Save
//     writes a temp file and renames it, so the rename can land (the file already
//     holds `want`) while a later SyncDir or Chmod errors. Guessing would risk
//     setting the guard opposite to the file, so re-read the file and match its
//     actual value. If the re-read ALSO fails, the on-disk state is unknowable, so
//     fail CLOSED (read-only on, writes blocked) and rely on the caller's log.
//
// load and logf are injected so the branches are unit-testable without forcing a
// post-rename failure inside config.Save.
func reconcileReadOnly(path string, want bool, saveErr error, load func(string) (config.Config, error), logf func(string, ...any)) bool {
	if saveErr == nil {
		return want
	}
	if loaded, lerr := load(path); lerr == nil {
		logf("settings rollback: save failed (%v); reconciled guard to the on-disk readOnly=%v", saveErr, loaded.ReadOnly)
		return loaded.ReadOnly
	} else {
		logf("settings rollback: save failed (%v) and reload failed (%v); guard forced read-only (fail-closed)", saveErr, lerr)
		return true
	}
}

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
		// The result records the FINAL applied state of the toggle (the guard was
		// already flipped and the file already written before "ok" is recorded), so
		// it must survive the client disconnecting. Persist it with a
		// cancellation-immune context: were it request-scoped, a cancel after the
		// writer was admitted but before its fsync completed would return
		// context.Canceled while the goroutine still durably wrote "ok", and this
		// function would then roll the guard and file back to prevVal — leaving the
		// durable audit trail contradicting both live values (round-5 adv 1).
		// WriteSync's own writeSyncTimeout still bounds the wait.
		return s.auditor.WriteSync(context.WithoutCancel(r.Context()), audit.Event{
			Actor: sess.who.User, UID: sess.who.UID, Admin: sess.admin, Root: sess.who.Root,
			IP: ClientIP(r), Door: sess.door, Op: "readonly", Phase: "result", Result: result, Code: code,
			Detail: detail, ForceMilestone: true,
		})
	}

	// 1. Durably record the INTENT before enabling any write. If it cannot be
	//    persisted, refuse and change nothing (adv 1).
	if s.auditor != nil {
		if err := s.auditor.WriteSync(r.Context(), audit.Event{
			Actor: sess.who.User, UID: sess.who.UID, Admin: sess.admin, Root: sess.who.Root,
			IP: ClientIP(r), Door: sess.door, Op: "readonly", Phase: "intent",
			Detail: fmt.Sprintf("readOnly=%v", newVal), ForceMilestone: true,
		}); err != nil {
			s.fail(w, r, "audit_unavailable", "The change was refused: its audit record could not be saved.", "", err.Error())
			return
		}
	}

	// 2. Persist. A save FAILURE does not imply the file is untouched — config.Save
	//    renames a temp file into place, so the rename can land (the file now holds
	//    newVal) before a later SyncDir/Chmod errors (round-10). The guard has not
	//    been flipped yet, so on failure reconcile it and s.cfg to whatever is
	//    ACTUALLY on disk (re-read; fail-closed if unreadable) before refusing, so
	//    the guard and the config can never disagree even on this early-return path,
	//    exactly as the rollback path does.
	//
	//    The value written is a READ-MODIFY-WRITE of the file, never s.cfg
	//    (round-1 P1-3). s.cfg is the snapshot this process started with, and
	//    `qnapfilemanager break-glass set-password` writes auth.local into the
	//    same file from a different process: persisting the snapshot whole would
	//    silently revert a password the operator had just set — or, worse,
	//    restore one they had just disabled — as a side effect of flipping a
	//    switch that has nothing to do with it. Only ReadOnly is ours to change
	//    here; the daemon never writes auth.local at all.
	//
	//    The whole read-modify-write runs under config.Update's CROSS-PROCESS
	//    lock, because `qnapfilemanager break-glass` writes the same file from
	//    another process and nothing else makes the pair atomic (round-2 P3-5).
	//    LoadDev's relaxations travel with it: a daemon started with -dev on an
	//    auth.mode "local" configuration must still be able to save it
	//    (round-2 P3-6).
	if s.ConfigPath != "" {
		if err := config.Update(s.ConfigPath, s.Dev, func(c *config.Config) error {
			c.ReadOnly = newVal
			return nil
		}); err != nil {
			effective := reconcileReadOnly(s.ConfigPath, prevVal, err, s.loadConfig, s.logger.Printf)
			s.cfg.ReadOnly = effective
			if s.guard != nil {
				s.guard.SetReadOnly(effective)
			}
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

	// 4. Record the result durably. If even this fails, revert to prevVal (captured
	//    under this same still-held lock) and refuse. The live guard is set to
	//    whatever value is ACTUALLY persisted, so the guard and the config can never
	//    disagree — even under a double failure (the audit sink wedged AND the
	//    rollback save itself failing), where newVal stays on disk and the guard is
	//    kept at newVal to match it rather than left contradicting the file
	//    (round-7 adv). The durable intent line from step 1 still records that a
	//    toggle was attempted; only the audit narrative can lag the live state
	//    (§2.6).
	if err := auditResult("ok", "", fmt.Sprintf("readOnly=%v", newVal)); err != nil {
		effective := prevVal
		if s.ConfigPath != "" {
			// The rollback re-reads too, for the same reason the write did: the
			// file may hold a credential this process has never seen.
			serr := config.Update(s.ConfigPath, s.Dev, func(c *config.Config) error {
				c.ReadOnly = prevVal
				return nil
			})
			effective = reconcileReadOnly(s.ConfigPath, prevVal, serr, s.loadConfig, s.logger.Printf)
		}
		s.cfg.ReadOnly = effective
		if s.guard != nil {
			s.guard.SetReadOnly(effective)
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

// loadConfig re-reads this daemon's own configuration file with the same
// validation mode it started under, so a -dev run's reconciliation reads the
// file rather than failing on it (round-2 P3-6).
func (s *Server) loadConfig(path string) (config.Config, error) {
	return config.LoadDev(path, s.Dev)
}
