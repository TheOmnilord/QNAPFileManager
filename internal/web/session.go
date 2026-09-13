package web

import (
	"container/list"
	"context"
	"crypto/rand"
	"errors"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"qnapfilemanager/internal/backend"
	"qnapfilemanager/internal/idmap"
	"qnapfilemanager/internal/qtsauth"
)

const (
	sessionTTL                = 12 * time.Hour
	qtsUnavailableGrace       = 5 * time.Minute
	DefaultMaxSessions        = 10000
	DefaultMaxSessionsPerUser = 16
)

var errSession = errors.New("invalid session")
var errSessionStoreFull = errors.New("session store full")
var errCSRF = errors.New("invalid CSRF token or origin")

func qtsUnavailable(err error) bool {
	var networkError net.Error
	return errors.Is(err, qtsauth.ErrUnreachable) || errors.Is(err, qtsauth.ErrBadResponse) ||
		errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &networkError) && networkError.Timeout())
}

type session struct {
	mu                      sync.Mutex
	id, csrf, binding, kind string
	who                     backend.Principal
	admin, partial          bool
	dead                    atomic.Bool
	authRequests            atomic.Int32
	// Index metadata is immutable after insertion; list links require Server.mu.
	user             string
	order, userOrder *list.Element
	note             string
	cred             qtsauth.Cred
	checked          time.Time
	unavailableSince time.Time // guarded by session.mu; reset only by successful validation
	expires          time.Time // guarded by Server.mu after insertion
}

func (s *Server) cookie(w http.ResponseWriter, r *http.Request, value string, age int) {
	p := s.cfg.Web.ProxyPrefix + "/"
	http.SetCookie(w, &http.Cookie{Name: "qfm_sid", Value: value, Path: p, MaxAge: age, HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"})
}

func (s *Server) destroy(id string) {
	s.mu.Lock()
	s.removeSessionLocked(s.sessions[id])
	s.mu.Unlock()
}

// removeSessionLocked never waits for a session undergoing QTS validation.
func (s *Server) removeSessionLocked(old *session) {
	if old == nil {
		return
	}
	old.dead.Store(true)
	delete(s.sessions, old.id)
	delete(s.archiveSelections, old.id)
	if s.byCredential[old.binding] == old {
		delete(s.byCredential, old.binding)
	}
	if old.order != nil {
		s.sessionOrder.Remove(old.order)
		users := s.byUser[old.user]
		users.Remove(old.userOrder)
		if users.Len() == 0 {
			delete(s.byUser, old.user)
		}
		old.order, old.userOrder = nil, nil
	}
}

func (s *Server) lookupSessionLocked(id, binding string) *session {
	s.sessionLookups++
	if id != "" {
		return s.sessions[id]
	}
	if binding != "" {
		return s.byCredential[binding]
	}
	return nil
}

// insertSession deduplicates concurrent first requests for the same credential.
// Both eviction queues are insertion ordered, not access ordered.
func (s *Server) insertSession(sess *session) *session {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess.binding != "" {
		if old := s.byCredential[sess.binding]; old != nil {
			if !s.reclaimExpiredLocked(old, time.Now()) {
				return old
			}
		}
	}
	if s.byCredential == nil {
		s.byCredential = make(map[string]*session)
		s.byUser = make(map[string]*list.List)
	}
	maxTotal, maxUser := s.MaxSessions, s.MaxSessionsPerUser
	if maxTotal <= 0 {
		maxTotal = DefaultMaxSessions
	}
	if maxUser <= 0 {
		maxUser = DefaultMaxSessionsPerUser
	}
	sess.user = sess.who.User
	// Sweep only under pressure, and never wait for a session doing network I/O.
	users := s.byUser[sess.user]
	if len(s.sessions) >= maxTotal || (users != nil && users.Len() >= maxUser) {
		now := time.Now()
		for _, old := range s.sessions {
			s.reclaimExpiredLocked(old, now)
		}
	}
	if users := s.byUser[sess.user]; users != nil && users.Len() >= maxUser {
		s.removeSessionLocked(users.Front().Value.(*session))
	}
	for len(s.sessions) >= maxTotal {
		users := s.byUser[sess.user]
		if users == nil || users.Len() == 0 {
			return nil // Never invalidate another identity's live session.
		}
		s.removeSessionLocked(users.Front().Value.(*session))
	}
	users = s.byUser[sess.user]
	if users == nil {
		users = new(list.List)
		s.byUser[sess.user] = users
	}
	sess.order = s.sessionOrder.PushBack(sess)
	sess.userOrder = users.PushBack(sess)
	s.sessions[sess.id] = sess
	if sess.binding != "" {
		s.byCredential[sess.binding] = sess
	}
	return sess
}

func (s *Server) reclaimExpiredLocked(old *session, now time.Time) bool {
	expired := !now.Before(old.expires)
	if expired {
		s.removeSessionLocked(old)
	}
	return expired
}

func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) (*session, error) {
	cred, hasCred := qtsauth.FromRequest(r)
	id, binding := "", ""
	if c, err := r.Cookie("qfm_sid"); err == nil {
		id = c.Value
	}
	if hasCred && s.pinned == nil {
		binding = qtsauth.CacheKey(cred)
	}
	s.mu.Lock()
	old := s.lookupSessionLocked(id, binding)
	s.mu.Unlock()
	var replaced *session
	if old != nil && s.pinned == nil && hasCred && binding != old.binding {
		if !safeMethod(r.Method) || r.URL.Path != "/api/session" {
			return nil, errSession
		}
		// Validate the new bootstrap credential before retiring the old session.
		// A rejected launch must not revoke the cookie's still-valid session.
		replaced, old = old, nil
	}
	if old != nil {
		return s.authenticateSession(w, r, old, cred, hasCred)
	}
	// Bootstrap through a safe request before accepting any session mutation.
	// An unsafe first request must not validate credentials or insert a session.
	if !safeMethod(r.Method) {
		return nil, errSession
	}
	if s.pinned == nil && !hasCred {
		return nil, nil
	}
	var stored *session
	var err error
	if s.pinned != nil {
		stored, err = s.createSession(r, cred)
	} else {
		stored, err = s.authAdmission.credential(r.Context(), binding, func() (*session, error) {
			// A previous leader may have inserted a session since the initial lookup.
			s.mu.Lock()
			existing := s.byCredential[binding]
			s.mu.Unlock()
			if existing != nil {
				return existing, nil
			}
			return s.createSession(r, cred)
		})
	}
	if err != nil {
		return nil, err
	}
	sess, err := s.authenticateSession(w, r, stored, cred, hasCred)
	if err == nil && replaced != nil {
		s.destroy(replaced.id)
	}
	return sess, err
}

func (s *Server) createSession(r *http.Request, cred qtsauth.Cred) (*session, error) {
	now := s.now()
	sess := &session{id: rand.Text(), csrf: rand.Text(), expires: now.Add(sessionTTL), checked: now}
	if s.pinned != nil {
		sess.who = *s.pinned
		sess.admin = idmap.IsLocalAdmin(idmap.Ident{Name: s.pinned.User, UID: s.pinned.UID, GID: s.pinned.GID, Groups: s.pinned.Groups}, s.ids)
	} else {
		if err := s.authenticateCredential(r, sess, cred); err != nil {
			return nil, err
		}
	}
	if err := r.Context().Err(); err != nil {
		return nil, err
	}
	stored := s.insertSession(sess)
	if stored == nil {
		return nil, errSessionStoreFull
	}
	return stored, nil
}

func (s *Server) authenticateCredential(r *http.Request, sess *session, cred qtsauth.Cred) error {
	if s.verifier == nil {
		return errSession
	}
	if err := s.authAdmission.enter(r.Context(), false); err != nil {
		return err
	}
	defer s.authAdmission.leave(false)
	verified, err := s.verifyCredential(r, cred, false)
	if err != nil {
		return err
	}
	ident, err := s.ids.Resolve(r.Context(), verified.User)
	if ctxErr := r.Context().Err(); ctxErr != nil {
		return ctxErr
	}
	if err != nil {
		return errSession
	}
	sess.who = principal(ident)
	sess.admin, sess.note = idmap.DecideAdmin(verified.IsAdmin(), ident, s.ids, s.cfg.Auth.AdminRequiresBoth)
	// An administrator operates as root, the way File Station does (owner
	// decision, 2026-09-10): the worker for an admin session runs as uid 0, so
	// it sees the whole filesystem. A non-admin keeps their own identity. The
	// guard's protected-path confirmations still apply to a root session.
	sess.who.Root = sess.admin
	sess.partial = ident.Partial
	sess.binding, sess.kind, sess.cred, sess.checked = qtsauth.CacheKey(cred), cred.Kind, cred, verified.ValidatedAt
	if sess.note != "" {
		s.logger.Printf("admin disagreement user=%q ip=%q: %s", ident.Name, ClientIP(r), sess.note)
	}
	return nil
}

func (s *Server) authenticateSession(w http.ResponseWriter, r *http.Request, old *session, cred qtsauth.Cred, hasCred bool) (*session, error) {
	// CSRF is immutable and bound to this session. Reject before waiting for
	// its lock or admitting any forced QTS revalidation.
	if !safeMethod(r.Method) && !validCSRF(r, old.csrf) {
		// Audit the rejected mutation before returning: a forged or stale
		// unsafe request must leave a denial line, not vanish silently (adv 10).
		s.auditAuthDenied(r, old, "csrf", "CSRF or Origin check failed")
		return nil, errCSRF
	}
	// Include requests that converged on this session during insertion too.
	n := old.authRequests.Add(1)
	defer old.authRequests.Add(-1)
	if n > maxSessionAuthWaiters+1 {
		return nil, qtsauth.ErrOverloaded
	}
	if err := s.authAdmission.lockSession(r.Context(), old); err != nil {
		return nil, err
	}
	now := s.now()
	s.mu.Lock()
	invalid := old.dead.Load() || !now.Before(old.expires)
	s.mu.Unlock()
	if s.pinned == nil && hasCred && qtsauth.CacheKey(cred) != old.binding {
		invalid = true
	}
	if !invalid && s.pinned == nil && (!safeMethod(r.Method) || !old.unavailableSince.IsZero() || now.Sub(old.checked) >= 60*time.Second) {
		if s.verifier == nil {
			invalid = true
		} else {
			if err := s.authAdmission.enter(r.Context(), true); err != nil {
				old.mu.Unlock()
				return nil, err
			}
			defer s.authAdmission.leave(true)
			if !safeMethod(r.Method) || !old.unavailableSince.IsZero() {
				s.verifier.Invalidate(old.cred)
			}
			verified, err := s.verifyCredential(r, old.cred, true)
			if ctxErr := r.Context().Err(); ctxErr != nil {
				err = ctxErr
			}
			if qtsUnavailable(err) {
				if old.unavailableSince.IsZero() {
					old.unavailableSince = now
				}
				expired := !s.now().Before(old.unavailableSince.Add(qtsUnavailableGrace))
				if expired {
					s.destroy(old.id)
					s.cookie(w, r, "", -1)
				}
				old.mu.Unlock()
				// Keep the credential during the bounded outage grace, but never
				// authorize operations using a failed validation.
				return nil, err
			}
			if errors.Is(err, errAuthRateLimited) || errors.Is(err, qtsauth.ErrOverloaded) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				old.mu.Unlock()
				return nil, err
			}
			if err != nil || verified.User != old.who.User {
				invalid = true
			} else {
				ident, err := s.ids.Resolve(r.Context(), verified.User)
				if ctxErr := r.Context().Err(); ctxErr != nil {
					old.mu.Unlock()
					return nil, ctxErr
				}
				if err != nil {
					invalid = true
				} else {
					old.who = principal(ident)
					old.admin, old.note = idmap.DecideAdmin(verified.IsAdmin(), ident, s.ids, s.cfg.Auth.AdminRequiresBoth)
					old.who.Root = old.admin
					old.partial = ident.Partial
					old.checked = verified.ValidatedAt
					old.unavailableSince = time.Time{}
				}
			}
		}
	}
	s.mu.Lock()
	if !invalid && !old.dead.Load() {
		old.expires = now.Add(sessionTTL)
		s.mu.Unlock()
		// Return an immutable request snapshot, not shared mutable session fields.
		cp := snapshot(old)
		old.mu.Unlock()
		s.cookie(w, r, old.id, int(sessionTTL.Seconds()))
		return cp, nil
	}
	s.mu.Unlock()
	old.mu.Unlock()
	s.destroy(old.id)
	s.cookie(w, r, "", -1)
	return nil, errSession
}

func snapshot(s *session) *session {
	return &session{id: s.id, csrf: s.csrf, who: s.who, admin: s.admin, kind: s.kind, partial: s.partial, note: s.note}
}

func principal(id idmap.Ident) backend.Principal {
	return backend.Principal{User: id.Name, UID: id.UID, GID: id.GID, Groups: append([]int{}, id.Groups...), Root: false}
}

func (s *Server) sessionInfo(w http.ResponseWriter, r *http.Request, sess *session) {
	readOnly := s.readOnly()
	v := map[string]any{"authenticated": sess != nil, "user": "", "admin": false, "rootMode": false, "uid": -1, "gid": -1, "groups": []int{}, "readOnly": readOnly, "canWrite": false, "version": s.version, "isQTS": s.isQTS(), "family": s.platform.Family, "csrf": "", "viaQTS": false}
	if sess != nil {
		v["rootMode"] = sess.who.Root
		// The UI enables mutating controls on canWrite alone: a live session and
		// read-only mode off.
		v["canWrite"] = !readOnly
	}
	if sess != nil {
		v["user"], v["admin"], v["uid"], v["gid"], v["groups"], v["csrf"], v["viaQTS"] = sess.who.User, sess.admin, sess.who.UID, sess.who.GID, sess.who.Groups, sess.csrf, sess.kind != ""
		v["groupsIncomplete"] = sess.partial
	}
	writeJSON(w, v)
}
