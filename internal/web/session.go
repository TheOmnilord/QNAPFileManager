package web

import (
	"container/list"
	"crypto/rand"
	"errors"
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
	DefaultMaxSessions        = 10000
	DefaultMaxSessionsPerUser = 16
)

var errSession = errors.New("invalid session")

type session struct {
	mu                      sync.Mutex
	id, csrf, binding, kind string
	who                     backend.Principal
	admin, partial          bool
	dead                    atomic.Bool
	// Index metadata is immutable after insertion; list links require Server.mu.
	user             string
	order, userOrder *list.Element
	note             string
	cred             qtsauth.Cred
	checked, expires time.Time
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
			return old
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
	if users := s.byUser[sess.user]; users != nil && users.Len() >= maxUser {
		s.removeSessionLocked(users.Front().Value.(*session))
	}
	for len(s.sessions) >= maxTotal {
		s.removeSessionLocked(s.sessionOrder.Front().Value.(*session))
	}
	users := s.byUser[sess.user]
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

func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) (*session, error) {
	now := time.Now()
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
	if old != nil {
		return s.authenticateSession(w, r, old, cred, hasCred)
	}
	if s.pinned == nil && !hasCred {
		return nil, nil
	}
	sess := &session{id: rand.Text(), csrf: rand.Text(), expires: now.Add(sessionTTL), checked: now}
	if s.pinned != nil {
		sess.who = *s.pinned
		sess.admin = idmap.IsLocalAdmin(idmap.Ident{Name: s.pinned.User, UID: s.pinned.UID, GID: s.pinned.GID, Groups: s.pinned.Groups}, s.ids)
	} else {
		if s.verifier == nil {
			return nil, errSession
		}
		verified, err := s.verifier.Verify(r.Context(), cred)
		if err != nil {
			return nil, errSession
		}
		ident, err := s.ids.Resolve(r.Context(), verified.User)
		if err != nil {
			return nil, errSession
		}
		sess.who = principal(ident)
		sess.admin, sess.note = idmap.DecideAdmin(verified.IsAdmin(), ident, s.ids, s.cfg.Auth.AdminRequiresBoth)
		sess.partial = ident.Partial
		sess.binding, sess.kind, sess.cred, sess.checked = binding, cred.Kind, cred, verified.ValidatedAt
		if sess.note != "" {
			s.logger.Printf("admin disagreement user=%q ip=%q: %s", ident.Name, ClientIP(r), sess.note)
		}
	}
	return s.authenticateSession(w, r, s.insertSession(sess), cred, hasCred)
}

func (s *Server) authenticateSession(w http.ResponseWriter, r *http.Request, old *session, cred qtsauth.Cred, hasCred bool) (*session, error) {
	now := time.Now()
	old.mu.Lock()
	invalid := old.dead.Load() || !now.Before(old.expires)
	if s.pinned == nil && hasCred && qtsauth.CacheKey(cred) != old.binding {
		invalid = true
	}
	if !invalid && s.pinned == nil && (!safeMethod(r.Method) || now.Sub(old.checked) >= 60*time.Second) {
		if s.verifier == nil {
			invalid = true
		} else {
			if !safeMethod(r.Method) {
				s.verifier.Invalidate(old.cred)
			}
			verified, err := s.verifier.Verify(r.Context(), old.cred)
			if err != nil || verified.User != old.who.User {
				invalid = true
			} else {
				ident, err := s.ids.Resolve(r.Context(), verified.User)
				if err != nil {
					invalid = true
				} else {
					old.who = principal(ident)
					old.admin, old.note = idmap.DecideAdmin(verified.IsAdmin(), ident, s.ids, s.cfg.Auth.AdminRequiresBoth)
					old.partial = ident.Partial
					old.checked = verified.ValidatedAt
				}
			}
		}
	}
	if !invalid && !old.dead.Load() {
		old.expires = now.Add(sessionTTL)
		// Return an immutable request snapshot, not shared mutable session fields.
		cp := snapshot(old)
		old.mu.Unlock()
		s.cookie(w, r, old.id, int(sessionTTL.Seconds()))
		return cp, nil
	}
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
	v := map[string]any{"authenticated": sess != nil, "user": "", "admin": false, "rootMode": false, "uid": -1, "gid": -1, "groups": []int{}, "readOnly": s.cfg.ReadOnly, "version": s.version, "isQTS": s.isQTS(), "family": s.platform.Family, "csrf": "", "viaQTS": false}
	if sess != nil {
		v["user"], v["admin"], v["uid"], v["gid"], v["groups"], v["csrf"], v["viaQTS"] = sess.who.User, sess.admin, sess.who.UID, sess.who.GID, sess.who.Groups, sess.csrf, sess.kind != ""
		v["groupsIncomplete"] = sess.partial
	}
	writeJSON(w, v)
}
