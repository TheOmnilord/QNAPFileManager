package web

import (
	"crypto/rand"
	"errors"
	"net/http"
	"sync"
	"time"

	"qnapfilemanager/internal/backend"
	"qnapfilemanager/internal/idmap"
	"qnapfilemanager/internal/qtsauth"
)

const sessionTTL = 12 * time.Hour

var errSession = errors.New("invalid session")

type session struct {
	mu                      sync.Mutex
	id, csrf, binding, kind string
	who                     backend.Principal
	admin, partial, dead    bool
	note                    string
	cred                    qtsauth.Cred
	checked, expires        time.Time
}

func (s *Server) cookie(w http.ResponseWriter, r *http.Request, value string, age int) {
	p := s.cfg.Web.ProxyPrefix + "/"
	http.SetCookie(w, &http.Cookie{Name: "qfm_sid", Value: value, Path: p, MaxAge: age, HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"})
}

func (s *Server) destroy(id string) {
	s.mu.Lock()
	old := s.sessions[id]
	delete(s.sessions, id)
	s.mu.Unlock()
	if old != nil {
		old.mu.Lock()
		old.dead = true
		old.mu.Unlock()
	}
}

func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) (*session, error) {
	now := time.Now()
	var old *session
	s.mu.Lock()
	if c, err := r.Cookie("qfm_sid"); err == nil {
		old = s.sessions[c.Value]
	}
	sessions := make(map[string]*session, len(s.sessions))
	for id, sess := range s.sessions {
		sessions[id] = sess
	}
	s.mu.Unlock()
	// Reclaim idle expired sessions. A busy session may be verifying with QTS
	// or NSS; neither the map lock nor another request should wait for it.
	for id, sess := range sessions {
		if !sess.mu.TryLock() {
			continue
		}
		if !now.Before(sess.expires) {
			sess.dead = true
			s.mu.Lock()
			if s.sessions[id] == sess {
				delete(s.sessions, id)
			}
			s.mu.Unlock()
		}
		sess.mu.Unlock()
	}
	cred, hasCred := qtsauth.FromRequest(r)
	if old != nil {
		old.mu.Lock()
		invalid := old.dead || !time.Now().Before(old.expires)
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
		if !invalid {
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
		sess.binding, sess.kind, sess.cred, sess.checked = qtsauth.CacheKey(cred), cred.Kind, cred, verified.ValidatedAt
		if sess.note != "" {
			s.logger.Printf("admin disagreement user=%q ip=%q: %s", ident.Name, ClientIP(r), sess.note)
		}
	}
	s.mu.Lock()
	s.sessions[sess.id] = sess
	s.mu.Unlock()
	s.cookie(w, r, sess.id, int(sessionTTL.Seconds()))
	return snapshot(sess), nil
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
