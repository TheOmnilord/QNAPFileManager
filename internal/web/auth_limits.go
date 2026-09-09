package web

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"qnapfilemanager/internal/qtsauth"
)

const (
	defaultAuthTimeout    = 10 * time.Second
	authFailureBurst      = 20
	authFailureWindow     = time.Minute
	maxFailureClients     = 4096
	maxSessionAuthWaiters = 8
)

var errAuthRateLimited = errors.New("authentication failure rate exceeded")

type failureBucket struct {
	credentials map[string]time.Time
}

type failureLimiter struct {
	mu      sync.Mutex
	clients map[string]*failureBucket
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (b *failureBucket) prune(now time.Time) {
	for key, expires := range b.credentials {
		if !now.Before(expires) {
			delete(b.credentials, key)
		}
	}
}

// Account only verified failures: an IP budget must never reject a valid
// credential. QTS's negative cache throttles repeated work for the same key.
func (l *failureLimiter) failed(ip, key string, now time.Time) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.clients == nil {
		l.clients = make(map[string]*failureBucket)
	}
	b := l.clients[ip]
	if b == nil && len(l.clients) >= maxFailureClients {
		for key, b := range l.clients {
			b.prune(now)
			if len(b.credentials) == 0 {
				delete(l.clients, key)
			}
		}
		if len(l.clients) >= maxFailureClients {
			return errAuthRateLimited
		}
	}
	if b == nil {
		b = &failureBucket{credentials: make(map[string]time.Time)}
		l.clients[ip] = b
	}
	b.prune(now)
	if _, exists := b.credentials[key]; exists {
		return nil // Repeats neither consume capacity nor extend the window.
	}
	if len(b.credentials) >= authFailureBurst {
		return errAuthRateLimited
	}
	b.credentials[key] = now.Add(authFailureWindow)
	return nil
}

func (s *Server) verifyCredential(r *http.Request, cred qtsauth.Cred) (qtsauth.Session, error) {
	verified, err := s.verifier.Verify(r.Context(), cred)
	if ctxErr := r.Context().Err(); ctxErr != nil {
		return qtsauth.Session{}, ctxErr
	}
	if err != nil && !errors.Is(err, qtsauth.ErrOverloaded) && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		if limitErr := s.authFailures.failed(ClientIP(r), qtsauth.CacheKey(cred), s.now()); limitErr != nil {
			return qtsauth.Session{}, limitErr
		}
	}
	return verified, err
}

// Shared by new credentials and existing sessions, including lock and identity
// resolution waits. The verifier independently bounds actual CGI work.
type authAdmission struct {
	once    sync.Once
	slots   chan struct{}
	waiters chan struct{}
}

func (a *authAdmission) enter(ctx context.Context) error {
	a.once.Do(func() {
		a.slots = make(chan struct{}, qtsauth.DefaultMaxConcurrentValidations)
		a.waiters = make(chan struct{}, qtsauth.DefaultMaxValidationWaiters)
	})
	select {
	case a.slots <- struct{}{}:
		return nil
	default:
	}
	select {
	case a.waiters <- struct{}{}:
		defer func() { <-a.waiters }()
	default:
		return qtsauth.ErrOverloaded
	}
	select {
	case a.slots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (a *authAdmission) leave() { <-a.slots }

// A session's validation lock must not hold its followers beyond their deadline.
func lockSession(ctx context.Context, sess *session) error {
	for !sess.mu.TryLock() {
		timer := time.NewTimer(5 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	if err := ctx.Err(); err != nil {
		sess.mu.Unlock()
		return err
	}
	return nil
}
