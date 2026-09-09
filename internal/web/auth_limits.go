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
	defaultAuthTimeout = 10 * time.Second
	authFailureBurst   = 20
	authFailureWindow  = time.Minute
	maxFailureClients  = 4096
)

var errAuthRateLimited = errors.New("authentication failure rate exceeded")

type failureBucket struct {
	tokens                float64
	updated, blockedUntil time.Time
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

func (b *failureBucket) refill(now time.Time) {
	if now.After(b.updated) {
		b.tokens = min(authFailureBurst, b.tokens+now.Sub(b.updated).Seconds()*authFailureBurst/authFailureWindow.Seconds())
		b.updated = now
	}
}

func (l *failureLimiter) allow(ip string, now time.Time) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if b := l.clients[ip]; b != nil {
		if now.Before(b.blockedUntil) {
			return errAuthRateLimited
		}
		return nil
	}
	// Keep the limiter itself bounded without evicting a live client's ban.
	if len(l.clients) >= maxFailureClients {
		for key, b := range l.clients {
			b.refill(now)
			if !now.Before(b.blockedUntil) && b.tokens >= authFailureBurst {
				delete(l.clients, key)
			}
		}
		if len(l.clients) >= maxFailureClients {
			return qtsauth.ErrOverloaded
		}
	}
	return nil
}

func (l *failureLimiter) failed(ip string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.clients == nil {
		l.clients = make(map[string]*failureBucket)
	}
	b := l.clients[ip]
	if b == nil {
		if len(l.clients) >= maxFailureClients {
			return
		}
		b = &failureBucket{tokens: authFailureBurst, updated: now}
		l.clients[ip] = b
	}
	if now.Before(b.blockedUntil) {
		return // Completions already in flight must not extend the ban.
	}
	b.refill(now)
	b.tokens--
	if b.tokens < 1 {
		b.blockedUntil = now.Add(authFailureWindow)
	}
}

func (s *Server) verifyCredential(r *http.Request, cred qtsauth.Cred) (qtsauth.Session, error) {
	verified, err := s.verifier.Verify(r.Context(), cred)
	if ctxErr := r.Context().Err(); ctxErr != nil {
		return qtsauth.Session{}, ctxErr
	}
	if err != nil && !errors.Is(err, qtsauth.ErrOverloaded) && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		s.authFailures.failed(ClientIP(r), s.now())
	}
	return verified, err
}

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
