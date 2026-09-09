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

// Account only verified failures. Cache hits do not consume network capacity.
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
	// The verifier exposes no cache-only lookup. Gate its transport so cached
	// answers (including positives from other IPs) bypass the failure budget.
	s.authTransportOnce.Do(func() {
		if c := s.verifier.Client; c != nil {
			client := c.HTTP
			if client == nil {
				client = qtsauth.NewHTTPClient(c.BaseURL, qtsauth.DefaultTimeout)
			}
			cp := *client
			next := cp.Transport
			if next == nil {
				next = http.DefaultTransport
			}
			cp.Transport = authBudgetTransport{next: next}
			c.HTTP = &cp
		}
	})
	ctx, cancel := context.WithCancelCause(r.Context())
	defer cancel(nil)
	ctx = context.WithValue(ctx, authBudgetKey{}, &authBudget{s: s, ip: ClientIP(r), cancel: cancel})
	verified, err := s.verifier.Verify(ctx, cred)
	if ctxErr := r.Context().Err(); ctxErr != nil {
		return qtsauth.Session{}, ctxErr
	}
	if errors.Is(context.Cause(ctx), errAuthRateLimited) {
		return qtsauth.Session{}, errAuthRateLimited
	}
	if err != nil && !errors.Is(err, qtsauth.ErrOverloaded) && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		// Already-running calls can finish after another failure fills the
		// budget. Preserve their actual failure so sessions are revoked.
		_ = s.authFailures.failed(ClientIP(r), qtsauth.CacheKey(cred), s.now())
	}
	return verified, err
}

type authBudgetKey struct{}

type authBudget struct {
	s      *Server
	ip     string
	cancel context.CancelCauseFunc
}

type authBudgetTransport struct{ next http.RoundTripper }

func (t authBudgetTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if b, ok := r.Context().Value(authBudgetKey{}).(*authBudget); ok {
		if err := b.s.authFailures.allow(b.ip, b.s.now()); err != nil {
			// Admission pressure says nothing about credential validity. Cancel
			// this verification so the verifier cannot negative-cache the refusal.
			b.cancel(err)
			return nil, err
		}
	}
	return t.next.RoundTrip(r)
}

func (l *failureLimiter) allow(ip string, now time.Time) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if b := l.clients[ip]; b != nil {
		b.prune(now)
		if len(b.credentials) >= authFailureBurst {
			return errAuthRateLimited
		}
		return nil
	}
	if len(l.clients) >= maxFailureClients {
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
	return nil
}

// Shared by credential validation and identity resolution. Session followers
// share the waiting bound but never occupy execution slots.
type authAdmission struct {
	once    sync.Once
	slots   chan struct{}
	waiters chan struct{}
}

func (a *authAdmission) init() {
	a.once.Do(func() {
		a.slots = make(chan struct{}, qtsauth.DefaultMaxConcurrentValidations)
		a.waiters = make(chan struct{}, qtsauth.DefaultMaxValidationWaiters)
	})
}

func (a *authAdmission) wait() error {
	a.init()
	select {
	case a.waiters <- struct{}{}:
		return nil
	default:
		return qtsauth.ErrOverloaded
	}
}

func (a *authAdmission) enter(ctx context.Context) error {
	a.init()
	select {
	case a.slots <- struct{}{}:
		return nil
	default:
	}
	if err := a.wait(); err != nil {
		return err
	}
	defer func() { <-a.waiters }()
	select {
	case a.slots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (a *authAdmission) leave() { <-a.slots }

// A session's validation lock must not hold its followers beyond their deadline.
func (a *authAdmission) lockSession(ctx context.Context, sess *session) error {
	if sess.mu.TryLock() {
		if err := ctx.Err(); err != nil {
			sess.mu.Unlock()
			return err
		}
		return nil
	}
	if err := a.wait(); err != nil {
		return err
	}
	defer func() { <-a.waiters }()
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
