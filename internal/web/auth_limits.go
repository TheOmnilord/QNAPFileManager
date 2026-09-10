package web

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"qnapfilemanager/internal/qtsauth"
)

const (
	defaultAuthTimeout           = 10 * time.Second
	authFailureBurst             = 20
	unattributedFailureBurst     = 200
	authRecoveryInterval         = time.Second
	unattributedRecoveryInterval = time.Second / 5
	reservedAuthClassSlots       = 2
	authFailureWindow            = time.Minute
	maxFailureClients            = 4096
	maxSessionAuthWaiters        = 8
)

var errAuthRateLimited = errors.New("authentication failure rate exceeded")
var errAuthRetry = errors.New("authentication leader interrupted; retry")

type failureBucket struct {
	credentials map[string]time.Time
	next        time.Time
}

type failureLimiter struct {
	mu           sync.Mutex
	clients      map[string]*failureBucket
	unattributed failureBucket
	overflowNext time.Time
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

// VERIFY ON NAS: QTS must append/replace X-Forwarded-For with the actual peer.
// Without usable proxy attribution, use a validated username and a coarse
// budget so rotating usernames cannot drive QTS at full rate.
func authFailureClient(r *http.Request, cred qtsauth.Cred) string {
	if ip := forwardedClientIP(r); ip != "" {
		return "ip:" + ip
	}
	user := ""
	if qtsauth.ValidUserName(cred.User) {
		user = strings.ToLower(cred.User)
	}
	return "user:" + user
}

func (b *failureBucket) failed(key string, now time.Time, limit int, recovery time.Duration) {
	b.prune(now)
	if b.credentials == nil {
		b.credentials = make(map[string]time.Time)
	}
	if _, exists := b.credentials[key]; exists || len(b.credentials) >= limit {
		return
	}
	b.credentials[key] = now.Add(authFailureWindow)
	if len(b.credentials) == limit {
		b.next = now.Add(recovery)
	}
}

func (l *failureLimiter) pruneClients(now time.Time) {
	for key, b := range l.clients {
		b.prune(now)
		if len(b.credentials) == 0 && !now.Before(b.next) {
			delete(l.clients, key)
		}
	}
}

// Account only verified failures. Established sessions never use this budget.
func (l *failureLimiter) failed(ip, key string, now time.Time) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if strings.HasPrefix(ip, "user:") {
		l.unattributed.failed(key, now, unattributedFailureBurst, unattributedRecoveryInterval)
	}
	if l.clients == nil {
		l.clients = make(map[string]*failureBucket)
	}
	b := l.clients[ip]
	if b == nil && len(l.clients) >= maxFailureClients {
		l.pruneClients(now)
		if len(l.clients) >= maxFailureClients {
			return errAuthRateLimited
		}
	}
	if b == nil {
		b = &failureBucket{credentials: make(map[string]time.Time)}
		l.clients[ip] = b
	}
	b.failed(key, now, authFailureBurst, authRecoveryInterval)
	return nil
}

func (s *Server) verifyCredential(r *http.Request, cred qtsauth.Cred, revalidation bool) (qtsauth.Session, error) {
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
	client := authFailureClient(r, cred)
	if !revalidation {
		ctx = context.WithValue(ctx, authBudgetKey{}, &authBudget{s: s, ip: client, cancel: cancel})
	}
	verified, err := s.verifier.Verify(ctx, cred)
	if qtsUnavailable(err) {
		// Infrastructure failures are not credential failures. Do not retain
		// the verifier's negative cache or charge the bad-credential budget.
		s.verifier.Invalidate(cred)
		return qtsauth.Session{}, err
	}
	if ctxErr := r.Context().Err(); ctxErr != nil {
		return qtsauth.Session{}, ctxErr
	}
	if errors.Is(context.Cause(ctx), errAuthRateLimited) {
		return qtsauth.Session{}, errAuthRateLimited
	}
	if !revalidation && err != nil && !errors.Is(err, qtsauth.ErrOverloaded) && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		// Already-running calls can finish after another failure fills the
		// budget. Preserve their actual failure so sessions are revoked.
		_ = s.authFailures.failed(client, qtsauth.CacheKey(cred), s.now())
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
	var recovery *time.Time
	if b := l.clients[ip]; b != nil {
		b.prune(now)
		if len(b.credentials) >= authFailureBurst {
			recovery = &b.next
		}
	} else if len(l.clients) >= maxFailureClients {
		l.pruneClients(now)
		if len(l.clients) >= maxFailureClients {
			recovery = &l.overflowNext
		}
	}
	coarse := false
	if strings.HasPrefix(ip, "user:") {
		l.unattributed.prune(now)
		coarse = len(l.unattributed.credentials) >= unattributedFailureBurst
	}
	// Check both gates before consuming either recovery allowance.
	if (recovery != nil && now.Before(*recovery)) || (coarse && now.Before(l.unattributed.next)) {
		return errAuthRateLimited
	}
	if recovery != nil {
		*recovery = now.Add(authRecoveryInterval)
	}
	if coarse {
		l.unattributed.next = now.Add(unattributedRecoveryInterval)
	}
	return nil
}

// Shared by credential validation and identity resolution. Session followers
// and credential followers share the waiting bound but never occupy execution slots.
type authAdmission struct {
	once          sync.Once
	slots         chan struct{}
	logins        chan struct{}
	revalidations chan struct{}
	mu            sync.Mutex
	flights       map[string]*credentialFlight
	waiters       chan struct{}
}

func (a *authAdmission) init() {
	a.once.Do(func() {
		a.slots = make(chan struct{}, qtsauth.DefaultMaxConcurrentValidations)
		a.logins = make(chan struct{}, qtsauth.DefaultMaxConcurrentValidations-reservedAuthClassSlots)
		a.revalidations = make(chan struct{}, qtsauth.DefaultMaxConcurrentValidations-reservedAuthClassSlots)
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

func (a *authAdmission) enter(ctx context.Context, revalidation bool) error {
	a.init()
	waiting := false
	defer func() {
		if waiting {
			<-a.waiters
		}
	}()
	acquire := func(ch chan struct{}) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		select {
		case ch <- struct{}{}:
			return nil
		default:
		}
		if !waiting {
			if err := a.wait(); err != nil {
				return err
			}
			waiting = true
		}
		select {
		case ch <- struct{}{}:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	class := a.logins
	if revalidation {
		class = a.revalidations
	}
	// Acquire the class limit first so queued work cannot consume the other
	// class's reserved execution capacity.
	if err := acquire(class); err != nil {
		return err
	}
	if err := acquire(a.slots); err != nil {
		<-class
		return err
	}
	return nil
}

func (a *authAdmission) leave(revalidation bool) {
	<-a.slots
	if revalidation {
		<-a.revalidations
	} else {
		<-a.logins
	}
}

type credentialFlight struct {
	done chan struct{}
	sess *session
	err  error
}

// Include identity resolution and session insertion in the flight. Followers
// never duplicate either work or execution admission, even after a cache hit.
func (a *authAdmission) credential(ctx context.Context, key string, create func() (*session, error)) (*session, error) {
	a.mu.Lock()
	if f := a.flights[key]; f != nil {
		if err := a.wait(); err != nil {
			a.mu.Unlock()
			return nil, err
		}
		a.mu.Unlock()
		defer func() { <-a.waiters }()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-f.done:
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if errors.Is(f.err, context.Canceled) || errors.Is(f.err, context.DeadlineExceeded) {
				return nil, errAuthRetry
			}
			return f.sess, f.err
		}
	}
	if a.flights == nil {
		a.flights = make(map[string]*credentialFlight)
	}
	f := &credentialFlight{done: make(chan struct{})}
	a.flights[key] = f
	a.mu.Unlock()
	f.sess, f.err = create()
	a.mu.Lock()
	delete(a.flights, key)
	close(f.done)
	a.mu.Unlock()
	return f.sess, f.err
}

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
