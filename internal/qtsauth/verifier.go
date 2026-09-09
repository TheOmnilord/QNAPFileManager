package qtsauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Cache lifetimes. PLAN.md decision 3: "60 s cache with single-flight;
// unconditional revalidation before any write".
const (
	DefaultPositiveTTL = 60 * time.Second
	DefaultNegativeTTL = 10 * time.Second
)

// Session is the outcome of a successful verification. It carries only what
// QTS told us; mapping User to a uid/gid is internal/idmap's job and is glued
// in by the web layer.
type Session struct {
	// User is the authoritative user name. For KindSID it always comes from the
	// response body, never from the cookie.
	User string
	// Admin is QTS's isAdmin answer, nil when the response did not carry one.
	// nil must be treated as "not an administrator" for authorisation, but is
	// kept distinct so the UI can offer the password re-entry path instead of
	// claiming the account is not an administrator.
	Admin *bool
	// ValidatedAt is when the endpoint was actually called (not when a cached
	// answer was served).
	ValidatedAt time.Time
	// Kind is the credential kind that produced this session.
	Kind string
}

// IsAdmin reports whether QTS positively said "administrator".
func (s Session) IsAdmin() bool { return s.Admin != nil && *s.Admin }

// Verifier wraps a Client with a short cache and single-flight, so that a burst
// of API calls from one page load produces exactly one authLogin.cgi request.
// The endpoint is a fork-per-request CGI and may write a QuLog event per call
// (VERIFY ON NAS, identity-and-hero-plan.md §5.4 item 13), so this is a
// correctness requirement, not just an optimisation.
//
// The zero value is not usable; use NewVerifier.
type Verifier struct {
	// Client is the endpoint client. Required.
	Client *Client

	// AllowSIDWithoutUsername lets a NAS_SID session take its identity from the
	// NAS_USER cookie when the response carries no username.
	//
	// DEFAULT false, AND IT SHOULD STAY FALSE. With it set, any authenticated
	// non-admin can set NAS_USER=admin in their own browser and be handed an
	// administrator session, because the sid call validates only the token.
	// identity-and-hero-plan.md §1.3 requires this to fail closed and calls for
	// a hard-coded default rather than a config option; the field exists only
	// so a NAS-side experiment can be run deliberately.
	AllowSIDWithoutUsername bool

	// RequireAdminSignal rejects a response that carries no isAdmin element.
	// Default false: the plan's chosen degradation is to issue a normal-user
	// session and have administrators re-enter their password once.
	RequireAdminSignal bool

	// PositiveTTL / NegativeTTL default to DefaultPositiveTTL and
	// DefaultNegativeTTL when zero.
	PositiveTTL time.Duration
	NegativeTTL time.Duration

	// Now is the clock, for tests. nil means time.Now.
	Now func() time.Time

	mu       sync.Mutex
	cache    map[string]cacheEntry
	inflight map[string]*flight
}

type cacheEntry struct {
	sess    Session
	err     error
	expires time.Time
}

type flight struct {
	done chan struct{}
	sess Session
	err  error
}

// NewVerifier returns a Verifier over c with the plan's defaults: fail closed on
// an unbound sid, no admin-signal requirement, 60 s positive and 10 s negative
// caching.
func NewVerifier(c *Client) *Verifier {
	return &Verifier{
		Client:      c,
		PositiveTTL: DefaultPositiveTTL,
		NegativeTTL: DefaultNegativeTTL,
	}
}

func (v *Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

func (v *Verifier) positiveTTL() time.Duration {
	if v.PositiveTTL > 0 {
		return v.PositiveTTL
	}
	return DefaultPositiveTTL
}

func (v *Verifier) negativeTTL() time.Duration {
	if v.NegativeTTL > 0 {
		return v.NegativeTTL
	}
	return DefaultNegativeTTL
}

// CacheKey is the cache and single-flight key for a credential. The token is
// hashed so it never sits in a map key that might be dumped in a diagnostic.
func CacheKey(c Cred) string {
	sum := sha256.Sum256([]byte(c.Kind + "|" + c.User + "|" + c.Token))
	return hex.EncodeToString(sum[:])
}

// Verify validates a credential, serving a cached answer when one is fresh and
// collapsing concurrent verifications of the same credential into one call.
//
// Callers that are about to perform a write must call Invalidate first: PLAN.md
// decision 3 requires unconditional revalidation before any mutation, so that a
// QTS sign-out takes effect immediately.
func (v *Verifier) Verify(ctx context.Context, cred Cred) (Session, error) {
	key := CacheKey(cred)

	v.mu.Lock()
	if v.cache == nil {
		v.cache = map[string]cacheEntry{}
	}
	if v.inflight == nil {
		v.inflight = map[string]*flight{}
	}
	if e, ok := v.cache[key]; ok && v.now().Before(e.expires) {
		v.mu.Unlock()
		return e.sess, e.err
	}
	if f, ok := v.inflight[key]; ok {
		v.mu.Unlock()
		select {
		case <-f.done:
			return f.sess, f.err
		case <-ctx.Done():
			return Session{}, fmt.Errorf("qtsauth: verify cancelled: %w", ctx.Err())
		}
	}
	f := &flight{done: make(chan struct{})}
	v.inflight[key] = f
	v.mu.Unlock()

	sess, err := v.validate(ctx, cred)

	ttl := v.positiveTTL()
	if err != nil {
		ttl = v.negativeTTL()
	}
	v.mu.Lock()
	v.cache[key] = cacheEntry{sess: sess, err: err, expires: v.now().Add(ttl)}
	delete(v.inflight, key)
	v.mu.Unlock()

	f.sess, f.err = sess, err
	close(f.done)
	return sess, err
}

// Invalidate drops any cached answer for a credential. Call it on QTS sign-out
// and before any write.
func (v *Verifier) Invalidate(cred Cred) {
	key := CacheKey(cred)
	v.mu.Lock()
	delete(v.cache, key)
	v.mu.Unlock()
}

// InvalidateAll drops the whole cache, e.g. when configuration changes.
func (v *Verifier) InvalidateAll() {
	v.mu.Lock()
	v.cache = map[string]cacheEntry{}
	v.mu.Unlock()
}

func (v *Verifier) validate(ctx context.Context, cred Cred) (Session, error) {
	if v.Client == nil {
		return Session{}, fmt.Errorf("qtsauth: no client configured: %w", ErrUnreachable)
	}
	if !validToken(cred.Token) {
		return Session{}, fmt.Errorf("qtsauth: malformed token: %w", ErrNotAuthenticated)
	}
	if cred.User != "" && !ValidUserName(cred.User) {
		return Session{}, fmt.Errorf("qtsauth: malformed user name: %w", ErrNotAuthenticated)
	}

	var (
		res Result
		err error
	)
	switch cred.Kind {
	case KindQToken:
		if cred.User == "" {
			return Session{}, fmt.Errorf("qtsauth: qtoken without user: %w", ErrNotAuthenticated)
		}
		res, err = v.Client.ValidateQToken(ctx, cred.User, cred.Token)
	case KindSID:
		res, err = v.Client.ValidateSID(ctx, cred.Token)
	default:
		return Session{}, fmt.Errorf("qtsauth: unknown credential kind %q: %w", cred.Kind, ErrNotAuthenticated)
	}
	if err != nil {
		return Session{}, err
	}
	if !res.AuthPassed {
		return Session{}, fmt.Errorf("qtsauth: authPassed=%q errorValue=%d: %w",
			res.Raw["authpassed"], res.ErrorValue, ErrNotAuthenticated)
	}
	if v.RequireAdminSignal && res.IsAdmin == nil {
		return Session{}, fmt.Errorf("qtsauth: response carries no isAdmin element: %w", ErrBadResponse)
	}

	user, err := bindUser(cred, res, v.AllowSIDWithoutUsername)
	if err != nil {
		return Session{}, err
	}
	return Session{
		User:        user,
		Admin:       res.IsAdmin,
		ValidatedAt: v.now(),
		Kind:        cred.Kind,
	}, nil
}

// bindUser decides which user name a validated response actually authorises.
//
// qtoken: the pair was validated together, so the cookie name is safe; if the
// response also names a user it must agree.
//
// sid: only the token was validated. The name MUST come from the response, or
// the session is refused (ErrSIDUnbound). See identity-and-hero-plan.md §1.3.
func bindUser(cred Cred, res Result, allowSIDWithoutUsername bool) (string, error) {
	respUser := strings.TrimSpace(res.Username)
	if respUser != "" && !ValidUserName(respUser) {
		return "", fmt.Errorf("qtsauth: response username %q is not a valid user name: %w", respUser, ErrBadResponse)
	}
	if respUser != "" && cred.User != "" && !strings.EqualFold(respUser, cred.User) {
		return "", fmt.Errorf("qtsauth: response says %q, client claimed %q: %w", respUser, cred.User, ErrUserMismatch)
	}
	if cred.Kind == KindQToken {
		if respUser != "" {
			return respUser, nil
		}
		return cred.User, nil
	}
	// KindSID.
	if respUser != "" {
		return respUser, nil
	}
	if !allowSIDWithoutUsername {
		return "", ErrSIDUnbound
	}
	if cred.User == "" {
		return "", fmt.Errorf("qtsauth: no username in response and none presented: %w", ErrSIDUnbound)
	}
	return cred.User, nil
}
