package qtsauth

import "errors"

// Sentinel errors. Callers should use errors.Is; every error returned by this
// package wraps exactly one of these.
var (
	// ErrOverloaded means no validation waiter capacity remains; QTS was not called.
	ErrOverloaded = errors.New("qtsauth: validation overloaded")

	// ErrNotAuthenticated means QTS answered but rejected the credential
	// (authPassed was absent or zero).
	ErrNotAuthenticated = errors.New("qtsauth: not authenticated")

	// ErrSIDUnbound means a NAS_SID was validated but the response carried no
	// user name, so the session cannot be bound to an identity. Trusting the
	// NAS_USER cookie here would let any authenticated user claim any account,
	// so this fails closed. See identity-and-hero-plan.md §1.3.
	ErrSIDUnbound = errors.New("qtsauth: sid validated but response carries no username")

	// ErrUserMismatch means the user name in the response differs from the one
	// presented by the client.
	ErrUserMismatch = errors.New("qtsauth: username mismatch")

	// ErrUnreachable means the QTS endpoint could not be reached: connection
	// refused, timeout, DNS, or a body that could not be read.
	ErrUnreachable = errors.New("qtsauth: endpoint unreachable")

	// ErrBadResponse means the endpoint answered with something we cannot use:
	// a non-2xx status (including an unfollowed redirect), or a body that is
	// not XML carrying any recognised element.
	ErrBadResponse = errors.New("qtsauth: unusable response")
)
